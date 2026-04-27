using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Analysis;

public sealed class ScanPipeline(
    UnityPackageExtractor extractor,
    IEnumerable<IDetectionRule> rules,
    ILogger<ScanPipeline> logger)
{
    private readonly IReadOnlyList<IDetectionRule> _rules = rules.ToList();

    public async Task<ScanResult> ScanAsync(string path, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var info = new FileInfo(path);

        logger.LogInformation("Scan started: {Path}", path);

        var (entries, sha256) = await extractor.ExtractAsync(path, ct);

        logger.LogInformation("Extraction complete: {Count} entries in {ElapsedMs}ms",
            entries.Count, sw.ElapsedMilliseconds);

        var allFindings = new List<Finding>();

        foreach (var rule in _rules.Where(r => r.IsEnabled))
        {
            ct.ThrowIfCancellationRequested();
            var ruleStart = sw.ElapsedMilliseconds;
            logger.LogDebug("Running rule {RuleId}", rule.RuleId);

            await foreach (var finding in rule.AnalyzeAsync(entries, ct))
            {
                allFindings.Add(finding);
                logger.LogInformation("Finding: [{Severity}] {RuleId} — {Title} ({Path})",
                    finding.Severity, finding.RuleId, finding.Title, finding.Entry?.Pathname ?? "(package)");
            }

            logger.LogDebug("Rule {RuleId} finished in {ElapsedMs}ms",
                rule.RuleId, sw.ElapsedMilliseconds - ruleStart);
        }

        var withAdvisory = VerdictAggregator.ApplyAdvisoryFlags(allFindings);
        var verdict = VerdictAggregator.Aggregate(withAdvisory);

        sw.Stop();
        logger.LogInformation(
            "Scan complete: verdict={Verdict}, findings={Count}, duration={ElapsedMs}ms",
            verdict, withAdvisory.Count, sw.ElapsedMilliseconds);

        return new ScanResult
        {
            PackagePath = path,
            PackageSize = info.Length,
            PackageSha256 = sha256,
            EntryCount = entries.Count,
            Entries = entries,
            Findings = withAdvisory,
            Verdict = verdict,
            ScanDuration = sw.Elapsed,
        };
    }

    /// <summary>
    /// Scans and streams findings as they are produced so the UI can update incrementally.
    /// </summary>
    public async IAsyncEnumerable<Finding> ScanStreamingAsync(
        IReadOnlyList<PackageEntry> entries,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        foreach (var rule in _rules.Where(r => r.IsEnabled))
        {
            ct.ThrowIfCancellationRequested();
            await foreach (var finding in rule.AnalyzeAsync(entries, ct))
                yield return finding;
        }
    }
}
