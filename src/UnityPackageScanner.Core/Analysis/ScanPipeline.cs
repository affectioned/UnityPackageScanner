using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Analysis;

public sealed class ScanPipeline(
    UnityPackageExtractor extractor,
    IEnumerable<IDetectionRule> rules,
    ILogger<ScanPipeline> logger,
    SandboxedDllAnalyzer? dllAnalyzer = null)
{
    private readonly IReadOnlyList<IDetectionRule> _rules = rules.ToList();

    // Entry types whose binary content is parsed out-of-process by the sandbox.
    private static readonly HashSet<DetectedType> SandboxedTypes =
    [
        DetectedType.ManagedDll,
        DetectedType.NativePE,
        DetectedType.NativeElf,
        DetectedType.NativeMachO,
    ];

    // Rules that call AsmResolver must not receive DLL/native entries in-process when the
    // sandbox is active; those entries are analysed exclusively by SandboxedDllAnalyzer.
    private static readonly HashSet<string> AsmResolverRuleIds =
    [
        KnownRuleIds.ObfuscatedDll,
        KnownRuleIds.AutoExecuteEditor,
        KnownRuleIds.NativePlugin,
        KnownRuleIds.NetworkAccess,
        KnownRuleIds.ProcessSpawn,
        KnownRuleIds.ReflectionLoad,
        KnownRuleIds.SuspiciousPInvoke,
        KnownRuleIds.EmbeddedEncryptedResource,
    ];

    public async Task<ScanResult> ScanAsync(string path, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var info = new FileInfo(path);

        logger.LogInformation("Scan started: {Path}", path);

        var (entries, sha256) = await extractor.ExtractAsync(path, ct);

        logger.LogInformation("Extraction complete: {Count} entries in {ElapsedMs}ms",
            entries.Count, sw.ElapsedMilliseconds);

        var (inProcess, sandbox) = PartitionEntries(entries);
        var allFindings = new List<Finding>();

        foreach (var rule in _rules.Where(r => r.IsEnabled))
        {
            ct.ThrowIfCancellationRequested();
            var ruleStart = sw.ElapsedMilliseconds;
            logger.LogDebug("Running rule {RuleId}", rule.RuleId);

            // Rules that call AsmResolver receive only non-DLL entries in-process;
            // their DLL analysis runs in the sandbox below.
            var entriesToPass = (dllAnalyzer is not null && AsmResolverRuleIds.Contains(rule.RuleId)) ? inProcess : entries;

            await foreach (var finding in rule.AnalyzeAsync(entriesToPass, ct))
            {
                allFindings.Add(finding);
                logger.LogInformation("Finding: [{Severity}] {RuleId} — {Title} ({Path})",
                    finding.Severity, finding.RuleId, finding.Title, finding.Entry?.Pathname ?? "(package)");
            }

            logger.LogDebug("Rule {RuleId} finished in {ElapsedMs}ms",
                rule.RuleId, sw.ElapsedMilliseconds - ruleStart);
        }

        if (dllAnalyzer is not null && sandbox.Count > 0)
        {
            logger.LogDebug("DllWorker: analysing {Count} DLL/native entr(ies)", sandbox.Count);
            var sandboxStart = sw.ElapsedMilliseconds;

            await foreach (var finding in dllAnalyzer.AnalyzeAsync(sandbox, ct))
            {
                allFindings.Add(finding);
                logger.LogInformation("Finding: [{Severity}] {RuleId} — {Title} ({Path})",
                    finding.Severity, finding.RuleId, finding.Title, finding.Entry?.Pathname ?? "(package)");
            }

            logger.LogDebug("DllWorker finished in {ElapsedMs}ms", sw.ElapsedMilliseconds - sandboxStart);
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
        var (inProcess, sandbox) = PartitionEntries(entries);

        foreach (var rule in _rules.Where(r => r.IsEnabled))
        {
            ct.ThrowIfCancellationRequested();
            var entriesToPass = (dllAnalyzer is not null && AsmResolverRuleIds.Contains(rule.RuleId)) ? inProcess : entries;
            await foreach (var finding in rule.AnalyzeAsync(entriesToPass, ct))
                yield return finding;
        }

        if (dllAnalyzer is not null && sandbox.Count > 0)
        {
            await foreach (var finding in dllAnalyzer.AnalyzeAsync(sandbox, ct))
                yield return finding;
        }
    }

    private (IReadOnlyList<PackageEntry> inProcess, List<PackageEntry> sandbox) PartitionEntries(
        IReadOnlyList<PackageEntry> entries)
    {
        if (dllAnalyzer is null)
            return (entries, []);

        var sandbox = entries.Where(e => SandboxedTypes.Contains(e.DetectedType)).ToList();
        var inProcess = entries.Where(e => !SandboxedTypes.Contains(e.DetectedType)).ToList();
        return (inProcess, sandbox);
    }
}
