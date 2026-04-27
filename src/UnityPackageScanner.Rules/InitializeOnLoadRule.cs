using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects editor scripts that auto-execute on package import via Unity's InitializeOnLoad
/// mechanism, or through AssetPostprocessor / AssetModificationProcessor subclasses.
/// </summary>
public sealed partial class InitializeOnLoadRule(ILogger<InitializeOnLoadRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.AutoExecuteEditor;
    public string Title => "Auto-executing editor code";
    public Severity DefaultSeverity => Severity.Critical;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects C# source files and compiled assemblies that use Unity's " +
        "[InitializeOnLoad] or [InitializeOnLoadMethod] attributes, or that subclass " +
        "AssetPostprocessor or AssetModificationProcessor. Code marked with these " +
        "mechanisms runs automatically the moment a package is imported — before the " +
        "developer has had a chance to inspect it.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Legitimate editor tooling (e.g. asset store packages with setup wizards) commonly uses [InitializeOnLoad]. " +
        "Look at what the static constructor actually does before concluding it is malicious.",
        "Test-only packages that configure test runners on import.",
    ];

    // Matches [InitializeOnLoad] and [InitializeOnLoadMethod] with optional namespace prefix
    [GeneratedRegex(@"\[\s*(?:\w+\.)*InitializeOnLoad(Method)?\s*(?:\(.*?\))?\s*\]", RegexOptions.Compiled)]
    private static partial Regex InitAttrRegex();

    // Matches class declarations that extend AssetPostprocessor or AssetModificationProcessor
    [GeneratedRegex(@"\bclass\s+\w+\s*:\s*[\w.]*(?:AssetPostprocessor|AssetModificationProcessor)\b",
        RegexOptions.Compiled)]
    private static partial Regex ProcessorBaseRegex();

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (entry.DetectedType == DetectedType.CSharpSource)
            {
                await foreach (var f in AnalyzeCsSourceAsync(entry, ct))
                    yield return f;
            }
            else if (entry.DetectedType is DetectedType.ManagedDll or DetectedType.NativePE)
            {
                await foreach (var f in AnalyzeManagedDllAsync(entry, ct))
                    yield return f;
            }
        }
    }

    private async IAsyncEnumerable<Finding> AnalyzeCsSourceAsync(
        PackageEntry entry,
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (entry.AssetBytes is null) yield break;

        string source;
        try
        {
            source = Encoding.UTF8.GetString(entry.AssetBytes);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not decode {Path} as UTF-8", entry.Pathname);
            yield break;
        }

        var evidence = new List<string>();

        if (InitAttrRegex().IsMatch(source))
        {
            evidence.Add("[InitializeOnLoad] or [InitializeOnLoadMethod] attribute found");
            logger.LogDebug("{RuleId}: InitializeOnLoad attribute matched in {Path}", RuleId, entry.Pathname);
        }

        if (ProcessorBaseRegex().IsMatch(source))
        {
            evidence.Add("Subclass of AssetPostprocessor or AssetModificationProcessor found");
            logger.LogDebug("{RuleId}: Processor base class matched in {Path}", RuleId, entry.Pathname);
        }

        if (evidence.Count > 0)
        {
            yield return new Finding
            {
                RuleId = RuleId,
                Severity = DefaultSeverity,
                Title = Title,
                Description = "This script will execute automatically when the package is imported into a Unity project.",
                Entry = entry,
                Evidence = string.Join("; ", evidence),
            };
        }

        await Task.CompletedTask; // satisfy async enumerable requirement
    }

    private async IAsyncEnumerable<Finding> AnalyzeManagedDllAsync(
        PackageEntry entry,
        [EnumeratorCancellation] CancellationToken ct)
    {
        // DLL inspection via AsmResolver is implemented in later milestones.
        // For now, yield nothing — the rule is wired up and ready to be extended.
        await Task.CompletedTask;
        yield break;
    }
}
