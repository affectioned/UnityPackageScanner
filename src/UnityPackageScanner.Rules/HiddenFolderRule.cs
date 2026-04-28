using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects assets stored under dot-prefixed directories (e.g. .hidden/evil.dll).
/// This is unusual in Unity packages and may indicate an attempt to hide content
/// from casual inspection in a file manager.
/// </summary>
public sealed class HiddenFolderRule(ILogger<HiddenFolderRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.HiddenFolder;
    public string Title => "Asset stored in hidden directory";
    public Severity DefaultSeverity => Severity.Suspicious;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects package entries whose path contains a directory component that begins with a dot " +
        "(e.g. '.hidden/', '.cache/'). On macOS and Linux, dot-prefixed names are hidden from " +
        "directory listings by default. Unity packages have no legitimate reason to use hidden " +
        "directories; their presence may be an attempt to conceal malicious content from reviewers " +
        "who inspect a package's file tree before import.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        ".DS_Store files are macOS metadata accidentally bundled by the package author. " +
        "They are harmless but indicate the author did not clean up before packaging.",
        "Some package managers or asset pipeline tools create dot-prefixed working directories; " +
        "verify the publisher intent before concluding the path is intentionally hidden.",
    ];

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            var hiddenPart = FindHiddenComponent(entry.Pathname);
            if (hiddenPart is null) continue;

            logger.LogDebug("{RuleId}: hidden component '{Part}' in {Path}", RuleId, hiddenPart, entry.Pathname);

            yield return new Finding
            {
                RuleId = RuleId,
                Severity = DefaultSeverity,
                Title = Title,
                Description =
                    $"This asset is stored under a dot-prefixed directory '{hiddenPart}', which is " +
                    "invisible by default in macOS and Linux file managers. Unity packages should not " +
                    "use hidden directories.",
                Entry = entry,
                Evidence = $"Hidden component: '{hiddenPart}'",
            };
        }

        await Task.CompletedTask;
    }

    private static string? FindHiddenComponent(string pathname)
    {
        // Normalise separators, then check each directory component.
        var parts = pathname.Replace('\\', '/').Split('/');
        foreach (var part in parts)
        {
            // Skip the file name (last segment) — only flag hidden directories.
            if (part == parts[^1]) break;

            if (part.StartsWith('.') && part.Length > 1)
                return part;
        }
        return null;
    }
}
