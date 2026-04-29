using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects file paths that could escape the Unity project directory or overwrite
/// sensitive project configuration. Checks for directory traversal, absolute paths,
/// null bytes, and entries targeting reserved Unity directories.
/// </summary>
public sealed class PathAnomalyRule(ILogger<PathAnomalyRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.PathAnomaly;
    public string Title => "Suspicious file path";
    public Severity DefaultSeverity => Severity.Critical;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects file paths inside the package that could escape the Unity project directory " +
        "or overwrite sensitive project configuration. Checks for directory traversal segments " +
        "('..'), absolute Unix and Windows paths, null bytes, and entries targeting reserved " +
        "Unity directories (ProjectSettings/, Packages/).";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "No legitimate Unity package should contain path traversal sequences or absolute paths. " +
        "These patterns have essentially no false-positive rate.",
        "Packages that ship ProjectSettings templates as documentation may include a " +
        "'ProjectSettings/' folder. This is extremely unusual and still warrants scrutiny.",
    ];

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            var finding = CheckPath(entry);
            if (finding is not null)
                yield return finding;
        }

        await Task.CompletedTask;
    }

    private Finding? CheckPath(PackageEntry entry)
    {
        var path = entry.NormalizedPathname;

        if (path.Split('/').Any(s => s == ".."))
        {
            logger.LogWarning("{RuleId}: path traversal in '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.Critical,
                "Contains '..' path segment",
                "The path contains a directory traversal segment ('..') that could write files outside the Unity project directory.");
        }

        if (path.Contains('\0'))
        {
            logger.LogWarning("{RuleId}: null byte in path '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.Critical,
                "Path contains a null byte (\\0)",
                "The path contains a null byte, which can be used to truncate the path in C-based APIs and evade path-validation filters.");
        }

        if (path.StartsWith('/'))
        {
            logger.LogWarning("{RuleId}: absolute Unix path '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.Critical,
                "Starts with '/' (absolute Unix path)",
                "The path is an absolute Unix filesystem path. Importing this package could overwrite arbitrary files on the host system.");
        }

        if (path.Length >= 3 && char.IsLetter(path[0]) && path[1] == ':' && (path[2] == '/' || path[2] == '\\'))
        {
            logger.LogWarning("{RuleId}: absolute Windows path '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.Critical,
                $"Drive-letter path ({path[..3]}) — absolute Windows path",
                "The path is an absolute Windows filesystem path. Importing this package could overwrite arbitrary files on the host system.");
        }

        if (path.StartsWith("ProjectSettings/", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("{RuleId}: targets ProjectSettings/ — '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.HighRisk,
                "Path prefix: ProjectSettings/",
                "This entry targets Unity's ProjectSettings directory, which controls editor behavior and build configuration. Overwriting these files can alter project-wide security settings.");
        }

        if (path.StartsWith("Packages/", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("{RuleId}: targets Packages/ — '{Path}'", RuleId, path);
            return MakeFinding(entry, Severity.HighRisk,
                "Path prefix: Packages/",
                "This entry targets Unity's Packages directory, used for package dependency resolution. It could shadow or replace installed packages with malicious versions.");
        }

        return null;
    }

    private Finding MakeFinding(PackageEntry entry, Severity severity, string evidence, string description) => new()
    {
        RuleId = RuleId,
        Severity = severity,
        Title = Title,
        Description = description,
        Entry = entry,
        Evidence = evidence,
    };
}
