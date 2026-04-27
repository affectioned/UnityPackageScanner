using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Analysis;

/// <summary>
/// Contract for all detection rules. Implementations live in UnityPackageScanner.Rules.
/// </summary>
public interface IDetectionRule
{
    string RuleId { get; }
    string Title { get; }
    Severity DefaultSeverity { get; }
    bool IsEnabled { get; set; }

    /// <summary>One-paragraph explanation shown in docs/rules.md and the Settings view.</summary>
    string LongDescription { get; }

    /// <summary>Patterns that produce false positives, shown in docs/rules.md.</summary>
    IReadOnlyList<string> FalsePositivePatterns { get; }

    IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        CancellationToken ct = default);
}
