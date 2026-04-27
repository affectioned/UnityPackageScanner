using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Analysis;

public static class VerdictAggregator
{
    public static Verdict Aggregate(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0) return Verdict.Clean;

        // Any obfuscation finding forces Critical immediately.
        if (findings.Any(f => f.RuleId == KnownRuleIds.ObfuscatedDll))
            return Verdict.Critical;

        // Native plugin forces at least HighRisk.
        var maxSeverity = findings.Max(f => f.Severity);

        if (maxSeverity == Severity.Critical) return Verdict.Critical;
        if (maxSeverity == Severity.HighRisk) return Verdict.HighRisk;

        if (findings.Any(f => f.RuleId == KnownRuleIds.NativePlugin))
            return Verdict.HighRisk;

        if (maxSeverity == Severity.Suspicious) return Verdict.Suspicious;

        return Verdict.Clean;
    }

    /// <summary>
    /// Marks findings on DLLs that are also flagged for obfuscation as advisory.
    /// </summary>
    public static IReadOnlyList<Finding> ApplyAdvisoryFlags(IReadOnlyList<Finding> findings)
    {
        var obfuscatedGuids = findings
            .Where(f => f.RuleId == KnownRuleIds.ObfuscatedDll && f.Entry is not null)
            .Select(f => f.Entry!.Guid)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (obfuscatedGuids.Count == 0) return findings;

        return findings
            .Select(f =>
                f.RuleId != KnownRuleIds.ObfuscatedDll
                && f.Entry is not null
                && obfuscatedGuids.Contains(f.Entry.Guid)
                    ? f with { IsAdvisory = true }
                    : f)
            .ToList();
    }
}
