using FluentAssertions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Tests.Core;

public sealed class VerdictAggregatorTests
{
    private static Finding MakeFinding(string ruleId, Severity severity) => new()
    {
        RuleId = ruleId,
        Severity = severity,
        Title = "test",
        Description = "test",
    };

    [Fact]
    public void Empty_findings_yields_Clean()
    {
        VerdictAggregator.Aggregate([]).Should().Be(Verdict.Clean);
    }

    [Fact]
    public void Informational_only_yields_Clean()
    {
        var findings = new[] { MakeFinding(KnownRuleIds.PackageInfo, Severity.Informational) };
        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.Clean);
    }

    [Fact]
    public void Suspicious_severity_yields_Suspicious()
    {
        var findings = new[] { MakeFinding(KnownRuleIds.HashBlocklist, Severity.Suspicious) };
        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.Suspicious);
    }

    [Fact]
    public void HighRisk_severity_yields_HighRisk()
    {
        var findings = new[] { MakeFinding(KnownRuleIds.NetworkAccess, Severity.HighRisk) };
        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.HighRisk);
    }

    [Fact]
    public void Critical_severity_yields_Critical()
    {
        var findings = new[] { MakeFinding(KnownRuleIds.AutoExecuteEditor, Severity.Critical) };
        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.Critical);
    }

    [Fact]
    public void Obfuscation_finding_forces_Critical_regardless_of_other_findings()
    {
        var findings = new[]
        {
            MakeFinding(KnownRuleIds.ObfuscatedDll, Severity.Critical),
            MakeFinding(KnownRuleIds.PackageInfo, Severity.Informational),
            MakeFinding(KnownRuleIds.PackageInfo, Severity.Informational),
        };

        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.Critical);
    }

    [Fact]
    public void Native_plugin_alone_yields_at_least_HighRisk()
    {
        var findings = new[]
        {
            MakeFinding(KnownRuleIds.NativePlugin, Severity.HighRisk),
        };

        var verdict = VerdictAggregator.Aggregate(findings);
        ((int)verdict).Should().BeGreaterThanOrEqualTo((int)Verdict.HighRisk);
    }

    [Fact]
    public void Verdict_is_max_severity_when_no_overrides_apply()
    {
        var findings = new[]
        {
            MakeFinding(KnownRuleIds.HashBlocklist, Severity.Suspicious),
            MakeFinding(KnownRuleIds.NetworkAccess, Severity.HighRisk),
            MakeFinding(KnownRuleIds.PackageInfo, Severity.Informational),
        };

        VerdictAggregator.Aggregate(findings).Should().Be(Verdict.HighRisk);
    }

    [Fact]
    public void ApplyAdvisoryFlags_marks_sibling_findings_on_obfuscated_dll()
    {
        var guid = Guid.NewGuid().ToString("N");
        var entry = new PackageEntry
        {
            Guid = guid,
            Pathname = "Assets/Plugins/bad.dll",
            DetectedType = DetectedType.ManagedDll,
        };

        var obfuscation = new Finding
        {
            RuleId = KnownRuleIds.ObfuscatedDll,
            Severity = Severity.Critical,
            Title = "Obfuscated",
            Description = "...",
            Entry = entry,
        };
        var network = new Finding
        {
            RuleId = KnownRuleIds.NetworkAccess,
            Severity = Severity.HighRisk,
            Title = "Network",
            Description = "...",
            Entry = entry,
        };

        var result = VerdictAggregator.ApplyAdvisoryFlags([obfuscation, network]);

        result.Single(f => f.RuleId == KnownRuleIds.NetworkAccess).IsAdvisory.Should().BeTrue();
        result.Single(f => f.RuleId == KnownRuleIds.ObfuscatedDll).IsAdvisory.Should().BeFalse();
    }

    [Fact]
    public void ApplyAdvisoryFlags_does_not_affect_findings_on_other_entries()
    {
        var badGuid = Guid.NewGuid().ToString("N");
        var cleanGuid = Guid.NewGuid().ToString("N");

        var badEntry = new PackageEntry { Guid = badGuid, Pathname = "Assets/bad.dll", DetectedType = DetectedType.ManagedDll };
        var cleanEntry = new PackageEntry { Guid = cleanGuid, Pathname = "Assets/other.dll", DetectedType = DetectedType.ManagedDll };

        var findings = new[]
        {
            new Finding { RuleId = KnownRuleIds.ObfuscatedDll, Severity = Severity.Critical, Title = "Obf", Description = "...", Entry = badEntry },
            new Finding { RuleId = KnownRuleIds.NetworkAccess, Severity = Severity.HighRisk, Title = "Net", Description = "...", Entry = cleanEntry },
        };

        var result = VerdictAggregator.ApplyAdvisoryFlags(findings);

        result.Single(f => f.RuleId == KnownRuleIds.NetworkAccess).IsAdvisory
            .Should().BeFalse("finding is on a different entry from the obfuscated one");
    }
}
