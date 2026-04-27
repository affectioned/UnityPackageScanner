using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Rules;

namespace UnityPackageScanner.Tests.Rules;

public sealed class RuleMetadataTests
{
    public static TheoryData<IDetectionRule> AllRules() => new()
    {
        new InitializeOnLoadRule(NullLogger<InitializeOnLoadRule>.Instance),
        new NativePluginRule(NullLogger<NativePluginRule>.Instance),
        new NetworkAccessRule(NullLogger<NetworkAccessRule>.Instance),
        new PathAnomalyRule(NullLogger<PathAnomalyRule>.Instance),
        new ProcessSpawnRule(NullLogger<ProcessSpawnRule>.Instance),
        new ReflectionLoadRule(NullLogger<ReflectionLoadRule>.Instance),
        new SuspiciousPInvokeRule(NullLogger<SuspiciousPInvokeRule>.Instance),
    };

    [Theory]
    [MemberData(nameof(AllRules))]
    public void LongDescription_is_non_empty(IDetectionRule rule)
    {
        rule.LongDescription.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [MemberData(nameof(AllRules))]
    public void FalsePositivePatterns_has_at_least_one_entry(IDetectionRule rule)
    {
        rule.FalsePositivePatterns.Should().NotBeEmpty();
    }

    [Theory]
    [MemberData(nameof(AllRules))]
    public void RuleId_is_non_empty(IDetectionRule rule)
    {
        rule.RuleId.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [MemberData(nameof(AllRules))]
    public void Title_is_non_empty(IDetectionRule rule)
    {
        rule.Title.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [MemberData(nameof(AllRules))]
    public void IsEnabled_defaults_to_true(IDetectionRule rule)
    {
        rule.IsEnabled.Should().BeTrue();
    }
}
