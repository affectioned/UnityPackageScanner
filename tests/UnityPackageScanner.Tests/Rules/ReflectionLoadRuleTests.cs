using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class ReflectionLoadRuleTests
{
    private readonly ReflectionLoadRule _rule = new(NullLogger<ReflectionLoadRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_Assembly_LoadFrom_call()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithReflectionLoad());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.ReflectionLoad);
    }

    [Fact]
    public async Task Finding_has_HighRisk_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithReflectionLoad());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task Evidence_mentions_LoadFrom()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithReflectionLoad());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("LoadFrom");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_clean_managed_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", NativeBinaryBuilder.CreateManagedDll());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("no Assembly.Load* calls");
    }

    [Fact]
    public async Task Does_not_fire_on_network_dll()
    {
        // A DLL with HttpClient but no Assembly.Load* should not fire this rule
        var entries = await BuildAndExtract("Assets/Plugins/network.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("HttpClient is not Assembly.Load*");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithReflectionLoad());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
        _rule.IsEnabled = true;
    }

    [Fact]
    public async Task Does_not_fire_on_empty_package()
    {
        var package = new UnityPackageBuilder().Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    // --- Helpers ---

    private async Task<IReadOnlyList<PackageEntry>> BuildAndExtract(string pathname, byte[] bytes)
    {
        var package = new UnityPackageBuilder().WithAsset(pathname, bytes).Build();
        return await _extractor.ExtractFromStreamAsync(package);
    }

    private async Task<List<Finding>> CollectFindings(IReadOnlyList<PackageEntry> entries)
    {
        var findings = new List<Finding>();
        await foreach (var f in _rule.AnalyzeAsync(entries))
            findings.Add(f);
        return findings;
    }
}
