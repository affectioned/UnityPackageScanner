using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class NetworkAccessRuleTests
{
    private readonly NetworkAccessRule _rule = new(NullLogger<NetworkAccessRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_HttpClient_call()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.NetworkAccess);
    }

    [Fact]
    public async Task Finding_has_HighRisk_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("Assets/Plugins/spy.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Be("Assets/Plugins/spy.dll");
    }

    [Fact]
    public async Task Evidence_mentions_HttpClient()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("HttpClient");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_clean_managed_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", NativeBinaryBuilder.CreateManagedDll());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("no network types referenced");
    }

    [Fact]
    public async Task Does_not_fire_on_native_binary()
    {
        var entries = await BuildAndExtract("Assets/Plugins/native.so", NativeBinaryBuilder.CreateElf64());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("ELF is not a managed DLL");
    }

    [Fact]
    public async Task Does_not_fire_on_cs_source()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Script.cs", "using System.Net.Http; class X {}")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("source files are not inspected for method bodies");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithNetworkAccess());
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
