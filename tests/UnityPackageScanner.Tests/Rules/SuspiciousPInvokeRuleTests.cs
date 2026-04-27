using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class SuspiciousPInvokeRuleTests
{
    private readonly SuspiciousPInvokeRule _rule = new(NullLogger<SuspiciousPInvokeRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_pinvoke_declaration()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithPInvoke());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.SuspiciousPInvoke);
    }

    [Fact]
    public async Task Finding_has_HighRisk_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithPInvoke());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task Evidence_mentions_dll_name()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithPInvoke("kernel32.dll"));
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("kernel32.dll");
    }

    [Fact]
    public async Task Fires_on_custom_native_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithPInvoke("evil_native.dll"));
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("evil_native.dll");
    }

    [Fact]
    public async Task Fires_on_NativeLibrary_Load_call()
    {
        var entries = await BuildAndExtract("Assets/Plugins/native.dll", ManagedDllBuilder.WithNativeLibraryLoad());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.SuspiciousPInvoke);
    }

    [Fact]
    public async Task NativeLibrary_Load_evidence_mentions_Load()
    {
        var entries = await BuildAndExtract("Assets/Plugins/native.dll", ManagedDllBuilder.WithNativeLibraryLoad());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("Load");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_clean_managed_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", NativeBinaryBuilder.CreateManagedDll());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("no P/Invoke declarations");
    }

    [Fact]
    public async Task Does_not_fire_on_network_only_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/network.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("network access is not P/Invoke");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithPInvoke());
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
