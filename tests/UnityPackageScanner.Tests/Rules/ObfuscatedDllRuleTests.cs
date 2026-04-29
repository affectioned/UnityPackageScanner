using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class ObfuscatedDllRuleTests
{
    private readonly ObfuscatedDllRule _rule = new(NullLogger<ObfuscatedDllRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_dll_with_control_chars_in_names()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedNames());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.ObfuscatedDll);
    }

    [Fact]
    public async Task Finding_has_HighRisk_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedNames());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("Assets/Plugins/sneaky.dll", ManagedDllBuilder.WithObfuscatedNames());
        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Be("Assets/Plugins/sneaky.dll");
    }

    [Fact]
    public async Task Evidence_mentions_control_chars()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedNames());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().ContainEquivalentOf("control char");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_clean_managed_dll()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", NativeBinaryBuilder.CreateManagedDll());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("empty managed DLL has no obfuscation signals");
    }

    [Fact]
    public async Task Does_not_fire_on_cs_source()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Script.cs", "class X {}")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("source files are not inspected for obfuscation");
    }

    [Fact]
    public async Task Does_not_fire_on_native_elf()
    {
        var entries = await BuildAndExtract("Assets/Plugins/native.so", NativeBinaryBuilder.CreateElf64());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("ELF binaries are not parsed as managed DLLs");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedNames());
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

    [Fact]
    public async Task Does_not_fire_on_dll_with_normal_named_types()
    {
        var entries = await BuildAndExtract("Assets/Plugins/network.dll", ManagedDllBuilder.WithNetworkAccess());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("normally named DLL has no obfuscation signals");
    }

    [Fact]
    public async Task Fires_on_dll_with_control_chars_in_method_names_only()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedMethodNamesOnly());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.ObfuscatedDll);
    }

    [Fact]
    public async Task Short_name_ratio_scoring_executes_without_firing_on_its_own()
    {
        // Many short names score +30 which is below the 40-point threshold on its own.
        var entries = await BuildAndExtract("Assets/Plugins/shortnames.dll", ManagedDllBuilder.WithManyShortNames(12));
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("short-name ratio alone (score=30) is below the firing threshold");
    }

    [Fact]
    public async Task Evidence_mentions_obfuscation_attribute_when_present()
    {
        // WithObfuscatedNames also adds [ObfuscationAttribute]; both signals appear in evidence.
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll", ManagedDllBuilder.WithObfuscatedNames());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("Obfuscation");
    }

    [Fact]
    public async Task Fires_on_dll_with_high_entropy_string_literals()
    {
        // 6 all-unique-character strings → suspicious * 8 = 48, above the 40-point threshold.
        var entries = await BuildAndExtract("Assets/Plugins/obf.dll", ManagedDllBuilder.WithObfuscatedStringLiterals(6));
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.ObfuscatedDll);
    }

    [Fact]
    public async Task Evidence_mentions_obfuscated_strings()
    {
        var entries = await BuildAndExtract("Assets/Plugins/obf.dll", ManagedDllBuilder.WithObfuscatedStringLiterals(6));
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().ContainEquivalentOf("string literal");
    }

    [Fact]
    public async Task Does_not_fire_on_dll_with_normal_string_literals()
    {
        // Readable identifiers have entropy ≈ 3.5 bits/char — well below the 4.5 threshold.
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", ManagedDllBuilder.WithNormalStringLiterals());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("normal readable strings do not trigger the entropy signal");
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
