using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class NativePluginRuleTests
{
    private readonly NativePluginRule _rule = new(NullLogger<NativePluginRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_elf_binary()
    {
        var entries = await BuildAndExtract("Assets/Plugins/Linux/libfoo.so", NativeBinaryBuilder.CreateElf64());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.NativePlugin);
    }

    [Fact]
    public async Task Fires_on_macho_binary()
    {
        var entries = await BuildAndExtract("Assets/Plugins/macOS/libfoo.dylib", NativeBinaryBuilder.CreateMachO64());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.NativePlugin);
    }

    [Fact]
    public async Task Fires_on_native_pe_stub()
    {
        // Minimal MZ bytes with no valid PE structure — AsmResolver cannot parse it,
        // so IsNativePe falls back to true (safe/conservative default).
        var entries = await BuildAndExtract("Assets/Plugins/Windows/payload.dll", NativeBinaryBuilder.CreateNativePeStub());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.NativePlugin);
    }

    [Fact]
    public async Task ELF_finding_has_Critical_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/libfoo.so", NativeBinaryBuilder.CreateElf64());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("Assets/Plugins/libbar.so", NativeBinaryBuilder.CreateElf64());
        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Be("Assets/Plugins/libbar.so");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_managed_dll()
    {
        // A valid managed assembly has a CLR directory — IsNativePe returns false.
        var managedBytes = NativeBinaryBuilder.CreateManagedDll();
        var entries = await BuildAndExtract("Assets/Plugins/Managed.dll", managedBytes);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("managed assemblies have a CLR directory and are not native plugins");
    }

    [Fact]
    public async Task Does_not_fire_on_cs_source_file()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Editor/Script.cs", "public class Foo {}")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("C# source files are not native binaries");
    }

    [Fact]
    public async Task Does_not_fire_on_png_texture()
    {
        // PNG magic bytes — not MZ/ELF/Mach-O
        var pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
        var entries = await BuildAndExtract("Assets/Textures/icon.png", pngBytes);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("PNG files are not native binaries");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;

        var entries = await BuildAndExtract("Assets/Plugins/libfoo.so", NativeBinaryBuilder.CreateElf64());
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
    public async Task Does_not_fire_on_native_pe_entry_without_bytes()
    {
        // AssetBytes == null means the asset file was absent or too large — skip silently.
        var package = new UnityPackageBuilder()
            .WithEmptyAsset("Assets/Plugins/payload.dll")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("no asset bytes to inspect");
    }

    // --- Helpers ---

    private async Task<IReadOnlyList<PackageEntry>> BuildAndExtract(string pathname, byte[] bytes)
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, bytes)
            .Build();

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
