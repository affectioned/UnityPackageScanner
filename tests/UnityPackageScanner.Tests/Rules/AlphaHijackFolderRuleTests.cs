using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class AlphaHijackFolderRuleTests
{
    private readonly AlphaHijackFolderRule _rule = new(NullLogger<AlphaHijackFolderRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_dll_in_bang_prefixed_folder()
    {
        var findings = await ScanPath("Assets/!Author/Editor/payload.dll");

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AlphaHijackFolder);
    }

    [Fact]
    public async Task Fires_on_csharp_source_in_bang_prefixed_folder()
    {
        var findings = await ScanPath("Assets/!Tools/Editor/Setup.cs");

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AlphaHijackFolder);
    }

    [Fact]
    public async Task Fires_on_tilde_prefixed_folder()
    {
        var findings = await ScanPath("Assets/~Hidden/lib.dll");

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Fires_on_hash_prefixed_folder()
    {
        var findings = await ScanPath("Assets/#Priority/Editor/hook.dll");

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Finding_has_Suspicious_severity()
    {
        var findings = await ScanPath("Assets/!Temmie/Editor/TOS.dll");

        findings.Single().Severity.Should().Be(Severity.Suspicious);
    }

    [Fact]
    public async Task Evidence_names_the_hijack_folder()
    {
        var findings = await ScanPath("Assets/!Temmie/Editor/TOS.dll");

        findings.Single().Evidence.Should().Contain("!Temmie");
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var findings = await ScanPath("Assets/!Author/Editor/malware.dll");

        findings.Single().Entry!.Pathname.Should().Be("Assets/!Author/Editor/malware.dll");
    }

    [Fact]
    public async Task Fires_on_nested_hijack_folder()
    {
        var findings = await ScanPath("Assets/Normal/!Sub/payload.dll");

        findings.Should().ContainSingle();
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_dll_in_normal_folder()
    {
        var findings = await ScanPath("Assets/Plugins/MyPlugin.dll");

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_texture_in_bang_folder()
    {
        // Textures / meshes cannot execute code — only flag executables.
        var findings = await ScanPath("Assets/!Author/Textures/albedo.png");

        findings.Should().BeEmpty("non-executable assets in a '!'-folder are not a risk");
    }

    [Fact]
    public async Task Does_not_fire_when_file_name_starts_with_bang()
    {
        // '!' in the file name itself (last path segment) is not a directory prefix.
        var findings = await ScanPath("Assets/Normal/!readme.txt");

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_single_char_bang_folder()
    {
        // A lone '!' is too ambiguous — only flag when the folder name has content after the prefix.
        var findings = await ScanPath("Assets/!/payload.dll");

        findings.Should().BeEmpty("single-character folder '!' has no name after the prefix");
    }

    [Fact]
    public async Task Does_not_fire_on_empty_package()
    {
        var package = new UnityPackageBuilder().Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = new List<Finding>();
        await foreach (var f in _rule.AnalyzeAsync(entries))
            findings.Add(f);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var findings = await ScanPath("Assets/!Temmie/Editor/TOS.dll");

        findings.Should().BeEmpty();
        _rule.IsEnabled = true;
    }

    // --- Helpers ---

    private async Task<List<Finding>> ScanPath(string pathname)
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, "placeholder"u8.ToArray())
            .Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);

        var findings = new List<Finding>();
        await foreach (var f in _rule.AnalyzeAsync(entries))
            findings.Add(f);
        return findings;
    }
}
