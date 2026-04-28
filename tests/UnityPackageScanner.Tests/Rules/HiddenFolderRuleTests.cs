using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class HiddenFolderRuleTests
{
    private readonly HiddenFolderRule _rule = new(NullLogger<HiddenFolderRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_when_asset_is_in_dot_prefixed_directory()
    {
        var findings = await ScanPath("Assets/.hidden/evil.dll");

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.HiddenFolder);
    }

    [Fact]
    public async Task Finding_has_Suspicious_severity()
    {
        var findings = await ScanPath("Assets/.hidden/evil.dll");

        findings.Single().Severity.Should().Be(Severity.Suspicious);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var findings = await ScanPath("Assets/.secret/payload.dll");

        findings.Single().Entry!.Pathname.Should().Be("Assets/.secret/payload.dll");
    }

    [Fact]
    public async Task Evidence_contains_hidden_component()
    {
        var findings = await ScanPath("Assets/.hidden/evil.dll");

        findings.Single().Evidence.Should().Contain(".hidden");
    }

    [Fact]
    public async Task Fires_on_nested_hidden_directory()
    {
        var findings = await ScanPath("Assets/Plugins/.obfuscated/lib.dll");

        findings.Should().ContainSingle();
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_normal_path()
    {
        var findings = await ScanPath("Assets/Plugins/MyPlugin.dll");

        findings.Should().BeEmpty("normal asset path has no hidden directories");
    }

    [Fact]
    public async Task Does_not_fire_on_dot_file_in_root()
    {
        // A dot-prefixed FILE (not directory) in the asset root should not fire.
        var findings = await ScanPath("Assets/.DS_Store");

        findings.Should().BeEmpty("dot-file at path root is a file name, not a directory");
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
        var findings = await ScanPath("Assets/.hidden/evil.dll");

        findings.Should().BeEmpty();
        _rule.IsEnabled = true;
    }

    // --- Helpers ---

    private async Task<List<Finding>> ScanPath(string pathname)
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, "content"u8.ToArray())
            .Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);

        var findings = new List<Finding>();
        await foreach (var f in _rule.AnalyzeAsync(entries))
            findings.Add(f);
        return findings;
    }
}
