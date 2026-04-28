using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class SuspiciousFileTypeRuleTests
{
    private readonly SuspiciousFileTypeRule _rule = new(NullLogger<SuspiciousFileTypeRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests (Critical severity extensions) ---

    [Theory]
    [InlineData("evil.exe")]
    [InlineData("evil.com")]
    [InlineData("evil.scr")]
    [InlineData("evil.bat")]
    [InlineData("evil.cmd")]
    public async Task Fires_as_Critical_on_windows_executable_types(string filename)
    {
        var findings = await ScanPath($"Assets/{filename}");

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Theory]
    [InlineData("evil.ps1")]
    [InlineData("evil.vbs")]
    [InlineData("evil.wsf")]
    [InlineData("evil.sh")]
    [InlineData("evil.lnk")]
    public async Task Fires_as_HighRisk_on_script_and_shortcut_types(string filename)
    {
        var findings = await ScanPath($"Assets/{filename}");

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.HighRisk);
    }

    [Theory]
    [InlineData("evil.scf")]
    [InlineData("evil.jar")]
    public async Task Fires_as_Suspicious_on_lower_risk_types(string filename)
    {
        var findings = await ScanPath($"Assets/{filename}");

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Suspicious);
    }

    [Fact]
    public async Task Finding_has_correct_rule_id()
    {
        var findings = await ScanPath("Assets/evil.exe");

        findings.Single().RuleId.Should().Be(KnownRuleIds.SuspiciousFileType);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var findings = await ScanPath("Assets/Tools/launcher.exe");

        findings.Single().Entry!.Pathname.Should().Be("Assets/Tools/launcher.exe");
    }

    [Fact]
    public async Task Evidence_mentions_extension()
    {
        var findings = await ScanPath("Assets/evil.exe");

        findings.Single().Evidence.Should().Contain(".exe");
    }

    // --- Negative tests ---

    [Theory]
    [InlineData("Script.cs")]
    [InlineData("Plugin.dll")]
    [InlineData("Texture.png")]
    [InlineData("Audio.wav")]
    [InlineData("Data.json")]
    [InlineData("Scene.unity")]
    [InlineData("Prefab.prefab")]
    public async Task Does_not_fire_on_legitimate_unity_extensions(string filename)
    {
        var findings = await ScanPath($"Assets/{filename}");

        findings.Should().BeEmpty($"{filename} is a legitimate Unity asset type");
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
        var findings = await ScanPath("Assets/evil.exe");

        findings.Should().BeEmpty();
        _rule.IsEnabled = true;
    }

    [Fact]
    public async Task Extension_comparison_is_case_insensitive()
    {
        var findings = await ScanPath("Assets/EVIL.EXE");

        findings.Should().ContainSingle("extension check must be case-insensitive");
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
