using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class PathAnomalyRuleTests
{
    private readonly PathAnomalyRule _rule = new(NullLogger<PathAnomalyRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive: path traversal ---

    [Fact]
    public async Task Fires_on_path_traversal()
    {
        var entries = await BuildAndExtract("Assets/../../etc/passwd");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.PathAnomaly);
    }

    [Fact]
    public async Task Traversal_finding_is_Critical()
    {
        var entries = await BuildAndExtract("Assets/../malicious.cs");
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("Assets/../evil.cs");
        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Contain("..");
    }

    [Fact]
    public async Task Fires_on_null_byte_in_path()
    {
        // Can't pass null bytes through the tar builder, so test the rule directly.
        var entry = new PackageEntry { Guid = "aaaaaaaa", Pathname = "Assets/evil\0.cs", DetectedType = DetectedType.CSharpSource };
        var findings = await CollectFindings([entry]);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    // --- Positive: absolute paths ---

    [Fact]
    public async Task Fires_on_absolute_unix_path()
    {
        var entries = await BuildAndExtract("/etc/cron.d/evil");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Fires_on_absolute_windows_path_forward_slash()
    {
        var entries = await BuildAndExtract("C:/Windows/System32/evil.dll");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Fires_on_absolute_windows_path_backslash()
    {
        // The extractor normalizes backslashes to forward slashes;
        // PathAnomalyRule also uses NormalizedPathname — still detected as drive-letter path.
        var entries = await BuildAndExtract("D:\\Users\\target\\AppData\\Roaming\\malware.dll");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    // --- Positive: reserved Unity directories ---

    [Fact]
    public async Task Fires_on_ProjectSettings_path()
    {
        var entries = await BuildAndExtract("ProjectSettings/ProjectVersion.txt");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task Fires_on_Packages_path()
    {
        var entries = await BuildAndExtract("Packages/com.company.fake/package.json");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.HighRisk);
    }

    [Fact]
    public async Task ProjectSettings_check_is_case_insensitive()
    {
        var entries = await BuildAndExtract("projectsettings/EditorBuildSettings.asset");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.PathAnomaly);
    }

    // --- Negative ---

    [Fact]
    public async Task Does_not_fire_on_normal_asset_path()
    {
        var entries = await BuildAndExtract("Assets/Scripts/PlayerController.cs");
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_editor_plugin_path()
    {
        var entries = await BuildAndExtract("Assets/Plugins/Android/libfoo.so");
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Fires_on_trailing_dotdot_without_slash()
    {
        // Previously a false negative: "Assets/Plugins/.." ends with ".." but has no trailing "/"
        var entries = await BuildAndExtract("Assets/Plugins/..");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Fires_on_bare_dotdot()
    {
        var entries = await BuildAndExtract("..");
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Does_not_fire_on_asset_path_containing_dots()
    {
        // "Assets/v1.2.3/readme.txt" contains dots but no ".." segment
        var entries = await BuildAndExtract("Assets/v1.2.3/readme.txt");
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_path_with_dotdot_as_prefix_of_segment()
    {
        // "..foo" is not a traversal segment — only an exact ".." match should fire
        var entries = await BuildAndExtract("Assets/..foo/bar.cs");
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;

        var entries = await BuildAndExtract("Assets/../../evil.cs");
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

    private async Task<IReadOnlyList<PackageEntry>> BuildAndExtract(string pathname)
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, "// content")
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
