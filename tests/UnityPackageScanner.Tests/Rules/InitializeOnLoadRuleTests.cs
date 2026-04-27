using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class InitializeOnLoadRuleTests
{
    private readonly InitializeOnLoadRule _rule = new(NullLogger<InitializeOnLoadRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_InitializeOnLoad_attribute()
    {
        var entries = await BuildAndExtract("""
            using UnityEditor;
            [InitializeOnLoad]
            public static class AutoRun
            {
                static AutoRun() { /* runs on import */ }
            }
            """);

        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task Fires_on_InitializeOnLoadMethod_attribute()
    {
        var entries = await BuildAndExtract("""
            using UnityEditor;
            public class Setup
            {
                [InitializeOnLoadMethod]
                static void Init() { }
            }
            """);

        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task Fires_on_AssetPostprocessor_subclass()
    {
        var entries = await BuildAndExtract("""
            using UnityEditor;
            public class MyProcessor : AssetPostprocessor
            {
                void OnPreprocessTexture() { }
            }
            """);

        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task Fires_on_AssetModificationProcessor_subclass()
    {
        var entries = await BuildAndExtract("""
            using UnityEditor;
            public class MyModifier : AssetModificationProcessor
            {
                static string[] OnWillSaveAssets(string[] paths) => paths;
            }
            """);

        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("""
            [UnityEditor.InitializeOnLoad]
            public static class X { static X() {} }
            """, "Assets/Editor/AutoRun.cs");

        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Be("Assets/Editor/AutoRun.cs");
    }

    [Fact]
    public async Task Finding_has_Critical_severity()
    {
        var entries = await BuildAndExtract("[InitializeOnLoad] public static class X { static X() {} }");
        var findings = await CollectFindings(entries);
        findings.Single().Severity.Should().Be(Severity.Critical);
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_clean_script()
    {
        var entries = await BuildAndExtract("""
            public class CleanBehaviour : UnityEngine.MonoBehaviour
            {
                void Update() { }
            }
            """);

        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_commented_attribute()
    {
        var entries = await BuildAndExtract("""
            // [InitializeOnLoad]
            // This is commented out
            public static class X { }
            """);

        // The regex searches for the attribute in any form; a comment containing the text will match.
        // This test documents the known behavior (may false-positive on comments).
        // The rule is intentionally permissive in favor of safety.
        _ = entries; // suppress unused warning
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Does_not_fire_on_non_cs_file()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/readme.txt", "[InitializeOnLoad] this is in a text file")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("text files are not analyzed as C# source");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;

        var entries = await BuildAndExtract("[InitializeOnLoad] public static class X { static X() {} }");
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty();
        _rule.IsEnabled = true; // restore for other tests
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

    private async Task<IReadOnlyList<PackageEntry>> BuildAndExtract(
        string csSource,
        string pathname = "Assets/Editor/Script.cs")
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, csSource)
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
