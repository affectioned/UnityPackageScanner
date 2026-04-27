using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Core;

public sealed class ScanPipelineTests : IDisposable
{
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);
    private readonly ScanPipeline _pipeline;
    private readonly List<string> _tempFiles = [];

    public ScanPipelineTests()
    {
        var rules = new IDetectionRule[]
        {
            new InitializeOnLoadRule(NullLogger<InitializeOnLoadRule>.Instance),
        };
        _pipeline = new ScanPipeline(_extractor, rules, NullLogger<ScanPipeline>.Instance);
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles)
            if (File.Exists(f)) File.Delete(f);
    }

    [Fact]
    public async Task ScanAsync_returns_Clean_for_empty_package()
    {
        var path = await WriteTempPackage(b => { });
        var result = await _pipeline.ScanAsync(path);

        result.Verdict.Should().Be(Verdict.Clean);
        result.Findings.Should().BeEmpty();
        result.EntryCount.Should().Be(0);
    }

    [Fact]
    public async Task ScanAsync_returns_Critical_for_InitializeOnLoad_script()
    {
        var path = await WriteTempPackage(b =>
            b.WithAsset("Assets/Editor/AutoRun.cs",
                "[InitializeOnLoad] public static class X { static X() {} }"));

        var result = await _pipeline.ScanAsync(path);

        result.Verdict.Should().Be(Verdict.Critical);
        result.Findings.Should().ContainSingle(f => f.RuleId == KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task ScanAsync_populates_package_metadata()
    {
        var path = await WriteTempPackage(b =>
            b.WithAsset("Assets/X.cs", "class X {}"));

        var result = await _pipeline.ScanAsync(path);

        result.PackagePath.Should().Be(path);
        result.PackageSize.Should().BeGreaterThan(0);
        result.PackageSha256.Should().HaveLength(64, "SHA-256 hex string is 64 chars");
        result.EntryCount.Should().Be(1);
        result.ScanDuration.Should().BeGreaterThan(TimeSpan.Zero);
    }

    [Fact]
    public async Task ScanAsync_sha256_is_stable_for_same_file()
    {
        var path = await WriteTempPackage(b =>
            b.WithAsset("Assets/X.cs", "class X {}"));

        var r1 = await _pipeline.ScanAsync(path);
        var r2 = await _pipeline.ScanAsync(path);

        r1.PackageSha256.Should().Be(r2.PackageSha256);
    }

    [Fact]
    public async Task ScanAsync_respects_disabled_rule()
    {
        var rule = new InitializeOnLoadRule(NullLogger<InitializeOnLoadRule>.Instance)
        {
            IsEnabled = false,
        };
        var pipeline = new ScanPipeline(_extractor, [rule], NullLogger<ScanPipeline>.Instance);

        var path = await WriteTempPackage(b =>
            b.WithAsset("Assets/Editor/AutoRun.cs",
                "[InitializeOnLoad] public static class X { static X() {} }"));

        var result = await pipeline.ScanAsync(path);

        result.Findings.Should().BeEmpty("rule is disabled");
        result.Verdict.Should().Be(Verdict.Clean);
    }

    [Fact]
    public async Task ScanAsync_result_contains_all_entries()
    {
        var path = await WriteTempPackage(b =>
        {
            b.WithAsset("Assets/A.cs", "class A {}");
            b.WithAsset("Assets/B.cs", "class B {}");
        });

        var result = await _pipeline.ScanAsync(path);

        result.EntryCount.Should().Be(2);
        result.Entries.Should().HaveCount(2);
    }

    [Fact]
    public async Task ScanStreamingAsync_yields_same_findings_as_ScanAsync()
    {
        var entries = await _extractor.ExtractFromStreamAsync(
            new UnityPackageBuilder()
                .WithAsset("Assets/Editor/AutoRun.cs",
                    "[InitializeOnLoad] public static class X { static X() {} }")
                .Build());

        var streamedFindings = new List<Finding>();
        await foreach (var f in _pipeline.ScanStreamingAsync(entries))
            streamedFindings.Add(f);

        streamedFindings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.AutoExecuteEditor);
    }

    [Fact]
    public async Task ScanStreamingAsync_is_empty_for_clean_package()
    {
        var entries = await _extractor.ExtractFromStreamAsync(
            new UnityPackageBuilder()
                .WithAsset("Assets/Clean.cs", "class Clean {}")
                .Build());

        var findings = new List<Finding>();
        await foreach (var f in _pipeline.ScanStreamingAsync(entries))
            findings.Add(f);

        findings.Should().BeEmpty();
    }

    // --- helpers ---

    private async Task<string> WriteTempPackage(Action<UnityPackageBuilder> configure)
    {
        var builder = new UnityPackageBuilder();
        configure(builder);

        var path = Path.ChangeExtension(Path.GetTempFileName(), ".unitypackage");
        _tempFiles.Add(path);

        using var stream = builder.Build();
        await using var file = File.Create(path);
        await stream.CopyToAsync(file);
        return path;
    }
}
