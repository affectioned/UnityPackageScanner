using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class EmbeddedEncryptedResourceRuleTests
{
    private readonly EmbeddedEncryptedResourceRule _rule = new(NullLogger<EmbeddedEncryptedResourceRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_dll_with_high_entropy_embedded_resource()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll",
            ManagedDllBuilder.WithHighEntropyEmbeddedResource());
        var findings = await CollectFindings(entries);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.EmbeddedEncryptedResource);
    }

    [Fact]
    public async Task Finding_has_Suspicious_severity()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll",
            ManagedDllBuilder.WithHighEntropyEmbeddedResource());
        var findings = await CollectFindings(entries);

        findings.Single().Severity.Should().Be(Severity.Suspicious);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var entries = await BuildAndExtract("Assets/Plugins/sneaky.dll",
            ManagedDllBuilder.WithHighEntropyEmbeddedResource());
        var findings = await CollectFindings(entries);

        findings.Single().Entry!.Pathname.Should().Be("Assets/Plugins/sneaky.dll");
    }

    [Fact]
    public async Task Evidence_contains_resource_name_and_entropy()
    {
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll",
            ManagedDllBuilder.WithHighEntropyEmbeddedResource());
        var findings = await CollectFindings(entries);

        findings.Single().Evidence.Should().Contain("encrypted_payload")
            .And.Contain("entropy");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_dll_with_low_entropy_resource()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll",
            ManagedDllBuilder.WithLowEntropyEmbeddedResource());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("repeating-byte resource has near-zero entropy");
    }

    [Fact]
    public async Task Does_not_fire_on_dll_with_no_resources()
    {
        var entries = await BuildAndExtract("Assets/Plugins/clean.dll", NativeBinaryBuilder.CreateManagedDll());
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("no embedded resources present");
    }

    [Fact]
    public async Task Does_not_fire_on_cs_source()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Script.cs", "class X {}")
            .Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);
        var findings = await CollectFindings(entries);

        findings.Should().BeEmpty("source files are not inspected for embedded resources");
    }

    [Fact]
    public async Task Does_not_fire_when_rule_is_disabled()
    {
        _rule.IsEnabled = false;
        var entries = await BuildAndExtract("Assets/Plugins/evil.dll",
            ManagedDllBuilder.WithHighEntropyEmbeddedResource());
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
