using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Rules;

public sealed class BinaryMasqueradeRuleTests
{
    private readonly BinaryMasqueradeRule _rule = new(NullLogger<BinaryMasqueradeRule>.Instance);
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    // Simulates the Rogue_Jinxxy.json pattern: random binary bytes that are invalid UTF-8.
    private static readonly byte[] BinaryPayload =
        [0xDF, 0xC4, 0xFD, 0xEA, 0xAD, 0xF6, 0xCA, 0x39, 0x1C, 0x15, 0x43, 0x50, 0xE7, 0x29, 0x30, 0x3E,
         0x61, 0x83, 0xC2, 0xD8, 0xF5, 0xA6, 0x21, 0xD1, 0xA7, 0x23, 0x7A, 0x7E, 0x82, 0x6F, 0xEB, 0x5A];

    // --- Positive tests ---

    [Fact]
    public async Task Fires_on_binary_json_file()
    {
        var findings = await ScanEntry("Assets/Config/config.json", BinaryPayload);

        findings.Should().ContainSingle()
            .Which.RuleId.Should().Be(KnownRuleIds.BinaryMasquerade);
    }

    [Fact]
    public async Task Fires_on_binary_xml_file()
    {
        var findings = await ScanEntry("Assets/Data/settings.xml", BinaryPayload);

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Fires_on_binary_txt_file()
    {
        var findings = await ScanEntry("Assets/notes.txt", BinaryPayload);

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Fires_on_binary_yaml_file()
    {
        var findings = await ScanEntry("Assets/config.yaml", BinaryPayload);

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Fires_on_binary_yml_file()
    {
        var findings = await ScanEntry("Assets/config.yml", BinaryPayload);

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Fires_on_binary_csv_file()
    {
        var findings = await ScanEntry("Assets/data.csv", BinaryPayload);

        findings.Should().ContainSingle();
    }

    [Fact]
    public async Task Finding_has_Suspicious_severity()
    {
        var findings = await ScanEntry("Assets/Config/secret.json", BinaryPayload);

        findings.Single().Severity.Should().Be(Severity.Suspicious);
    }

    [Fact]
    public async Task Finding_references_correct_entry()
    {
        var findings = await ScanEntry("Assets/GonsoLicense/Rogue.json", BinaryPayload);

        findings.Single().Entry!.Pathname.Should().Be("Assets/GonsoLicense/Rogue.json");
    }

    [Fact]
    public async Task Evidence_contains_extension_and_size()
    {
        var findings = await ScanEntry("Assets/Config/config.json", BinaryPayload);

        findings.Single().Evidence.Should().Contain(".json");
        findings.Single().Evidence.Should().Contain("bytes");
    }

    // --- Negative tests ---

    [Fact]
    public async Task Does_not_fire_on_valid_json()
    {
        var json = """{"key": "value", "number": 42}"""u8.ToArray();
        var findings = await ScanEntry("Assets/Config/valid.json", json);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_valid_xml()
    {
        var xml = """<?xml version="1.0" encoding="UTF-8"?><root><item>test</item></root>"""u8.ToArray();
        var findings = await ScanEntry("Assets/Data/valid.xml", xml);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Does_not_fire_on_valid_utf8_text_with_unicode()
    {
        var text = Encoding.UTF8.GetBytes("Hello, 世界! Привет мир. 🌍");
        var findings = await ScanEntry("Assets/notes.txt", text);

        findings.Should().BeEmpty("multi-byte UTF-8 sequences are valid");
    }

    [Fact]
    public async Task Does_not_fire_on_utf8_bom_prefixed_json()
    {
        var bomJson = new byte[] { 0xEF, 0xBB, 0xBF }
            .Concat("""{"bom": true}"""u8.ToArray()).ToArray();
        var findings = await ScanEntry("Assets/Config/bom.json", bomJson);

        findings.Should().BeEmpty("UTF-8 BOM is valid and should be stripped before checking");
    }

    [Fact]
    public async Task Does_not_fire_on_dll_file()
    {
        // DLLs are binary by nature — rule only applies to text-extension files.
        var findings = await ScanEntry("Assets/Plugins/lib.dll", BinaryPayload);

        findings.Should().BeEmpty("DLL files are not text-format extensions");
    }

    [Fact]
    public async Task Does_not_fire_on_small_file_below_minimum()
    {
        var tinyBinary = new byte[] { 0xFF, 0xFE, 0x00, 0x01 };
        var findings = await ScanEntry("Assets/Config/tiny.json", tinyBinary);

        findings.Should().BeEmpty("files below the minimum byte threshold are skipped");
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
        var findings = await ScanEntry("Assets/Config/config.json", BinaryPayload);

        findings.Should().BeEmpty();
        _rule.IsEnabled = true;
    }

    // --- Helpers ---

    private async Task<List<Finding>> ScanEntry(string pathname, byte[] content)
    {
        var package = new UnityPackageBuilder()
            .WithAsset(pathname, content)
            .Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);

        var findings = new List<Finding>();
        await foreach (var f in _rule.AnalyzeAsync(entries))
            findings.Add(f);
        return findings;
    }
}
