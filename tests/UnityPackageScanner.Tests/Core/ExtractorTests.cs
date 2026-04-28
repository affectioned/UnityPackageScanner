using System.IO.Compression;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.TestFixtures;

namespace UnityPackageScanner.Tests.Core;

public sealed class ExtractorTests
{
    private readonly UnityPackageExtractor _extractor = new(NullLogger<UnityPackageExtractor>.Instance);

    [Fact]
    public async Task Extracts_pathname_correctly()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Scripts/Player.cs", "// hello")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Should().ContainSingle()
            .Which.Pathname.Should().Be("Assets/Scripts/Player.cs");
    }

    [Fact]
    public async Task Extracts_asset_bytes_into_memory()
    {
        const string source = "public class X {}";
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/X.cs", source)
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        var entry = entries.Single();
        entry.AssetBytes.Should().NotBeNull();
        Encoding.UTF8.GetString(entry.AssetBytes!).Should().Be(source);
    }

    [Fact]
    public async Task Detects_cs_type_by_extension()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Code.cs", "// code")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().DetectedType.Should().Be(DetectedType.CSharpSource);
    }

    [Fact]
    public async Task Detects_PE_magic_bytes_overriding_extension()
    {
        // A file named .cs but starting with MZ (PE header)
        var mzBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 };
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Weird.cs", mzBytes)
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().DetectedType.Should().Be(DetectedType.NativePE,
            "magic bytes take precedence over extension");
    }

    [Fact]
    public async Task Detects_ELF_magic_bytes()
    {
        var elfBytes = new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00 };
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Plugins/libfoo.so", elfBytes)
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().DetectedType.Should().Be(DetectedType.NativeElf);
    }

    [Fact]
    public async Task Detects_MachO_magic_bytes()
    {
        // Mach-O little-endian 64-bit: CE FA ED FE
        var machoBytes = new byte[] { 0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01 };
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/Plugins/libfoo.dylib", machoBytes)
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().DetectedType.Should().Be(DetectedType.NativeMachO);
    }

    [Fact]
    public async Task Returns_empty_for_empty_package()
    {
        var package = new UnityPackageBuilder().Build();
        var entries = await _extractor.ExtractFromStreamAsync(package);
        entries.Should().BeEmpty();
    }

    [Fact]
    public async Task Skips_entries_without_pathname_file()
    {
        var package = new UnityPackageBuilder()
            .WithEmptyAsset("Assets/Normal.cs")  // has pathname
            .Build();

        // Manually craft a package with a GUID folder that only has asset, no pathname
        var ms = new System.IO.MemoryStream();
        using (var gzip = new GZipStream(ms, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new System.Formats.Tar.TarWriter(gzip, System.Formats.Tar.TarEntryFormat.Pax, leaveOpen: true))
        {
            var guid = Guid.NewGuid().ToString("N");
            var orphanEntry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, $"{guid}/asset")
            {
                DataStream = new System.IO.MemoryStream([0x01, 0x02])
            };
            tar.WriteEntry(orphanEntry);
        }
        ms.Position = 0;

        var entries = await _extractor.ExtractFromStreamAsync(ms);
        entries.Should().BeEmpty("orphan asset with no pathname is ignored");
    }

    [Fact]
    public async Task Normalizes_backslash_pathnames()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets\\Scripts\\Player.cs", "// code")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().Pathname.Should().NotContain("\\");
    }

    [Fact]
    public async Task Handles_multiple_assets()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/A.cs", "class A {}")
            .WithAsset("Assets/B.cs", "class B {}")
            .WithAsset("Assets/C.cs", "class C {}")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Should().HaveCount(3);
        entries.Select(e => e.Pathname).Should().BeEquivalentTo(
            ["Assets/A.cs", "Assets/B.cs", "Assets/C.cs"]);
    }

    [Fact]
    public async Task Returns_correct_size()
    {
        const string content = "public class X {}";
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/X.cs", content)
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().Size.Should().Be(Encoding.UTF8.GetByteCount(content));
    }

    [Fact]
    public async Task Extracts_meta_text()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/X.cs", "class X {}", "guid: abc123\nfileFormatVersion: 2")
            .Build();

        var entries = await _extractor.ExtractFromStreamAsync(package);

        entries.Single().MetaText.Should().Contain("guid: abc123");
    }

    [Fact]
    public async Task Total_memory_cap_stops_loading_bytes_when_exceeded()
    {
        // Three 100-byte entries; cap is 150 bytes — only the first entry fits.
        const int entrySize = 100;
        const long cap = 150;
        var extractor = new UnityPackageExtractor(NullLogger<UnityPackageExtractor>.Instance, totalMemoryCap: cap);

        var data = new byte[entrySize];
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/A.bin", data)
            .WithAsset("Assets/B.bin", data)
            .WithAsset("Assets/C.bin", data)
            .Build();

        var entries = await extractor.ExtractFromStreamAsync(package);

        entries.Should().HaveCount(3);
        entries.Count(e => e.AssetBytes is not null).Should().Be(1, "only the first entry fits within the cap");
        entries.Count(e => e.AssetTooLargeForMemory).Should().Be(2, "remaining entries are drained, not loaded");
    }

    [Fact]
    public async Task Total_memory_cap_does_not_affect_packages_within_limit()
    {
        const long cap = 10_000;
        var extractor = new UnityPackageExtractor(NullLogger<UnityPackageExtractor>.Instance, totalMemoryCap: cap);

        var package = new UnityPackageBuilder()
            .WithAsset("Assets/A.cs", "class A {}")
            .WithAsset("Assets/B.cs", "class B {}")
            .Build();

        var entries = await extractor.ExtractFromStreamAsync(package);

        entries.Should().HaveCount(2);
        entries.Should().AllSatisfy(e => e.AssetBytes.Should().NotBeNull("both entries fit within the cap"));
    }

    [Fact]
    public async Task Handles_truncated_gzip_gracefully()
    {
        var package = new UnityPackageBuilder()
            .WithAsset("Assets/X.cs", "class X {}")
            .Build();

        // Truncate the stream to half its length
        var truncated = new byte[package.Length / 2];
        Array.Copy(package.ToArray(), truncated, truncated.Length);

        // Should complete without crashing — returns partial (possibly empty) results.
        // ExtractFromStreamAsync logs a warning and returns whatever it could parse.
        var act = () => _extractor.ExtractFromStreamAsync(new System.IO.MemoryStream(truncated));
        await act.Should().NotThrowAsync();
    }
}
