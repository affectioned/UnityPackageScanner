using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace UnityPackageScanner.TestFixtures;

/// <summary>
/// Builds valid .unitypackage streams in memory for use in tests.
/// </summary>
public sealed class UnityPackageBuilder
{
    private readonly List<AssetSpec> _assets = [];

    /// <summary>Adds an asset with string content (UTF-8 encoded).</summary>
    public UnityPackageBuilder WithAsset(string pathname, string content) =>
        WithAsset(pathname, Encoding.UTF8.GetBytes(content));

    /// <summary>Adds an asset with string content and optional meta override.</summary>
    public UnityPackageBuilder WithAsset(string pathname, string content, string metaContent) =>
        WithAsset(pathname, Encoding.UTF8.GetBytes(content), metaContent);

    /// <summary>Adds an asset with raw byte content.</summary>
    public UnityPackageBuilder WithAsset(string pathname, byte[] content, string? metaContent = null)
    {
        _assets.Add(new AssetSpec(
            Guid: Guid.NewGuid().ToString("N"),
            Pathname: pathname,
            Content: content,
            MetaContent: metaContent ?? DefaultMeta(pathname)));
        return this;
    }

    /// <summary>
    /// Adds an asset with no content (models cases where the asset file is absent from the package).
    /// </summary>
    public UnityPackageBuilder WithEmptyAsset(string pathname)
    {
        _assets.Add(new AssetSpec(
            Guid: Guid.NewGuid().ToString("N"),
            Pathname: pathname,
            Content: null,
            MetaContent: DefaultMeta(pathname)));
        return this;
    }

    /// <summary>Serializes the package into a new <see cref="MemoryStream"/>.</summary>
    public MemoryStream Build()
    {
        var ms = new MemoryStream();
        BuildInto(ms);
        ms.Position = 0;
        return ms;
    }

    /// <summary>Serializes the package into an existing stream.</summary>
    public void BuildInto(Stream output)
    {
        using var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true);
        using var tar = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: true);

        foreach (var spec in _assets)
        {
            WriteTextEntry(tar, $"{spec.Guid}/pathname", spec.Pathname + "\n");
            WriteTextEntry(tar, $"{spec.Guid}/asset.meta", spec.MetaContent);

            if (spec.Content is not null)
                WriteBytesEntry(tar, $"{spec.Guid}/asset", spec.Content);
        }
    }

    private static void WriteTextEntry(TarWriter tar, string name, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        WriteBytesEntry(tar, name, bytes);
    }

    private static void WriteBytesEntry(TarWriter tar, string name, byte[] bytes)
    {
        var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(bytes, writable: false),
        };
        tar.WriteEntry(entry);
    }

    private static string DefaultMeta(string pathname) =>
        $"""
        fileFormatVersion: 2
        guid: {Guid.NewGuid():N}
        DefaultImporter:
          externalObjects:
          userData:
          assetBundleName:
          assetBundleVariant:
        """;

    private sealed record AssetSpec(string Guid, string Pathname, byte[]? Content, string MetaContent);
}
