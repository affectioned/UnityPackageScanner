using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Extraction;

/// <summary>
/// Reads a .unitypackage (gzipped tar) and returns a list of <see cref="PackageEntry"/> records.
/// Two memory guards apply:
/// <list type="bullet">
///   <item><see cref="InMemoryThresholdBytes"/> — per-file cap (default 50 MB).</item>
///   <item><see cref="TotalMemoryCapBytes"/> — total across all entries (default 512 MB).</item>
/// </list>
/// Entries whose bytes are not loaded have <see cref="PackageEntry.AssetTooLargeForMemory"/> set to true.
/// </summary>
public sealed class UnityPackageExtractor(
    ILogger<UnityPackageExtractor> logger,
    long totalMemoryCap = 512L * 1024L * 1024L)
{
    /// <summary>Per-file cap: files larger than this are not read into memory.</summary>
    public const long InMemoryThresholdBytes = 50 * 1024 * 1024; // 50 MB

    /// <summary>
    /// Total bytes that may be loaded across all entries in one package.
    /// The default used when no value is passed to the constructor.
    /// </summary>
    public const long TotalMemoryCapBytes = 512L * 1024L * 1024L; // 512 MB

    public async Task<(IReadOnlyList<PackageEntry> Entries, string Sha256)> ExtractAsync(
        string path, CancellationToken ct = default)
    {
        logger.LogInformation("Opening package {Path} ({Size} bytes)", path, new FileInfo(path).Length);

        string sha256;
        using (var hashStream = File.OpenRead(path))
        {
            var hash = await SHA256.HashDataAsync(hashStream, ct);
            sha256 = Convert.ToHexString(hash).ToLowerInvariant();
        }

        logger.LogInformation("SHA-256: {Hash}", sha256);

        await using var fileStream = File.OpenRead(path);
        return (await ExtractFromStreamAsync(fileStream, ct), sha256);
    }

    public async Task<IReadOnlyList<PackageEntry>> ExtractFromStreamAsync(
        Stream stream, CancellationToken ct = default)
    {
        // guid -> { "asset": bytes, "pathname": text, "asset.meta": text }
        var buckets = new Dictionary<string, GuidBucket>(StringComparer.OrdinalIgnoreCase);
        long totalBytesLoaded = 0;
        bool capWarningLogged = false;

        await using var gzip = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
        using var tar = new TarReader(gzip, leaveOpen: true);

        TarEntry? entry;
        try
        {
        while ((entry = await tar.GetNextEntryAsync(copyData: false, ct)) != null)
        {
            ct.ThrowIfCancellationRequested();

            // entry.Name looks like: /abc123/asset, /abc123/pathname, abc123/asset.meta, etc.
            var name = entry.Name.Replace('\\', '/').TrimStart('/');
            if (string.IsNullOrEmpty(name)) continue;

            var slash = name.IndexOf('/');
            if (slash < 0) continue;

            var guid = name[..slash];
            var file = name[(slash + 1)..];

            if (!buckets.TryGetValue(guid, out var bucket))
            {
                bucket = new GuidBucket();
                buckets[guid] = bucket;
            }

            if (entry.DataStream is null) continue;

            switch (file)
            {
                case "pathname":
                    bucket.Pathname = await ReadTextAsync(entry.DataStream, ct);
                    break;
                case "asset.meta":
                    bucket.MetaText = await ReadTextAsync(entry.DataStream, ct);
                    break;
                case "asset":
                    if (entry.Length is > 0 and <= InMemoryThresholdBytes)
                    {
                        if (totalBytesLoaded + entry.Length <= totalMemoryCap)
                        {
                            bucket.AssetBytes = await ReadBytesAsync(entry.DataStream, (int)entry.Length, ct);
                            bucket.AssetSize = entry.Length;
                            totalBytesLoaded += entry.Length;
                        }
                        else
                        {
                            if (!capWarningLogged)
                            {
                                logger.LogWarning(
                                    "Package exceeds total in-memory cap of {CapMb} MB; " +
                                    "remaining asset bytes will not be loaded into memory for analysis",
                                    totalMemoryCap / 1024 / 1024);
                                capWarningLogged = true;
                            }
                            bucket.AssetSize = entry.Length;
                            bucket.AssetTooLarge = true;
                            await entry.DataStream.CopyToAsync(Stream.Null, ct);
                        }
                    }
                    else if (entry.Length > InMemoryThresholdBytes)
                    {
                        bucket.AssetSize = entry.Length;
                        bucket.AssetTooLarge = true;
                        // Drain the stream so TarReader can advance.
                        await entry.DataStream.CopyToAsync(Stream.Null, ct);
                    }
                    break;
                default:
                    // preview.png and anything else — skip
                    await entry.DataStream.CopyToAsync(Stream.Null, ct);
                    break;
            }
        }
        }
        catch (EndOfStreamException) when (buckets.Count == 0)
        {
            // An empty or zero-entry tar archive produces no entries; not an error.
        }

        var results = new List<PackageEntry>(buckets.Count);
        foreach (var (guid, bucket) in buckets)
        {
            if (bucket.Pathname is null)
            {
                logger.LogDebug("GUID {Guid} has no pathname file — skipping", guid);
                continue;
            }

            var pathname = bucket.Pathname.Trim().Replace('\\', '/');
            var detectedType = DetectType(pathname, bucket.AssetBytes);

            results.Add(new PackageEntry
            {
                Guid = guid,
                Pathname = pathname,
                Size = bucket.AssetSize,
                DetectedType = detectedType,
                AssetBytes = bucket.AssetBytes,
                MetaText = bucket.MetaText,
                AssetTooLargeForMemory = bucket.AssetTooLarge,
            });
        }

        logger.LogInformation("Extracted {Count} entries", results.Count);
        return results;
    }

    private static DetectedType DetectType(string pathname, byte[]? bytes)
    {
        // Magic-byte detection takes precedence over extension.
        if (bytes is { Length: >= 4 })
        {
            if (bytes[0] == 0x4D && bytes[1] == 0x5A) return DetectedType.NativePE;          // MZ
            if (bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46)
                return DetectedType.NativeElf;  // ELF
            if ((bytes[0] == 0xCE || bytes[0] == 0xCF) && bytes[1] == 0xFA && bytes[2] == 0xED && bytes[3] == 0xFE)
                return DetectedType.NativeMachO; // Mach-O LE
            if (bytes[0] == 0xFE && bytes[1] == 0xED && bytes[2] == 0xFA && (bytes[3] == 0xCE || bytes[3] == 0xCF))
                return DetectedType.NativeMachO; // Mach-O BE
            if (bytes[0] == 0xCA && bytes[1] == 0xFE && bytes[2] == 0xBA && bytes[3] == 0xBE)
                return DetectedType.NativeMachO; // Mach-O fat binary

            // Managed DLL: MZ header is already caught above; check PE characteristics separately if needed.
            // Managed assemblies start with MZ so they are detected as NativePE first;
            // the Rules layer distinguishes managed from unmanaged by reading the PE headers.
        }

        return Path.GetExtension(pathname).ToLowerInvariant() switch
        {
            ".cs" => DetectedType.CSharpSource,
            ".dll" => DetectedType.ManagedDll,
            ".so" => DetectedType.NativeElf,
            ".dylib" or ".bundle" => DetectedType.NativeMachO,
            ".png" or ".jpg" or ".jpeg" or ".tga" or ".bmp" or ".gif" or ".tif" or ".tiff" or ".psd"
                => DetectedType.Texture,
            ".fbx" or ".obj" or ".blend" or ".dae" or ".3ds" or ".max" => DetectedType.Model,
            ".wav" or ".mp3" or ".ogg" or ".aif" or ".aiff" or ".flac" => DetectedType.Audio,
            ".unity" => DetectedType.Scene,
            ".prefab" => DetectedType.Prefab,
            ".anim" => DetectedType.AnimationClip,
            ".mat" => DetectedType.Material,
            ".shader" or ".cginc" or ".hlsl" or ".glsl" => DetectedType.Shader,
            _ => DetectedType.Unknown,
        };
    }

    private static async Task<string> ReadTextAsync(Stream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static async Task<byte[]> ReadBytesAsync(Stream stream, int length, CancellationToken ct)
    {
        var buf = new byte[length];
        await stream.ReadExactlyAsync(buf, ct);
        return buf;
    }

    private sealed class GuidBucket
    {
        public string? Pathname;
        public byte[]? AssetBytes;
        public string? MetaText;
        public long AssetSize;
        public bool AssetTooLarge;
    }
}
