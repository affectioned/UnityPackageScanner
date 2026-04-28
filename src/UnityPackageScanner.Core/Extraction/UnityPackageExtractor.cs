using System.Buffers;
using System.IO.Compression;
using System.Runtime.CompilerServices;
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

        try
        {
        await foreach (var (name, size, data) in ReadTarEntriesAsync(gzip, InMemoryThresholdBytes, logger, ct))
        {
            // name looks like: /abc123/asset, /abc123/pathname, abc123/asset.meta, etc.
            var entryName = name.Replace('\\', '/').TrimStart('/');
            if (string.IsNullOrEmpty(entryName)) continue;

            var slash = entryName.IndexOf('/');
            if (slash < 0) continue;

            var guid = entryName[..slash];
            var file = entryName[(slash + 1)..];

            if (!buckets.TryGetValue(guid, out var bucket))
            {
                bucket = new GuidBucket();
                buckets[guid] = bucket;
            }

            switch (file)
            {
                case "pathname":
                    bucket.Pathname = data is not null ? Encoding.UTF8.GetString(data).Trim() : null;
                    break;
                case "asset.meta":
                    bucket.MetaText = data is not null ? Encoding.UTF8.GetString(data) : null;
                    break;
                case "asset":
                    bucket.AssetSize = size;
                    if (data is not null)
                    {
                        if (totalBytesLoaded + size <= totalMemoryCap)
                        {
                            bucket.AssetBytes = data;
                            totalBytesLoaded += size;
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
                            bucket.AssetTooLarge = true;
                        }
                    }
                    else if (size > 0)
                    {
                        bucket.AssetTooLarge = true;
                    }
                    break;
                default:
                    // preview.png and anything else — skip
                    break;
            }
        }
        }
        catch (InvalidDataException ex)
        {
            logger.LogWarning(ex, "Corrupt or truncated archive data — returning {Count} partial entries", buckets.Count);
        }
        catch (IOException ex)
        {
            logger.LogWarning(ex, "I/O error reading archive — returning {Count} partial entries", buckets.Count);
        }

        var results = new List<PackageEntry>(buckets.Count);
        foreach (var (guid, bucket) in buckets)
        {
            if (bucket.Pathname is null)
            {
                logger.LogDebug("GUID {Guid} has no pathname file — skipping", guid);
                continue;
            }

            var pathname = bucket.Pathname.Replace('\\', '/');
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

    // ---------------------------------------------------------------------------
    // Lenient manual tar reader
    //
    // System.Formats.Tar.TarReader is strict about header fields (magic, version)
    // and throws InvalidDataException on the first bad block, losing all subsequent
    // entries. Unity packages produced by older Unity versions or third-party tools
    // sometimes contain non-standard headers. This reader skips unreadable blocks
    // and continues, matching the behaviour of other Unity package tools.
    // ---------------------------------------------------------------------------

    private static async IAsyncEnumerable<(string Name, long Size, byte[]? Data)> ReadTarEntriesAsync(
        Stream stream,
        long perFileLimit,
        ILogger logger,
        [EnumeratorCancellation] CancellationToken ct)
    {
        const int BlockSize = 512;
        var header = new byte[BlockSize];
        string? pendingLongName = null;
        int zeroBlocks = 0;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            int read = await FillBufferAsync(stream, header, ct);
            if (read == 0) yield break;
            if (read < BlockSize)
            {
                logger.LogWarning("Unexpected end of tar archive after {Read} bytes", read);
                yield break;
            }

            // Two consecutive all-zero blocks = end-of-archive marker
            if (IsAllZero(header))
            {
                if (++zeroBlocks >= 2) yield break;
                continue;
            }
            zeroBlocks = 0;

            string name = pendingLongName ?? ParseTarName(header);
            pendingLongName = null;

            long size = ParseTarSize(header);
            if (size < 0 || size > 8L * 1024 * 1024 * 1024)
            {
                // Implausible size — header is probably garbage; skip and try next block
                logger.LogDebug("Skipping tar block with implausible size {Size} (name={Name})", size, name);
                continue;
            }

            char typeFlag = header[156] == 0 ? '0' : (char)header[156];
            long paddedSize = (size + BlockSize - 1) / BlockSize * BlockSize;

            switch (typeFlag)
            {
                case 'L': // GNU long-name extension: the data IS the filename of the next entry
                {
                    if (size is > 0 and <= 4096)
                    {
                        var nameBuf = new byte[paddedSize];
                        await FillBufferAsync(stream, nameBuf, ct);
                        pendingLongName = NullTerminatedString(nameBuf, (int)size);
                    }
                    else
                    {
                        await DrainAsync(stream, paddedSize, ct);
                    }
                    continue;
                }
                case 'K': // GNU long-link extension — not relevant for our use; skip
                {
                    await DrainAsync(stream, paddedSize, ct);
                    continue;
                }
                case '0':  // POSIX regular file
                case '\0': // pre-POSIX regular file
                {
                    byte[]? data = null;
                    if (size > 0)
                    {
                        if (size <= perFileLimit)
                        {
                            data = new byte[size];
                            int dataRead = await FillBufferAsync(stream, data, ct);
                            if (dataRead < size)
                            {
                                logger.LogWarning("Truncated data for tar entry {Name} (expected {Size})", name, size);
                                yield break;
                            }
                            long padding = paddedSize - size;
                            if (padding > 0) await DrainAsync(stream, padding, ct);
                        }
                        else
                        {
                            await DrainAsync(stream, paddedSize, ct);
                        }
                    }

                    if (!string.IsNullOrEmpty(name))
                        yield return (name, size, data);
                    break;
                }
                default: // directory, symlink, etc.
                {
                    if (paddedSize > 0) await DrainAsync(stream, paddedSize, ct);
                    break;
                }
            }
        }
    }

    private static bool IsAllZero(byte[] buf)
    {
        foreach (byte b in buf)
            if (b != 0) return false;
        return true;
    }

    private static string ParseTarName(byte[] header)
    {
        // Name: bytes 0-99 (POSIX ustar also has a 155-byte prefix at bytes 345-499)
        bool isUstar = header[257] == 'u' && header[258] == 's' && header[259] == 't' &&
                       header[260] == 'a' && header[261] == 'r';

        string name = NullTerminatedString(header, 100, offset: 0);

        if (isUstar)
        {
            string prefix = NullTerminatedString(header, 155, offset: 345);
            if (!string.IsNullOrEmpty(prefix))
                name = prefix + "/" + name;
        }

        return name;
    }

    private static long ParseTarSize(byte[] header)
    {
        // GNU base-256: high bit of byte 124 is set
        if ((header[124] & 0x80) != 0)
        {
            long size = header[124] & 0x7FL;
            for (int i = 125; i < 136; i++)
                size = size * 256 + header[i];
            return size;
        }

        // Standard octal (lenient — ignore unexpected bytes rather than throwing)
        long result = 0;
        for (int i = 124; i < 136; i++)
        {
            byte b = header[i];
            if (b == 0 || b == ' ') break;
            if (b >= '0' && b <= '7') result = result * 8 + (b - '0');
        }
        return result;
    }

    private static string NullTerminatedString(byte[] buf, int maxLen, int offset = 0)
    {
        int end = offset;
        int limit = Math.Min(offset + maxLen, buf.Length);
        while (end < limit && buf[end] != 0) end++;
        return Encoding.UTF8.GetString(buf, offset, end - offset);
    }

    /// <summary>Reads until the buffer is full or the stream ends. Returns bytes read.</summary>
    private static async Task<int> FillBufferAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    /// <summary>Reads and discards exactly <paramref name="bytes"/> bytes from the stream.</summary>
    private static async Task DrainAsync(Stream stream, long bytes, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent((int)Math.Min(bytes, 65536));
        try
        {
            while (bytes > 0)
            {
                int n = await stream.ReadAsync(buf.AsMemory(0, (int)Math.Min(bytes, buf.Length)), ct);
                if (n == 0) break;
                bytes -= n;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // ---------------------------------------------------------------------------

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

    private sealed class GuidBucket
    {
        public string? Pathname;
        public byte[]? AssetBytes;
        public string? MetaText;
        public long AssetSize;
        public bool AssetTooLarge;
    }
}
