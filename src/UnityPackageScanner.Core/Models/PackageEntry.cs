namespace UnityPackageScanner.Core.Models;

public sealed record PackageEntry
{
    public required string Guid { get; init; }

    /// <summary>The relative path inside the Unity project (from the pathname file).</summary>
    public required string Pathname { get; init; }

    /// <summary>Normalized pathname with forward slashes.</summary>
    public string NormalizedPathname => Pathname.Replace('\\', '/');

    public string FileName => Path.GetFileName(Pathname);
    public string Extension => Path.GetExtension(Pathname).ToLowerInvariant();

    /// <summary>File size in bytes (0 if asset was too large to read into memory).</summary>
    public long Size { get; init; }

    public DetectedType DetectedType { get; init; }

    /// <summary>Asset file bytes — null if entry has no asset or exceeded the in-memory threshold.</summary>
    public byte[]? AssetBytes { get; init; }

    /// <summary>Contents of the .meta file, if present.</summary>
    public string? MetaText { get; init; }

    /// <summary>True when AssetBytes is null because the file was too large, not because it has none.</summary>
    public bool AssetTooLargeForMemory { get; init; }
}
