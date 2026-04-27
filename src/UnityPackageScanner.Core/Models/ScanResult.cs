namespace UnityPackageScanner.Core.Models;

public sealed record ScanResult
{
    public required string PackagePath { get; init; }
    public required long PackageSize { get; init; }
    public required string PackageSha256 { get; init; }
    public required int EntryCount { get; init; }
    public required IReadOnlyList<PackageEntry> Entries { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required Verdict Verdict { get; init; }
    public required TimeSpan ScanDuration { get; init; }
    public DateTimeOffset ScannedAt { get; init; } = DateTimeOffset.UtcNow;
}
