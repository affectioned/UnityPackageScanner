namespace UnityPackageScanner.Core.Models;

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public PackageEntry? Entry { get; init; }
    public string? Evidence { get; init; }

    /// <summary>
    /// Advisory findings appear on DLLs that are also flagged for obfuscation.
    /// They are shown but prefixed with a warning that static analysis was unreliable.
    /// </summary>
    public bool IsAdvisory { get; init; }
}
