using Microsoft.Extensions.Logging;

namespace UnityPackageScanner.Core.Models;

public sealed record LogEntry
{
    public required DateTimeOffset Timestamp { get; init; }
    public required LogLevel Level { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public Exception? Exception { get; init; }
    public IReadOnlyDictionary<string, object>? Properties { get; init; }
}
