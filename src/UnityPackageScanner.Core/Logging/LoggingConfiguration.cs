using System.Diagnostics.CodeAnalysis;
using Serilog;
using Serilog.Events;

namespace UnityPackageScanner.Core.Logging;

/// <summary>Shared Serilog setup used by both CLI and UI frontends.</summary>
[ExcludeFromCodeCoverage(Justification = "Pure Serilog wiring — no domain logic to unit test.")]
public static class LoggingConfiguration
{
    public static string LogDirectory =>
        Path.Combine(AppContext.BaseDirectory, "logs");

    /// <summary>
    /// Returns a Serilog <see cref="LoggerConfiguration"/> pre-wired with the rolling file sink.
    /// Callers add any front-end-specific sink (e.g. Spectre.Console for CLI) before calling CreateLogger().
    /// </summary>
    public static LoggerConfiguration CreateBaseConfiguration(bool verbose = false)
    {
        Directory.CreateDirectory(LogDirectory);

        return new LoggerConfiguration()
            .MinimumLevel.Is(verbose ? LogEventLevel.Debug : LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.File(
                path: Path.Combine(LogDirectory, "scanner-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}");
    }
}
