using Serilog;
using Serilog.Events;

namespace UnityPackageScanner.Core.Logging;

/// <summary>Shared Serilog setup used by both CLI and UI frontends.</summary>
public static class LoggingConfiguration
{
    public static string LogDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "UnityPackageScanner",
            "logs");

    /// <summary>
    /// Returns a Serilog <see cref="LoggerConfiguration"/> pre-wired with the rolling file sink.
    /// Callers add their front-end-specific sink (in-app or Spectre.Console) before calling CreateLogger().
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
