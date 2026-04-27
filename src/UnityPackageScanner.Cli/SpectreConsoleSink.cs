using Serilog.Core;
using Serilog.Events;
using Spectre.Console;

namespace UnityPackageScanner.Cli;

/// <summary>
/// Writes Serilog events to stderr via Spectre.Console.
/// Kept separate from stdout so structured output (JSON, SARIF, etc.) is not polluted.
/// </summary>
internal sealed class SpectreConsoleSink : ILogEventSink
{
    private readonly IAnsiConsole _stderr = AnsiConsole.Create(new AnsiConsoleSettings
    {
        Out = new AnsiConsoleOutput(Console.Error),
    });

    public void Emit(LogEvent logEvent)
    {
        var (color, label) = logEvent.Level switch
        {
            LogEventLevel.Verbose or LogEventLevel.Debug => ("grey", "DBG"),
            LogEventLevel.Information => ("white", "INF"),
            LogEventLevel.Warning => ("yellow", "WRN"),
            LogEventLevel.Error => ("red", "ERR"),
            LogEventLevel.Fatal => ("darkred", "FTL"),
            _ => ("white", "INF"),
        };

        var ts = logEvent.Timestamp.ToString("HH:mm:ss.fff");
        var msg = logEvent.RenderMessage();

        _stderr.MarkupLine($"[grey]{ts}[/] [{color}]{label}[/] {Markup.Escape(msg)}");

        if (logEvent.Exception is not null)
            _stderr.WriteException(logEvent.Exception);
    }
}
