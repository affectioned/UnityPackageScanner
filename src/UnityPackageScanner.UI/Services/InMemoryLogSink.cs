using System.Collections.ObjectModel;
using Avalonia.Threading;
using Serilog.Core;
using Serilog.Events;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.UI;

/// <summary>
/// Serilog sink that pushes log events into an ObservableCollection for binding in the console panel.
/// </summary>
public sealed class InMemoryLogSink : ILogEventSink
{
    public ObservableCollection<LogEntry> Entries { get; } = [];

    public void Emit(LogEvent logEvent)
    {
        var props = logEvent.Properties
            .ToDictionary(kv => kv.Key, kv => (object)kv.Value.ToString());

        var entry = new LogEntry
        {
            Timestamp = logEvent.Timestamp,
            Level = MapLevel(logEvent.Level),
            Category = logEvent.Properties.TryGetValue("SourceContext", out var ctx)
                ? ctx.ToString().Trim('"')
                : string.Empty,
            Message = logEvent.RenderMessage(),
            Exception = logEvent.Exception,
            Properties = props,
        };

        // Dispatch to the UI thread; the sink may be called from background threads.
        Dispatcher.UIThread.Post(() => Entries.Add(entry));
    }

    private static Microsoft.Extensions.Logging.LogLevel MapLevel(LogEventLevel level) => level switch
    {
        LogEventLevel.Verbose => Microsoft.Extensions.Logging.LogLevel.Trace,
        LogEventLevel.Debug => Microsoft.Extensions.Logging.LogLevel.Debug,
        LogEventLevel.Information => Microsoft.Extensions.Logging.LogLevel.Information,
        LogEventLevel.Warning => Microsoft.Extensions.Logging.LogLevel.Warning,
        LogEventLevel.Error => Microsoft.Extensions.Logging.LogLevel.Error,
        LogEventLevel.Fatal => Microsoft.Extensions.Logging.LogLevel.Critical,
        _ => Microsoft.Extensions.Logging.LogLevel.Information,
    };
}
