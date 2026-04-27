using Avalonia.Media;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.UI.ViewModels;

public sealed class LogEntryViewModel(LogEntry entry)
{
    public string Timestamp => entry.Timestamp.ToString("HH:mm:ss.fff");
    public string LevelLabel => entry.Level.ToString()[..3].ToUpperInvariant();
    public string Category => entry.Category;
    public string Message => entry.Message;
    public string? ExceptionText => entry.Exception?.ToString();
    public bool HasException => entry.Exception is not null;
    public LogLevel Level => entry.Level;

    public IBrush LevelBrush => entry.Level switch
    {
        LogLevel.Critical or LogLevel.Error => new SolidColorBrush(Color.Parse("#D44040")),
        LogLevel.Warning => new SolidColorBrush(Color.Parse("#D4B84A")),
        LogLevel.Information => new SolidColorBrush(Color.Parse("#DCDCDC")),
        _ => new SolidColorBrush(Color.Parse("#888888")),
    };
}
