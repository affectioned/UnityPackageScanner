using Avalonia;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;
using UnityPackageScanner.Core.Logging;
using UnityPackageScanner.UI;

internal sealed class Program
{
    // Held here so App.axaml.cs can access them in OnFrameworkInitializationCompleted,
    // which runs after the Win32 platform (and Dispatcher.UIThread) are fully initialised.
    internal static InMemoryLogSink LogSink { get; } = new();
    internal static ILoggerFactory LoggerFactory { get; private set; } = null!;

    // [STAThread] is required for Avalonia's Win32 message pump.
    [STAThread]
    public static void Main(string[] args)
    {
        var serilog = LoggingConfiguration.CreateBaseConfiguration()
            .WriteTo.Sink(LogSink)
            .CreateLogger();

        Log.Logger = serilog;
        LoggerFactory = new SerilogLoggerFactory(serilog, dispose: false);

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        finally
        {
            serilog.Dispose();
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
