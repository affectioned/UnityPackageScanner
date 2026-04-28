using System;
using Avalonia;
using Serilog;
using Serilog.Extensions.Logging;
using UnityPackageScanner.Core.Logging;
using UnityPackageScanner.UI;

internal sealed class Program
{
    // [STAThread] is required for Avalonia's Win32 message pump.
    // Top-level statements cannot carry this attribute, so we use an explicit Main.
    [STAThread]
    public static void Main(string[] args)
    {
        var logSink = new InMemoryLogSink();

        var serilog = LoggingConfiguration.CreateBaseConfiguration()
            .WriteTo.Sink(logSink)
            .CreateLogger();

        Log.Logger = serilog;

        ServiceLocator.Initialize(new SerilogLoggerFactory(serilog, dispose: false), logSink);

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
