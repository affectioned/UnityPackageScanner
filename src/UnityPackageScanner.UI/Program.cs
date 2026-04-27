using Avalonia;
using Serilog;
using Serilog.Extensions.Logging;
using UnityPackageScanner.Core.Logging;
using UnityPackageScanner.UI;

// Configure Serilog before Avalonia starts so the file sink is ready immediately.
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

static AppBuilder BuildAvaloniaApp() =>
    AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .WithInterFont()
        .LogToTrace();
