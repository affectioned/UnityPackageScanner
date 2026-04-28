using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using UnityPackageScanner.UI.ViewModels;
using UnityPackageScanner.UI.Views;

namespace UnityPackageScanner.UI;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        // ServiceLocator.Initialize is called here — after UsePlatformDetect() has run and
        // Dispatcher.UIThread is fully set up — so InMemoryLogSink.Emit can safely Post to it.
        ServiceLocator.Initialize(Program.LoggerFactory, Program.LogSink);

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = ServiceLocator.MainViewModel,
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
