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
