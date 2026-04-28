using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using UnityPackageScanner.UI.ViewModels;

namespace UnityPackageScanner.UI.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        AddHandler(DragDrop.DropEvent, OnDrop);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        var files = e.Data.GetFiles();
        if (files is null) return;

        var first = files.FirstOrDefault(f =>
            f.Name.EndsWith(".unitypackage", StringComparison.OrdinalIgnoreCase));

        if (first?.TryGetLocalPath() is string path)
            vm.ScanPackageCommand.Execute(path);
    }

    private async void OnOpenClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not MainViewModel vm) return;

        var dialog = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Unity Package",
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType("Unity Package")
                {
                    Patterns = ["*.unitypackage"],
                    MimeTypes = ["application/octet-stream"],
                },
                new FilePickerFileType("All Files") { Patterns = ["*"] },
            ],
        });

        if (dialog.Count > 0 && dialog[0].TryGetLocalPath() is string path)
            vm.ScanPackageCommand.Execute(path);
    }

    private void OnFindingClick(object? sender, PointerPressedEventArgs e)
    {
        if (sender is Border { DataContext: FindingViewModel finding })
            finding.IsExpanded = !finding.IsExpanded;
    }
}
