using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.UI.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly ScanPipeline _pipeline;
    private readonly ILogger<MainViewModel> _logger;

    [ObservableProperty]
    private string _packagePath = string.Empty;

    [ObservableProperty]
    private string _packageSize = string.Empty;

    [ObservableProperty]
    private string _verdictLabel = "No file loaded";

    [ObservableProperty]
    private IBrush _verdictBrush = new SolidColorBrush(Color.Parse("#888888"));

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private string _scanStatus = string.Empty;

    public ObservableCollection<FindingViewModel> Findings { get; } = [];
    public ObservableCollection<PackageEntryViewModel> PackageEntries { get; } = [];

    public MainViewModel(ScanPipeline pipeline, ILogger<MainViewModel> logger)
    {
        _pipeline = pipeline;
        _logger = logger;
    }

    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task ScanPackageAsync(string path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path)) return;

        IsScanning = true;
        ScanStatus = "Scanning…";
        Findings.Clear();
        PackageEntries.Clear();

        try
        {
            var result = await _pipeline.ScanAsync(path, ct);

            PackagePath = result.PackagePath;
            PackageSize = FormatSize(result.PackageSize);

            foreach (var entry in result.Entries.OrderBy(e => e.Pathname))
                PackageEntries.Add(new PackageEntryViewModel(entry));

            foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
                Findings.Add(new FindingViewModel(finding));

            UpdateVerdict(result.Verdict);
            ScanStatus = $"Done — {result.EntryCount} entries, {result.Findings.Count} findings, {result.ScanDuration.TotalMilliseconds:F0}ms";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan failed for {Path}", path);
            ScanStatus = $"Error: {ex.Message}";
            UpdateVerdict(null);
        }
        finally
        {
            IsScanning = false;
        }
    }

    private bool CanScan(string path) => !IsScanning;

    private void UpdateVerdict(Verdict? verdict)
    {
        (VerdictLabel, VerdictBrush) = verdict switch
        {
            Verdict.Clean => ("CLEAN", new SolidColorBrush(Color.Parse("#4EC94E"))),
            Verdict.Suspicious => ("SUSPICIOUS", new SolidColorBrush(Color.Parse("#D4B84A"))),
            Verdict.HighRisk => ("HIGH RISK", new SolidColorBrush(Color.Parse("#D47B3F"))),
            Verdict.Critical => ("CRITICAL", new SolidColorBrush(Color.Parse("#D44040"))),
            _ => ("—", new SolidColorBrush(Color.Parse("#888888"))),
        };
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}
