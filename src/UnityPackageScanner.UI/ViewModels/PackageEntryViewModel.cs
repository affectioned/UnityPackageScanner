using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.UI.ViewModels;

public sealed class PackageEntryViewModel(PackageEntry entry)
{
    public string Pathname => entry.Pathname;
    public string FileName => entry.FileName;
    public string Extension => entry.Extension;
    public long Size => entry.Size;
    public DetectedType DetectedType => entry.DetectedType;

    public string AnalyzabilityMarker => entry.DetectedType switch
    {
        DetectedType.ManagedDll or DetectedType.NativePE => "✓",
        _ => " ",
    };

    public string SizeDisplay => entry.Size switch
    {
        < 1024 => $"{entry.Size} B",
        < 1024 * 1024 => $"{entry.Size / 1024.0:F1} KB",
        _ => $"{entry.Size / (1024.0 * 1024):F1} MB",
    };
}
