using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.UI.ViewModels;

public sealed partial class FindingViewModel(Finding finding) : ObservableObject
{
    public string RuleId => finding.RuleId;
    public string Title => finding.Title;
    public string Description => finding.Description;
    public string? Evidence => finding.Evidence;
    public string? Pathname => finding.Entry?.Pathname;
    public Severity Severity => finding.Severity;
    public bool IsAdvisory => finding.IsAdvisory;

    public string SeverityLabel => finding.Severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.HighRisk => "HIGH RISK",
        Severity.Suspicious => "SUSPICIOUS",
        _ => "INFO",
    };

    public IBrush SeverityBrush => finding.Severity switch
    {
        Severity.Critical => new SolidColorBrush(Color.Parse("#D44040")),
        Severity.HighRisk => new SolidColorBrush(Color.Parse("#D47B3F")),
        Severity.Suspicious => new SolidColorBrush(Color.Parse("#D4B84A")),
        _ => new SolidColorBrush(Color.Parse("#888888")),
    };

    [ObservableProperty]
    private bool _isExpanded;
}
