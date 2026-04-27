using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Rules;
using UnityPackageScanner.UI.ViewModels;

namespace UnityPackageScanner.UI;

/// <summary>
/// Minimal manual DI — avoids a DI container dependency while keeping construction testable.
/// </summary>
internal static class ServiceLocator
{
    private static MainViewModel? _mainViewModel;

    public static MainViewModel MainViewModel =>
        _mainViewModel ?? throw new InvalidOperationException("ServiceLocator not initialized.");

    public static void Initialize(ILoggerFactory loggerFactory, InMemoryLogSink logSink)
    {
        var extractor = new UnityPackageExtractor(loggerFactory.CreateLogger<UnityPackageExtractor>());

        var rules = new IDetectionRule[]
        {
            new InitializeOnLoadRule(loggerFactory.CreateLogger<InitializeOnLoadRule>()),
            new NativePluginRule(loggerFactory.CreateLogger<NativePluginRule>()),
            new PathAnomalyRule(loggerFactory.CreateLogger<PathAnomalyRule>()),
            new NetworkAccessRule(loggerFactory.CreateLogger<NetworkAccessRule>()),
            new ProcessSpawnRule(loggerFactory.CreateLogger<ProcessSpawnRule>()),
            new ReflectionLoadRule(loggerFactory.CreateLogger<ReflectionLoadRule>()),
            new SuspiciousPInvokeRule(loggerFactory.CreateLogger<SuspiciousPInvokeRule>()),
        };

        var pipeline = new ScanPipeline(extractor, rules, loggerFactory.CreateLogger<ScanPipeline>());

        _mainViewModel = new MainViewModel(pipeline, extractor, logSink);
    }
}
