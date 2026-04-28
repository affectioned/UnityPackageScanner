using UnityPackageScanner.Cli;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Tests.Formatters;

public sealed class FormatterSnapshotTests
{
    [Fact]
    public Task Json_formats_clean_result() =>
        Verify(JsonFormatter.Format(MakeCleanResult()));

    [Fact]
    public Task Json_formats_result_with_findings() =>
        Verify(JsonFormatter.Format(MakeResultWithFindings()));

    [Fact]
    public Task Sarif_formats_result_with_findings() =>
        Verify(SarifFormatter.Format(MakeResultWithFindings()));

    [Fact]
    public Task Markdown_formats_clean_result() =>
        Verify(MarkdownFormatter.Format(MakeCleanResult()));

    [Fact]
    public Task Markdown_formats_result_with_findings() =>
        Verify(MarkdownFormatter.Format(MakeResultWithFindings()));

    // --- Deterministic fixtures ---

    private static ScanResult MakeCleanResult() => new()
    {
        PackagePath = "/test/CleanAsset.unitypackage",
        PackageSize = 1024,
        PackageSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        EntryCount = 1,
        Entries =
        [
            new PackageEntry
            {
                Guid = "00000000000000000000000000000001",
                Pathname = "Assets/Script.cs",
                Size = 42,
                DetectedType = DetectedType.CSharpSource,
            },
        ],
        Findings = [],
        Verdict = Verdict.Clean,
        ScanDuration = TimeSpan.FromMilliseconds(10),
        ScannedAt = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };

    private static ScanResult MakeResultWithFindings() => new()
    {
        PackagePath = "/test/SuspiciousAsset.unitypackage",
        PackageSize = 98765,
        PackageSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        EntryCount = 2,
        Entries =
        [
            new PackageEntry
            {
                Guid = "00000000000000000000000000000001",
                Pathname = "Assets/Editor/AutoRun.cs",
                Size = 200,
                DetectedType = DetectedType.CSharpSource,
            },
            new PackageEntry
            {
                Guid = "00000000000000000000000000000002",
                Pathname = "Assets/Plugins/evil.dll",
                Size = 50000,
                DetectedType = DetectedType.ManagedDll,
            },
        ],
        Findings =
        [
            new Finding
            {
                RuleId = "UPS002",
                Severity = Severity.Critical,
                Title = "Auto-executing editor code",
                Description = "This script will execute automatically when the package is imported into a Unity project.",
                Entry = new PackageEntry
                {
                    Guid = "00000000000000000000000000000001",
                    Pathname = "Assets/Editor/AutoRun.cs",
                    Size = 200,
                    DetectedType = DetectedType.CSharpSource,
                },
                Evidence = "[InitializeOnLoad] or [InitializeOnLoadMethod] attribute found",
            },
            new Finding
            {
                RuleId = "UPS001",
                Severity = Severity.HighRisk,
                Title = "Obfuscated managed assembly",
                Description = "This managed assembly shows signs of obfuscation.",
                Entry = new PackageEntry
                {
                    Guid = "00000000000000000000000000000002",
                    Pathname = "Assets/Plugins/evil.dll",
                    Size = 50000,
                    DetectedType = DetectedType.ManagedDll,
                },
                Evidence = "Control characters in type or method names",
            },
        ],
        Verdict = Verdict.Critical,
        ScanDuration = TimeSpan.FromMilliseconds(42),
        ScannedAt = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };
}
