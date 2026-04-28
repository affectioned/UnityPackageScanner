using FluentAssertions;
using Spectre.Console;
using UnityPackageScanner.Cli;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Tests.Formatters;

public sealed class TextFormatterTests
{
    private static IAnsiConsole MakeTestConsole(StringWriter writer) =>
        AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Out = new AnsiConsoleOutput(writer),
        });

    [Fact]
    public void WriteResult_clean_shows_verdict_and_metadata()
    {
        var writer = new StringWriter();
        TextFormatter.WriteResult(MakeCleanResult(), quiet: false, MakeTestConsole(writer));

        var output = writer.ToString();
        output.Should().Contain("CLEAN");
        output.Should().Contain("CleanAsset.unitypackage");
        output.Should().Contain("SHA-256");
        output.Should().Contain("No findings");
    }

    [Fact]
    public void WriteResult_quiet_suppresses_details()
    {
        var writer = new StringWriter();
        TextFormatter.WriteResult(MakeCleanResult(), quiet: true, MakeTestConsole(writer));

        var output = writer.ToString();
        output.Should().Contain("CLEAN");
        output.Should().NotContain("SHA-256");
        output.Should().NotContain("No findings");
    }

    [Fact]
    public void WriteResult_groups_findings_by_severity()
    {
        var writer = new StringWriter();
        TextFormatter.WriteResult(MakeResultWithFindings(), quiet: false, MakeTestConsole(writer));

        var output = writer.ToString();
        output.Should().Contain("CRITICAL");
        output.Should().Contain("HIGH RISK");
        output.Should().Contain("Auto-executing editor code");
        output.Should().Contain("Obfuscated managed assembly");
        output.Should().Contain("Assets/Editor/AutoRun.cs");
        output.Should().Contain("[InitializeOnLoad]");
    }

    [Fact]
    public void WriteResult_shows_suspicious_severity_group()
    {
        var writer = new StringWriter();
        var result = new ScanResult
        {
            PackagePath = "/test/Test.unitypackage",
            PackageSize = 0,
            PackageSha256 = "cc",
            EntryCount = 1,
            Entries = [],
            Findings =
            [
                new Finding
                {
                    RuleId = "UPS010",
                    Severity = Severity.Suspicious,
                    Title = "Hidden folder",
                    Description = "Dot-prefixed directory component.",
                },
            ],
            Verdict = Verdict.Suspicious,
            ScanDuration = TimeSpan.Zero,
            ScannedAt = DateTimeOffset.UtcNow,
        };

        TextFormatter.WriteResult(result, quiet: false, MakeTestConsole(writer));

        writer.ToString().Should().Contain("SUSPICIOUS");
        writer.ToString().Should().Contain("Hidden folder");
    }

    [Fact]
    public void WriteResult_marks_advisory_findings()
    {
        var writer = new StringWriter();
        var result = new ScanResult
        {
            PackagePath = "/test/Test.unitypackage",
            PackageSize = 0,
            PackageSha256 = "dd",
            EntryCount = 1,
            Entries = [],
            Findings =
            [
                new Finding
                {
                    RuleId = "UPS001",
                    Severity = Severity.Suspicious,
                    Title = "Advisory finding",
                    Description = "DLL could not be fully analyzed.",
                    IsAdvisory = true,
                },
            ],
            Verdict = Verdict.Suspicious,
            ScanDuration = TimeSpan.Zero,
            ScannedAt = DateTimeOffset.UtcNow,
        };

        TextFormatter.WriteResult(result, quiet: false, MakeTestConsole(writer));

        writer.ToString().Should().Contain("advisory");
    }

    [Theory]
    [InlineData("never", Verdict.Critical, 0)]
    [InlineData("clean", Verdict.Clean, 0)]
    [InlineData("clean", Verdict.Suspicious, 1)]
    [InlineData("suspicious", Verdict.Suspicious, 1)]
    [InlineData("suspicious", Verdict.Clean, 0)]
    [InlineData("high", Verdict.HighRisk, 1)]
    [InlineData("high", Verdict.Clean, 0)]
    [InlineData("critical", Verdict.Critical, 1)]
    [InlineData("critical", Verdict.HighRisk, 0)]
    [InlineData("unknown_default", Verdict.Critical, 0)]
    public void ToExitCode_returns_expected_code(string failOn, Verdict verdict, int expected) =>
        TextFormatter.ToExitCode(verdict, failOn).Should().Be(expected);

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
                Description = "This script will execute automatically when the package is imported.",
                Entry = new PackageEntry
                {
                    Guid = "00000000000000000000000000000001",
                    Pathname = "Assets/Editor/AutoRun.cs",
                    Size = 200,
                    DetectedType = DetectedType.CSharpSource,
                },
                Evidence = "[InitializeOnLoad] attribute found",
            },
            new Finding
            {
                RuleId = "UPS001",
                Severity = Severity.HighRisk,
                Title = "Obfuscated managed assembly",
                Description = "Signs of obfuscation detected.",
                Entry = new PackageEntry
                {
                    Guid = "00000000000000000000000000000002",
                    Pathname = "Assets/Plugins/evil.dll",
                    Size = 50000,
                    DetectedType = DetectedType.ManagedDll,
                },
                Evidence = "Control characters in names",
            },
        ],
        Verdict = Verdict.Critical,
        ScanDuration = TimeSpan.FromMilliseconds(42),
        ScannedAt = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };
}
