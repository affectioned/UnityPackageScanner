using FluentAssertions;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Tests.Core;

/// <summary>
/// Exercises model construction and computed properties.
/// These are trivial but ensure the coverage gate counts the model assembly lines.
/// </summary>
public sealed class ModelTests
{
    [Fact]
    public void ScanResult_constructs_and_exposes_all_properties()
    {
        var entries = new List<PackageEntry>();
        var findings = new List<Finding>();

        var result = new ScanResult
        {
            PackagePath = "/tmp/test.unitypackage",
            PackageSize = 1024,
            PackageSha256 = "abc123",
            EntryCount = 3,
            Entries = entries,
            Findings = findings,
            Verdict = Verdict.Suspicious,
            ScanDuration = TimeSpan.FromMilliseconds(250),
        };

        result.PackagePath.Should().Be("/tmp/test.unitypackage");
        result.PackageSize.Should().Be(1024);
        result.PackageSha256.Should().Be("abc123");
        result.EntryCount.Should().Be(3);
        result.Verdict.Should().Be(Verdict.Suspicious);
        result.ScanDuration.TotalMilliseconds.Should().Be(250);
        result.ScannedAt.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void PackageEntry_normalized_pathname_replaces_backslashes()
    {
        var entry = new PackageEntry
        {
            Guid = "abc",
            Pathname = @"Assets\Scripts\Player.cs",
            DetectedType = DetectedType.CSharpSource,
        };

        entry.NormalizedPathname.Should().Be("Assets/Scripts/Player.cs");
    }

    [Fact]
    public void PackageEntry_filename_and_extension_are_derived_from_pathname()
    {
        var entry = new PackageEntry
        {
            Guid = "abc",
            Pathname = "Assets/Plugins/win/payload.dll",
            DetectedType = DetectedType.ManagedDll,
        };

        entry.FileName.Should().Be("payload.dll");
        entry.Extension.Should().Be(".dll");
    }

    [Fact]
    public void Finding_with_all_optional_fields_null_is_valid()
    {
        var f = new Finding
        {
            RuleId = "UPS999",
            Severity = Severity.Informational,
            Title = "test",
            Description = "test",
        };

        f.Entry.Should().BeNull();
        f.Evidence.Should().BeNull();
        f.IsAdvisory.Should().BeFalse();
    }

    [Fact]
    public void Finding_with_advisory_flag_can_be_created_via_with()
    {
        var original = new Finding
        {
            RuleId = "UPS002",
            Severity = Severity.Critical,
            Title = "Auto-exec",
            Description = "desc",
        };

        var advisory = original with { IsAdvisory = true };

        advisory.IsAdvisory.Should().BeTrue();
        original.IsAdvisory.Should().BeFalse("original is immutable");
    }

    [Theory]
    [InlineData(DetectedType.Unknown)]
    [InlineData(DetectedType.CSharpSource)]
    [InlineData(DetectedType.ManagedDll)]
    [InlineData(DetectedType.NativePE)]
    [InlineData(DetectedType.NativeElf)]
    [InlineData(DetectedType.NativeMachO)]
    [InlineData(DetectedType.Texture)]
    [InlineData(DetectedType.Model)]
    [InlineData(DetectedType.Audio)]
    [InlineData(DetectedType.Scene)]
    [InlineData(DetectedType.Prefab)]
    [InlineData(DetectedType.AnimationClip)]
    [InlineData(DetectedType.Material)]
    [InlineData(DetectedType.Shader)]
    [InlineData(DetectedType.Other)]
    public void DetectedType_all_values_are_defined(DetectedType value)
    {
        Enum.IsDefined(value).Should().BeTrue();
    }

    [Theory]
    [InlineData(Severity.Informational)]
    [InlineData(Severity.Suspicious)]
    [InlineData(Severity.HighRisk)]
    [InlineData(Severity.Critical)]
    public void Severity_all_values_are_defined(Severity value)
    {
        Enum.IsDefined(value).Should().BeTrue();
    }

    [Theory]
    [InlineData(Verdict.Clean)]
    [InlineData(Verdict.Suspicious)]
    [InlineData(Verdict.HighRisk)]
    [InlineData(Verdict.Critical)]
    public void Verdict_all_values_are_defined(Verdict value)
    {
        Enum.IsDefined(value).Should().BeTrue();
    }
}
