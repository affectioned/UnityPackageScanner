using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Tests.Analysis;

public sealed class SandboxedDllAnalyzerTests
{
    // ── Unit tests (no worker process) ──────────────────────────────────────

    [Fact]
    public async Task Returns_empty_when_entry_list_is_empty()
    {
        var analyzer = new SandboxedDllAnalyzer(NullLogger<SandboxedDllAnalyzer>.Instance);
        var findings = new List<Finding>();

        await foreach (var f in analyzer.AnalyzeAsync([]))
            findings.Add(f);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task Throws_FileNotFoundException_when_worker_path_does_not_exist()
    {
        var analyzer = new SandboxedDllAnalyzer(
            NullLogger<SandboxedDllAnalyzer>.Instance,
            workerPath: "/nonexistent/ups-dll-worker");

        var entry = new PackageEntry
        {
            Guid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
            Pathname = "Assets/Plugins/fake.dll",
            DetectedType = DetectedType.ManagedDll,
            Size = 0,
        };

        var act = async () =>
        {
            await foreach (var _ in analyzer.AnalyzeAsync([entry])) { }
        };

        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    // ── Integration test (requires ups-dll-worker in AppContext.BaseDirectory) ──

    [Fact]
    public async Task Worker_handles_managed_dll_without_findings()
    {
        // Uses the worker DLL copied to the test output directory by the CopyDllWorker MSBuild target.
        // This test is skipped automatically if the worker is absent (e.g., isolated unit-test runs).
        var workerDll = Path.Combine(AppContext.BaseDirectory, "ups-dll-worker.dll");
        if (!File.Exists(workerDll))
            return; // worker not present — skip rather than fail

        // Use this test assembly as a benign managed DLL input.
        var thisDll = typeof(SandboxedDllAnalyzerTests).Assembly.Location;
        var bytes = await File.ReadAllBytesAsync(thisDll);

        var entry = new PackageEntry
        {
            Guid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00",
            Pathname = "Assets/Plugins/benign.dll",
            DetectedType = DetectedType.ManagedDll,
            Size = bytes.Length,
            AssetBytes = bytes,
        };

        var analyzer = new SandboxedDllAnalyzer(NullLogger<SandboxedDllAnalyzer>.Instance);
        var findings = new List<Finding>();

        await foreach (var f in analyzer.AnalyzeAsync([entry]))
            findings.Add(f);

        // The test assembly has no Unity-specific attributes, native P/Invoke, etc.
        // Assert we complete without error; we don't mandate zero findings (the assembly
        // might trip an obfuscation heuristic due to test-generated names).
        // Note: every finding must have Entry set and reference the correct entry.
        foreach (var f in findings)
        {
            f.Entry.Should().NotBeNull(because: "worker must re-attach the original entry to each finding");
            f.Entry!.Guid.Should().Be(entry.Guid);
        }
    }

    [Fact]
    public async Task Worker_returns_findings_with_original_entry_reference()
    {
        var workerDll = Path.Combine(AppContext.BaseDirectory, "ups-dll-worker.dll");
        if (!File.Exists(workerDll)) return;

        // Build a minimal PE that triggers NativePluginRule (NativeElf magic bytes — no AsmResolver call needed).
        byte[] elfMagic = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        var entry = new PackageEntry
        {
            Guid = "cccccccccccccccccccccccccccccccc00",
            Pathname = "Assets/Plugins/libfoo.so",
            DetectedType = DetectedType.NativeElf,
            Size = elfMagic.Length,
            AssetBytes = elfMagic,
        };

        var analyzer = new SandboxedDllAnalyzer(NullLogger<SandboxedDllAnalyzer>.Instance);
        var findings = new List<Finding>();

        await foreach (var f in analyzer.AnalyzeAsync([entry]))
            findings.Add(f);

        findings.Should().ContainSingle(f => f.RuleId == "UPS003",
            because: "NativePluginRule should fire on an ELF entry");
        findings.Single().Entry.Should().BeSameAs(entry,
            because: "the analyzer must re-attach the original entry, not a copy");
    }
}
