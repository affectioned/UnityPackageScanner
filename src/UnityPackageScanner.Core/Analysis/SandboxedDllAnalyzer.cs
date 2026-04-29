using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Core.Analysis;

/// <summary>
/// Runs AsmResolver-based detection rules in an isolated child process (ups-dll-worker).
/// Each DLL/native entry is sent as a JSON request over stdin; findings come back as JSON
/// over stdout. A crash or exploit in AsmResolver is confined to the worker process.
/// </summary>
public sealed class SandboxedDllAnalyzer
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // Encoding.UTF8 has a BOM preamble; pipes must not start with a BOM.
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private static readonly TimeSpan EntryTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    private readonly ILogger<SandboxedDllAnalyzer> _logger;
    private readonly string? _workerPath;

    public SandboxedDllAnalyzer(ILogger<SandboxedDllAnalyzer> logger, string? workerPath = null)
    {
        _logger = logger;
        _workerPath = workerPath;
    }

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> dllEntries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (dllEntries.Count == 0) yield break;

        var (workerFile, workerArgs) = FindWorker();
        _logger.LogDebug("DllWorker: spawning '{Worker}' for {Count} entr(ies)", workerFile, dllEntries.Count);

        var psi = new ProcessStartInfo(workerFile, workerArgs)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = Utf8NoBom,
            StandardOutputEncoding = Utf8NoBom,
            StandardErrorEncoding = Utf8NoBom,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null for ups-dll-worker.");

        process.StandardInput.AutoFlush = true;

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
                _logger.LogWarning("ups-dll-worker: {Line}", e.Data);
        };
        process.BeginErrorReadLine();

        foreach (var entry in dllEntries)
        {
            ct.ThrowIfCancellationRequested();

            var req = new WorkerRequest(
                entry.Guid,
                entry.Pathname,
                entry.AssetBytes is not null ? Convert.ToBase64String(entry.AssetBytes) : null,
                entry.DetectedType.ToString(),
                entry.Size);

            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(req, JsonOpts));

            using var entryCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            entryCts.CancelAfter(EntryTimeout);

            string? line;
            try
            {
                line = await process.StandardOutput.ReadLineAsync(entryCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("DllWorker timed out analysing '{Path}' — killing worker", entry.Pathname);
                process.Kill();
                yield break;
            }

            if (line is null)
            {
                _logger.LogWarning("DllWorker closed stdout unexpectedly after '{Path}'", entry.Pathname);
                yield break;
            }

            WorkerResponse? response;
            try { response = JsonSerializer.Deserialize<WorkerResponse>(line, JsonOpts); }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "DllWorker returned malformed JSON for '{Path}'", entry.Pathname);
                continue;
            }

            if (response is null) continue;

            foreach (var wf in response.Findings)
            {
                if (!Enum.TryParse<Severity>(wf.Severity, out var severity))
                {
                    _logger.LogWarning("DllWorker returned unknown severity '{Sev}' from rule {RuleId}", wf.Severity, wf.RuleId);
                    continue;
                }

                yield return new Finding
                {
                    RuleId = wf.RuleId,
                    Severity = severity,
                    Title = wf.Title,
                    Description = wf.Description,
                    Evidence = wf.Evidence,
                    IsAdvisory = wf.IsAdvisory,
                    Entry = entry,
                };
            }
        }

        process.StandardInput.Close();

        using var exitCts = new CancellationTokenSource(ShutdownTimeout);
        try { await process.WaitForExitAsync(exitCts.Token); }
        catch (OperationCanceledException) { process.Kill(); }

        _logger.LogDebug("DllWorker exited with code {Code}", process.ExitCode);
    }

    private (string fileName, string arguments) FindWorker()
    {
        if (_workerPath is not null)
        {
            if (File.Exists(_workerPath)) return (_workerPath, "");
            throw new FileNotFoundException("ups-dll-worker not found at specified path.", _workerPath);
        }

        var dir = AppContext.BaseDirectory;

        // Self-contained publish: standalone native executable
        var exe = Path.Combine(dir, OperatingSystem.IsWindows() ? "ups-dll-worker.exe" : "ups-dll-worker");
        if (File.Exists(exe)) return (exe, "");

        // Framework-dependent: run via dotnet
        var dll = Path.Combine(dir, "ups-dll-worker.dll");
        if (File.Exists(dll)) return ("dotnet", $"\"{dll}\"");

        throw new FileNotFoundException(
            $"ups-dll-worker not found in '{dir}'. Ensure it is built or published alongside the scanner.",
            exe);
    }

    // ── Wire-protocol DTOs (private to this class) ──────────────────────────
    private record WorkerRequest(string Id, string Pathname, string? AssetBytes, string DetectedType, long Size);
    private record WorkerResponse(string Id, List<WorkerFinding> Findings);
    private record WorkerFinding(string RuleId, string Severity, string Title, string Description, string? Evidence, bool IsAdvisory);
}
