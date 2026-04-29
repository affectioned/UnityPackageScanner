# Unity Package Scanner — Agent Guide

Static analysis tool for `.unitypackage` files. Detects malicious content (auto-executing editor scripts, obfuscated DLLs, native plugins, path traversal) before import into Unity.

## Directory layout

```
src/
  UnityPackageScanner.Core/        # Extraction, package model, analysis pipeline
  UnityPackageScanner.Rules/       # IDetectionRule implementations
  UnityPackageScanner.DllWorker/   # Out-of-process worker that runs AsmResolver rules
  UnityPackageScanner.Cli/         # CLI frontend (System.CommandLine + Spectre.Console)
  UnityPackageScanner.UI/          # Avalonia 11 GUI frontend
tests/
  UnityPackageScanner.Tests/       # xUnit tests; Fixtures/ subfolder contains package builders
tools/
  RulesDocGenerator/               # Generates docs/rules.md from rule metadata
docs/
  cli.md                           # CLI reference
  rules.md                         # Rule catalog (auto-generated — do not edit manually)
```

**Structural rule:** `Cli` and `UI` are siblings. Neither references the other. Anything both frontends need goes in `Core`. This is the guarantee that the engine stays UI-agnostic.

## Sandbox architecture

Rules that call AsmResolver (managed DLL analysis) run in an isolated child process (`ups-dll-worker`) via `SandboxedDllAnalyzer`. A crash or exploit in AsmResolver is contained to the worker.

**Protocol:** newline-delimited JSON over stdin/stdout. `SandboxedDllAnalyzer` sends one `WorkerRequest` per DLL entry; the worker sends back one `WorkerResponse` per request. stderr from the worker is logged as warnings.

**Routing in `ScanPipeline`:**
- `SandboxedTypes` — the set of `DetectedType` values whose entries go to the sandbox (ManagedDll, NativePE, NativeElf, NativeMachO).
- `AsmResolverRuleIds` — the set of rule IDs that must *not* receive DLL/native entries in-process when the sandbox is active. Update this set when adding a new AsmResolver rule.

**Worker registration:** AsmResolver rules are instantiated directly in `src/UnityPackageScanner.DllWorker/Program.cs`. When adding an AsmResolver rule, add it in both `Program.cs` (worker) and `AsmResolverRuleIds` (pipeline routing).

**Critical encoding rule:** Always use `new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)` for pipe I/O (`ProcessStartInfo` encoding properties, `Console.InputEncoding`/`OutputEncoding` in the worker). `Encoding.UTF8` emits a UTF-8 BOM preamble that causes the JSON deserializer on the other end to fail silently.

**Worker publish:** The CLI and UI `.csproj` files have `PublishDllWorker` / `CopyDllWorkerPublished` MSBuild targets that automatically build and copy the worker when publishing with a RID. Dev builds rely on `FindWorker()` finding `ups-dll-worker.dll` alongside the host and invoking it via `dotnet "ups-dll-worker.dll"`.

**Version forwarding:** Both `BuildDllWorker` and `PublishDllWorker` Exec commands pass `-p:Version=$(Version)`. DllWorker depends on Core+Rules, so its Exec build rebuilds those assemblies. Without the version flag the worker's build produces Core at the default version (0.1.0) while the parent exe was compiled against Core at the release version, causing `FileNotFoundException` at startup when the single-file bundle loads the mismatched assembly.

## Adding a detection rule

1. Create `src/UnityPackageScanner.Rules/YourRule.cs`.
2. Implement `IDetectionRule` from `UnityPackageScanner.Core.Analysis`.
3. Add a `RuleId` constant to `KnownRuleIds.cs`.
4. Wire the rule into `ServiceLocator.cs` (UI) and `Program.cs` (CLI).
5. **If the rule calls AsmResolver:** also add it to `DllWorker/Program.cs` and to `ScanPipeline.AsmResolverRuleIds`.
6. Write at least one positive test and one negative test using `UnityPackageBuilder` from `tests/UnityPackageScanner.Tests/Fixtures/`.
7. Fill in `LongDescription` and `FalsePositivePatterns` — these appear in `docs/rules.md`.
8. Run `dotnet run --project tools/RulesDocGenerator` to regenerate `docs/rules.md`.

A rule without positive AND negative tests is not done. A rule without documentation is not done.

## Testing

```bash
dotnet test                                      # Run all tests
dotnet test --filter "AlphaHijackFolder"         # Run tests whose name contains a substring
dotnet test --collect:"XPlat Code Coverage"      # With coverage
```

Coverage gate: ≥85% overall line coverage across all assemblies (Core, Rules, CLI). Enforced in CI via ReportGenerator + `coverlet.runsettings`. Excluded from measurement: `Program.cs` (top-level statements, no class to decorate) and `SpectreConsoleSink` (wraps live stderr — not unit-testable). Do not add new untested code to other classes without corresponding tests.

CI `run:` steps use `shell: bash` via a job-level default — this applies on both `windows-latest` and `ubuntu-latest`. Do not use PowerShell-specific syntax (backtick continuations, `$env:`, etc.) in workflow files.

## Build commands

```bash
# Build the whole solution
dotnet build

# Publish CLI for current platform
dotnet publish src/UnityPackageScanner.Cli -c Release -r win-x64 -p:PublishSingleFile=true --self-contained

# Publish GUI for current platform
dotnet publish src/UnityPackageScanner.UI -c Release -r win-x64 -p:PublishSingleFile=true --self-contained

# Regenerate docs/rules.md
dotnet run --project tools/RulesDocGenerator
```

## Minimalism rules

- No animations, transitions, gradients, or custom-drawn chrome in the UI.
- No speculative abstraction — interfaces exist where they enable testing or platform isolation, not "we might swap this out."
- No new NuGet package without justification in the PR description.
- Under ~100 lines of XAML per view. If a view exceeds that, factor a `UserControl`.
- Color palette is defined once in `App.axaml` as eight named resources. Never hardcode hex in a view.

## Forbidden patterns (with reasons)

- **No `Console.WriteLine`** — use `ILogger<T>`. `Console.WriteLine` bypasses the rolling file sink.
- **No hardcoded path separators** — always `Path.Combine`. Slashes differ between Windows and Linux.
- **No exception swallowing** — catch, log with context, then rethrow or convert to a `Finding`. Silent catches hide bugs.
- **No P/Invoke in `Core` or `Rules`** — these projects must be pure .NET and cross-platform.
- **No `.Result` or `.Wait()`** — async/await end-to-end. Blocking in async code deadlocks under Avalonia's dispatcher.
- **No content-bearing log statements** — log pathnames, sizes, and hashes freely, but never raw file bytes, decoded resources, or decompiled string literals. Users paste logs into Discord; the package being analyzed might contain private work.
- **No telemetry, crash reporting, or remote logging** — logs live on the user's machine, period.

## Code style

- Nullable reference types on, warnings as errors.
- `record`s for immutable data (`PackageEntry`, `Finding`, `ScanResult`).
- Async/await end-to-end, `IAsyncEnumerable<T>` for streaming findings.
- File-scoped namespaces.
- Default is no comments. Write one only when the WHY is non-obvious.

## Logging

Both frontends use `Microsoft.Extensions.Logging` via Serilog. The file sink (rolling daily, 7 days retained) writes to a `logs/` directory next to the executable (`AppContext.BaseDirectory/logs/`). This is cross-platform and requires no per-OS path logic.

The CLI frontend additionally writes to stderr via `SpectreConsoleSink`.

Log at `Debug` level for heuristic decisions (especially obfuscation scoring). Users can flip verbose mode to see why a rule fired without rebuilding the app.

## Docs update rule

Every behavior change ships with a doc update in the same PR. `docs/rules.md` is auto-generated and must not be edited manually. `docs/cli.md` is hand-written and must stay current with the actual CLI flags.
