using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects managed DLLs that declare P/Invoke methods (DllImport) or call NativeLibrary.Load.
/// Managed code calling arbitrary native code bypasses CLR security and is a common attack vector.
/// </summary>
public sealed class SuspiciousPInvokeRule(ILogger<SuspiciousPInvokeRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.SuspiciousPInvoke;
    public string Title => "Suspicious P/Invoke";
    public Severity DefaultSeverity => Severity.HighRisk;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies that declare Platform Invoke (P/Invoke) methods via [DllImport] " +
        "or load native libraries at runtime via NativeLibrary.Load. P/Invoke gives managed code " +
        "unrestricted access to native system APIs, bypassing the CLR's security model. Combined " +
        "with obfuscation, this is a common pattern for hiding malicious functionality.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Native interop wrappers (physics engines, audio SDKs, platform-specific APIs) legitimately " +
        "use P/Invoke. The concern is the combination of P/Invoke with obfuscation or unusual " +
        "target DLL names (random, temp-path, or OS internals like ntdll.dll/kernel32.dll).",
        "Unity's own Editor assemblies use P/Invoke extensively — this rule fires on user-supplied " +
        "packages only.",
    ];

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (entry.DetectedType is not (DetectedType.ManagedDll or DetectedType.NativePE)) continue;
            if (entry.AssetBytes is null) continue;

            ModuleDefinition module;
            try { module = ModuleDefinition.FromBytes(entry.AssetBytes); }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "{RuleId}: {Path} is not a managed DLL — skipping", RuleId, entry.Pathname);
                continue;
            }

            var finding = FindPInvoke(module, entry);
            if (finding is not null)
                yield return finding;
        }

        await Task.CompletedTask;
    }

    private Finding? FindPInvoke(ModuleDefinition module, PackageEntry entry)
    {
        // Check for P/Invoke declarations (ImplementationMap present)
        foreach (var type in module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                if (method.ImplementationMap is { } implMap)
                {
                    var dllName = implMap.Scope?.Name?.ToString() ?? "?";
                    logger.LogDebug("{RuleId}: P/Invoke {Method} -> {Dll}", RuleId, method.Name, dllName);

                    return new Finding
                    {
                        RuleId = RuleId,
                        Severity = DefaultSeverity,
                        Title = Title,
                        Description =
                            $"This managed assembly declares a P/Invoke entry point targeting '{dllName}'. " +
                            "P/Invoke gives managed code unrestricted access to native OS APIs, " +
                            "bypassing CLR security. Review the target DLL and entry-point names carefully.",
                        Entry = entry,
                        Evidence = $"[DllImport(\"{dllName}\")] {method.Name}",
                    };
                }
            }

        // Check for NativeLibrary.Load calls
        foreach (var type in module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody is null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.Operand is not MemberReference mr) continue;
                    if (mr.DeclaringType is not TypeReference tr) continue;

                    if (tr.Name == "NativeLibrary"
                        && (tr.Namespace ?? "").Contains("InteropServices")
                        && (mr.Name?.ToString() is "Load" or "TryLoad"))
                    {
                        logger.LogDebug("{RuleId}: NativeLibrary.{Method} in {MethodOwner}",
                            RuleId, mr.Name, method.FullName);

                        return new Finding
                        {
                            RuleId = RuleId,
                            Severity = DefaultSeverity,
                            Title = Title,
                            Description =
                                $"This managed assembly calls NativeLibrary.{mr.Name}, which loads a native " +
                                "library at runtime. Unlike [DllImport], the target library path can be " +
                                "computed dynamically, making it harder to review statically.",
                            Entry = entry,
                            Evidence = $"NativeLibrary.{mr.Name} called in method body",
                        };
                    }
                }
            }

        return null;
    }
}
