using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects managed DLLs that reference System.Diagnostics.Process or ProcessStartInfo.
/// Spawning child processes from a Unity plugin is unusual and potentially dangerous.
/// </summary>
public sealed class ProcessSpawnRule(ILogger<ProcessSpawnRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.ProcessSpawn;
    public string Title => "Suspicious process spawn";
    public Severity DefaultSeverity => Severity.HighRisk;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies that reference System.Diagnostics.Process or ProcessStartInfo " +
        "in their method bodies. A Unity plugin that spawns child processes can execute arbitrary " +
        "system commands, install persistence mechanisms, or launch privilege-escalation exploits.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Build-automation packages that invoke external compilers or code-generation tools may legitimately " +
        "reference Process. Verify that the process name and arguments are restricted to known safe values.",
    ];

    private static readonly HashSet<string> SuspiciousTypeNames =
        new(StringComparer.Ordinal) { "Process", "ProcessStartInfo" };

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

            var hit = FindProcessTypeRef(module);
            if (hit is not null)
                yield return MakeFinding(entry, hit.Value);
        }

        await Task.CompletedTask;
    }

    private (string typeName, string memberName)? FindProcessTypeRef(ModuleDefinition module)
    {
        foreach (var type in module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody is null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.Operand is not MemberReference mr) continue;
                    if (mr.DeclaringType is not TypeReference tr) continue;

                    if ((tr.Namespace?.ToString() ?? "").StartsWith("System.Diagnostics", StringComparison.Ordinal)
                        && SuspiciousTypeNames.Contains(tr.Name ?? ""))
                    {
                        logger.LogDebug("{RuleId}: found {FullName}::{Member}", RuleId, tr.FullName, mr.Name);
                        return (tr.Name!, mr.Name ?? "?");
                    }
                }
            }

        return null;
    }

    private Finding MakeFinding(PackageEntry entry, (string typeName, string memberName) hit) => new()
    {
        RuleId = RuleId,
        Severity = DefaultSeverity,
        Title = Title,
        Description =
            $"This managed assembly references '{hit.typeName}', a process-spawning type. " +
            "A Unity plugin that launches child processes can execute arbitrary system commands " +
            "or install persistence mechanisms.",
        Entry = entry,
        Evidence = $"System.Diagnostics.{hit.typeName}.{hit.memberName} referenced in method body",
    };
}
