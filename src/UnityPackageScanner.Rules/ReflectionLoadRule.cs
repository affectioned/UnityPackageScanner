using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects managed DLLs that call Assembly.Load, LoadFrom, LoadFile, or LoadWithPartialName.
/// Dynamic assembly loading is a common second-stage payload technique.
/// </summary>
public sealed class ReflectionLoadRule(ILogger<ReflectionLoadRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.ReflectionLoad;
    public string Title => "Dynamic assembly loading";
    public Severity DefaultSeverity => Severity.HighRisk;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies that call System.Reflection.Assembly.Load, LoadFrom, LoadFile, " +
        "or LoadWithPartialName in their method bodies. These methods load additional .NET assemblies " +
        "at runtime — a technique used by malware to deliver a second-stage payload that is not " +
        "visible to static analysis of the original package.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Plugin frameworks and extensibility systems that load user-provided assemblies by path " +
        "may legitimately call Assembly.LoadFrom. The risk depends entirely on where the path " +
        "comes from — a hardcoded relative path inside the package is more concerning than a " +
        "user-configured path.",
    ];

    private static readonly HashSet<string> LoadMethodNames =
        new(StringComparer.Ordinal) { "Load", "LoadFrom", "LoadFile", "LoadWithPartialName", "LoadModule" };

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

            var hit = FindReflectionLoad(module);
            if (hit is not null)
                yield return MakeFinding(entry, hit);
        }

        await Task.CompletedTask;
    }

    private string? FindReflectionLoad(ModuleDefinition module)
    {
        foreach (var type in module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody is null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.Operand is not MemberReference mr) continue;
                    if (mr.DeclaringType is not TypeReference tr) continue;

                    if (tr.Name == "Assembly"
                        && (tr.Namespace ?? "").Contains("Reflection")
                        && LoadMethodNames.Contains(mr.Name ?? ""))
                    {
                        logger.LogDebug("{RuleId}: found Assembly.{Method}", RuleId, mr.Name);
                        return mr.Name!;
                    }
                }
            }

        return null;
    }

    private Finding MakeFinding(PackageEntry entry, string methodName) => new()
    {
        RuleId = RuleId,
        Severity = DefaultSeverity,
        Title = Title,
        Description =
            $"This managed assembly calls Assembly.{methodName}, which loads an additional .NET assembly " +
            "at runtime. This is a common second-stage payload technique — the initial package looks " +
            "clean, but loads malicious code after import.",
        Entry = entry,
        Evidence = $"System.Reflection.Assembly.{methodName} called in method body",
    };
}
