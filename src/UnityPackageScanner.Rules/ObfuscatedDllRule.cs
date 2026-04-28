using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

public sealed class ObfuscatedDllRule(ILogger<ObfuscatedDllRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.ObfuscatedDll;
    public string Title => "Obfuscated managed assembly";
    public Severity DefaultSeverity => Severity.HighRisk;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies whose metadata shows signs of obfuscation: control characters " +
        "in type or method names, a high ratio of single-character identifiers, or known obfuscator " +
        "marker attributes such as [Obfuscation] or [ConfusedBy]. " +
        "Obfuscation alone is not malicious — commercial packages sometimes protect their IP — " +
        "but obfuscated code from an unknown source is harder to audit and warrants extra scrutiny, " +
        "particularly when combined with network-access or process-spawn findings.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Commercial packages often ship obfuscated assemblies to protect intellectual property. " +
        "If the package is from a known, trusted publisher this finding may be expected.",
        "Unity's own assemblies and some middleware (FMOD, Wwise, Photon) use name mangling internally.",
    ];

    // Score at or above this threshold emits a finding.
    private const int Threshold = 40;

    // Short-name ratio threshold and minimum sample size for the ratio signal.
    private const double ShortNameRatioMin = 0.40;
    private const int ShortNameCountMin = 10;

    private static readonly HashSet<string> KnownObfuscatorMarkers =
        new(StringComparer.Ordinal)
        {
            "ConfusedByAttribute",
            "SmartAssemblyAttribute",
            "DotfuscatorAttribute",
            "BabelObfuscatorAttribute",
        };

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

            var (score, signals) = ComputeScore(module, entry.Pathname);

            logger.LogDebug("{RuleId}: {Path} obfuscation score={Score} signals=[{Signals}]",
                RuleId, entry.Pathname, score, string.Join(", ", signals));

            if (score >= Threshold)
                yield return MakeFinding(entry, signals);
        }

        await Task.CompletedTask;
    }

    private (int score, List<string> signals) ComputeScore(ModuleDefinition module, string pathname)
    {
        var signals = new List<string>();
        int score = 0;
        int totalNames = 0;
        int shortNames = 0;
        bool controlCharReported = false;

        foreach (var type in module.GetAllTypes())
        {
            var typeName = type.Name?.ToString() ?? "";
            if (typeName is "<Module>" or "") continue;

            totalNames++;

            if (!controlCharReported && ContainsControlChar(typeName))
            {
                score += 50;
                signals.Add("Control characters in type or method names");
                controlCharReported = true;
                logger.LogDebug("{RuleId}: control char in type name at {Path}", RuleId, pathname);
            }
            else if (!controlCharReported && typeName.Length <= 2)
            {
                shortNames++;
            }

            CheckObfuscatorAttributes(type.CustomAttributes, signals, ref score);

            foreach (var method in type.Methods)
            {
                var methodName = method.Name?.ToString() ?? "";
                if (methodName is ".ctor" or ".cctor" or "") continue;

                totalNames++;

                if (!controlCharReported && ContainsControlChar(methodName))
                {
                    score += 50;
                    signals.Add("Control characters in type or method names");
                    controlCharReported = true;
                }
                else if (!controlCharReported && methodName.Length <= 2)
                {
                    shortNames++;
                }
            }
        }

        if (module.Assembly is not null)
            CheckObfuscatorAttributes(module.Assembly.CustomAttributes, signals, ref score);

        if (totalNames >= ShortNameCountMin && shortNames > 0)
        {
            double ratio = (double)shortNames / totalNames;
            if (ratio >= ShortNameRatioMin)
            {
                score += 30;
                signals.Add($"{shortNames}/{totalNames} identifiers are ≤2 chars long ({ratio:P0})");
            }
        }

        return (score, signals);
    }

    private static void CheckObfuscatorAttributes(
        IList<CustomAttribute> attrs, List<string> signals, ref int score)
    {
        foreach (var attr in attrs)
        {
            var name = attr.Constructor?.DeclaringType?.Name?.ToString() ?? "";

            if (KnownObfuscatorMarkers.Contains(name))
            {
                score += 70;
                signals.Add($"Known obfuscator attribute: [{name.Replace("Attribute", "")}]");
            }
            else if (name == "ObfuscationAttribute")
            {
                score += 25;
                signals.Add("[System.Reflection.Obfuscation] attribute");
            }
        }
    }

    private static bool ContainsControlChar(string s)
    {
        foreach (var c in s)
            if (c < 0x20 || (c >= 0x7F && c <= 0x9F))
                return true;
        return false;
    }

    private Finding MakeFinding(PackageEntry entry, List<string> signals) => new()
    {
        RuleId = RuleId,
        Severity = DefaultSeverity,
        Title = Title,
        Description =
            "This managed assembly shows signs of obfuscation. Obfuscated packages are harder to " +
            "audit and may be concealing malicious behavior. Treat other findings on this assembly " +
            "as advisory — static analysis is less reliable on obfuscated code.",
        Entry = entry,
        Evidence = string.Join("; ", signals),
    };
}
