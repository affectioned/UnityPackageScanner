using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
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
        "in type or method names, a high ratio of single-character identifiers, known obfuscator " +
        "marker attributes such as [Obfuscation] or [ConfusedBy], or string literals whose " +
        "character-distribution entropy indicates encrypted or randomly-generated content. " +
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

        CheckObfuscatedStringLiterals(module, pathname, signals, ref score);

        return (score, signals);
    }

    private void CheckObfuscatedStringLiterals(
        ModuleDefinition module, string pathname,
        List<string> signals, ref int score)
    {
        int suspicious = 0;
        int total = 0;

        foreach (var type in module.GetAllTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody is null) continue;

                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.OpCode != CilOpCodes.Ldstr) continue;
                    if (instr.Operand is not string s) continue;
                    if (s.Length < 6) continue;

                    total++;
                    if (IsObfuscatedLiteral(s))
                        suspicious++;
                }
            }
        }

        if (suspicious < 3) return;

        logger.LogDebug("{RuleId}: {Suspicious}/{Total} suspicious string literals in {Path}",
            RuleId, suspicious, total, pathname);

        // Score scales with count: 5 strings alone crosses the 40-point threshold.
        score += Math.Min(suspicious * 8, 50);
        signals.Add($"{suspicious} string literal(s) with high-entropy or non-printable character content");
    }

    private static bool IsObfuscatedLiteral(string s)
    {
        // Non-printable control characters (excluding tab / LF / CR) are a strong signal —
        // obfuscators store encrypted bytes directly in string operands.
        int controlCount = 0;
        foreach (char c in s)
            if (c < 0x20 && c is not '\t' and not '\n' and not '\r') controlCount++;
        if ((double)controlCount / s.Length > 0.15)
            return true;

        // For printable strings, skip obvious false-positive categories before running entropy.
        if (s.Length < 16) return false;
        if (s.Contains("://", StringComparison.Ordinal)) return false; // URL
        if (s.Contains('\\') || s.Contains('/')) return false;         // path
        if (s.Contains(' ')) return false;                              // human-readable text
        if (IsAllHex(s)) return false;                                  // SHA/MD5 hash
        if (IsGuidLike(s)) return false;

        return ComputeCharEntropy(s) > 4.5;
    }

    // Shannon entropy over the character distribution of a string (bits per character).
    // English code identifiers typically score 3.5–4.0; truly random strings score 4.5+.
    private static double ComputeCharEntropy(string s)
    {
        var freq = new Dictionary<char, int>(s.Length);
        foreach (char c in s)
            freq[c] = freq.GetValueOrDefault(c) + 1;

        double entropy = 0;
        double len = s.Length;
        foreach (var count in freq.Values)
        {
            double p = count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static bool IsAllHex(string s)
    {
        foreach (char c in s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        return s.Length > 0;
    }

    private static bool IsGuidLike(string s) =>
        s.Length == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-';

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
