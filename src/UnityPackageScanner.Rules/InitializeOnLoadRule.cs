using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects editor scripts that auto-execute on package import via Unity's InitializeOnLoad
/// mechanism, or through AssetPostprocessor / AssetModificationProcessor subclasses.
/// </summary>
public sealed partial class InitializeOnLoadRule(ILogger<InitializeOnLoadRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.AutoExecuteEditor;
    public string Title => "Auto-executing editor code";
    public Severity DefaultSeverity => Severity.Critical;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects C# source files and compiled assemblies that use Unity's " +
        "[InitializeOnLoad] or [InitializeOnLoadMethod] attributes, or that subclass " +
        "AssetPostprocessor or AssetModificationProcessor. Code marked with these " +
        "mechanisms runs automatically the moment a package is imported — before the " +
        "developer has had a chance to inspect it.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Legitimate editor tooling (e.g. asset store packages with setup wizards) commonly uses [InitializeOnLoad]. " +
        "Look at what the static constructor actually does before concluding it is malicious.",
        "Test-only packages that configure test runners on import.",
    ];

    // Matches [InitializeOnLoad] and [InitializeOnLoadMethod] with optional namespace prefix
    [GeneratedRegex(@"\[\s*(?:\w+\.)*InitializeOnLoad(Method)?\s*(?:\(.*?\))?\s*\]", RegexOptions.Compiled)]
    private static partial Regex InitAttrRegex();

    // Matches class declarations that extend AssetPostprocessor or AssetModificationProcessor
    [GeneratedRegex(@"\bclass\s+\w+\s*:\s*[\w.]*(?:AssetPostprocessor|AssetModificationProcessor)\b",
        RegexOptions.Compiled)]
    private static partial Regex ProcessorBaseRegex();

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (entry.DetectedType == DetectedType.CSharpSource)
            {
                await foreach (var f in AnalyzeCsSourceAsync(entry, ct))
                    yield return f;
            }
            else if (entry.DetectedType is DetectedType.ManagedDll or DetectedType.NativePE)
            {
                await foreach (var f in AnalyzeManagedDllAsync(entry, ct))
                    yield return f;
            }
        }
    }

    private async IAsyncEnumerable<Finding> AnalyzeCsSourceAsync(
        PackageEntry entry,
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (entry.AssetBytes is null) yield break;

        string source;
        try
        {
            source = Encoding.UTF8.GetString(entry.AssetBytes);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not decode {Path} as UTF-8", entry.Pathname);
            yield break;
        }

        var evidence = new List<string>();

        foreach (Match m in InitAttrRegex().Matches(source))
        {
            int line = GetLineNumber(source, m.Index);
            evidence.Add($"Line {line}: {m.Value.Trim()}");
            logger.LogDebug("{RuleId}: InitializeOnLoad attribute at line {Line} in {Path}", RuleId, line, entry.Pathname);
        }

        foreach (Match m in ProcessorBaseRegex().Matches(source))
        {
            int line = GetLineNumber(source, m.Index);
            evidence.Add($"Line {line}: {m.Value.Trim()}");
            logger.LogDebug("{RuleId}: Processor base class at line {Line} in {Path}", RuleId, line, entry.Pathname);
        }

        if (evidence.Count > 0)
        {
            yield return new Finding
            {
                RuleId = RuleId,
                Severity = DefaultSeverity,
                Title = Title,
                Description = "This script will execute automatically when the package is imported into a Unity project.",
                Entry = entry,
                Evidence = string.Join("\n", evidence),
            };
        }

        await Task.CompletedTask; // satisfy async enumerable requirement
    }

    private async IAsyncEnumerable<Finding> AnalyzeManagedDllAsync(
        PackageEntry entry,
        [EnumeratorCancellation] CancellationToken ct)
    {
        if (entry.AssetBytes is null) yield break;

        ModuleDefinition module;
        try { module = ModuleDefinition.FromBytes(entry.AssetBytes); }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "{RuleId}: {Path} is not a managed DLL — skipping", RuleId, entry.Pathname);
            yield break;
        }

        var evidence = new List<string>();

        foreach (var type in module.GetAllTypes())
        {
            var typeFqn = string.IsNullOrEmpty(type.Namespace?.ToString())
                ? type.Name?.ToString() ?? ""
                : $"{type.Namespace}.{type.Name}";

            // Custom attributes: [InitializeOnLoad] or [InitializeOnLoadMethod] on the type
            foreach (var attr in type.CustomAttributes)
            {
                var attrName = attr.Constructor?.DeclaringType?.Name?.ToString() ?? "";
                if (attrName is "InitializeOnLoadAttribute" or "InitializeOnLoadMethodAttribute")
                    evidence.Add($"[{attrName.Replace("Attribute", "")}] on {typeFqn}");
            }

            // Base class: AssetPostprocessor or AssetModificationProcessor
            var baseTypeName = type.BaseType?.Name?.ToString() ?? "";
            if (baseTypeName is "AssetPostprocessor" or "AssetModificationProcessor")
                evidence.Add($"Inherits {baseTypeName}: {typeFqn}");

            // Methods: [InitializeOnLoadMethod] on individual methods
            foreach (var method in type.Methods)
                foreach (var attr in method.CustomAttributes)
                {
                    var attrName = attr.Constructor?.DeclaringType?.Name ?? "";
                    if (attrName == "InitializeOnLoadMethodAttribute")
                        evidence.Add($"[InitializeOnLoadMethod] on {typeFqn}.{method.Name}");
                }
        }

        if (evidence.Count > 0)
        {
            logger.LogDebug("{RuleId}: DLL {Path} has {Count} auto-execute signal(s)", RuleId, entry.Pathname, evidence.Count);
            yield return new Finding
            {
                RuleId = RuleId,
                Severity = DefaultSeverity,
                Title = Title,
                Description = "This compiled assembly will execute code automatically when imported into Unity.",
                Entry = entry,
                Evidence = string.Join("\n", evidence),
            };
        }

        await Task.CompletedTask;
    }

    private static int GetLineNumber(string text, int charIndex)
    {
        int line = 1;
        for (int i = 0; i < charIndex && i < text.Length; i++)
            if (text[i] == '\n') line++;
        return line;
    }
}
