using System.Runtime.CompilerServices;
using AsmResolver.PE;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects native (unmanaged) binaries: PE files without a CLR header, ELF binaries, and Mach-O binaries.
/// Unity loads native plugins from the Plugins/ folder on startup — they execute outside the CLR
/// and cannot be inspected by this tool's managed-code analysis.
/// </summary>
public sealed class NativePluginRule(ILogger<NativePluginRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.NativePlugin;
    public string Title => "Native plugin detected";
    public Severity DefaultSeverity => Severity.Critical;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects native (unmanaged) binaries: PE files without a CLR header, ELF binaries, " +
        "and Mach-O binaries. Unity loads these from the Plugins/ folder at startup. Because " +
        "native code runs outside the CLR, this tool cannot statically analyze what it does — " +
        "treat any native plugin from an untrusted source with the same caution as an obfuscated " +
        "managed DLL. Detection is based on file magic bytes, so renaming a .dll to .asset " +
        "does not evade this rule.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Legitimate packages that wrap platform-specific native functionality (physics engines, " +
        "audio SDKs, rendering middleware) always contain native plugins. Check the publisher " +
        "and whether the plugin is signed before concluding it is malicious.",
        "Pre-compiled Burst-compiled assemblies (.bc, Burst-native .dll wrappers) may appear as native.",
    ];

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (entry.DetectedType == DetectedType.NativeElf)
            {
                yield return MakeFinding(entry, "ELF binary (Linux native code)", "ELF magic bytes (0x7F 45 4C 46)");
            }
            else if (entry.DetectedType == DetectedType.NativeMachO)
            {
                yield return MakeFinding(entry, "Mach-O binary (macOS/iOS native code)", "Mach-O magic bytes");
            }
            else if (entry.DetectedType == DetectedType.NativePE && entry.AssetBytes is not null)
            {
                // PE header found — check whether it has a CLR directory (managed) or not (native).
                if (IsNativePe(entry.AssetBytes))
                {
                    yield return MakeFinding(entry, "Native PE binary (Windows native code)",
                        "MZ/PE magic bytes, no CLR metadata directory");
                }
                else
                {
                    logger.LogDebug("{RuleId}: {Path} has CLR directory — managed assembly, skipping",
                        RuleId, entry.Pathname);
                }
            }
        }

        await Task.CompletedTask;
    }

    private Finding MakeFinding(PackageEntry entry, string typeDesc, string evidence) => new()
    {
        RuleId = RuleId,
        Severity = DefaultSeverity,
        Title = Title,
        Description =
            $"A {typeDesc} was found at '{entry.Pathname}'. Native code is opaque to static analysis. " +
            "This tool cannot determine what it does. Require explicit review before importing.",
        Entry = entry,
        Evidence = evidence,
    };

    private bool IsNativePe(byte[] bytes)
    {
        try
        {
            var image = PEImage.FromBytes(bytes);
            var isNative = image.DotNetDirectory is null;
            logger.LogDebug("{RuleId}: PE at parsed, DotNetDirectory={HasClr}",
                RuleId, image.DotNetDirectory is not null);
            return isNative;
        }
        catch (Exception ex)
        {
            // Cannot parse as valid PE — treat as native (conservative/safe default).
            logger.LogDebug(ex, "{RuleId}: Could not parse PE image — assuming native", RuleId);
            return true;
        }
    }
}
