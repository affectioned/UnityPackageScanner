using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects managed assemblies that contain high-entropy embedded resources — a common technique
/// used by ConfuserEx, Babel, and similar tools to hide encrypted payloads that are decrypted
/// and loaded at runtime.
/// </summary>
public sealed class EmbeddedEncryptedResourceRule(ILogger<EmbeddedEncryptedResourceRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.EmbeddedEncryptedResource;
    public string Title => "Possibly encrypted embedded resource";
    public Severity DefaultSeverity => Severity.Suspicious;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies that contain embedded resources with a Shannon entropy above " +
        $"{EntropyThreshold:F1} bits/byte. High entropy indicates the data is either encrypted or " +
        "heavily compressed. ConfuserEx and similar packers store the real assembly code as an " +
        "encrypted embedded resource and decrypt it in a static constructor, effectively hiding the " +
        "true behavior from static analysis tools. Resources with entropy this high are rarely " +
        "produced by normal .NET tooling.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Assemblies that embed compressed texture atlases, audio clips, or other binary assets as " +
        "embedded resources can produce high-entropy readings. Check the resource name — names like " +
        "'.resources', '.resx', or image/audio extensions are more likely to be legitimate.",
        "Third-party SDKs that embed a compressed version of their own dependencies (e.g., Costura.Fody) " +
        "also produce high-entropy embedded resources as a normal part of their packaging.",
    ];

    private const double EntropyThreshold = 7.5;
    private const int MinResourceBytes = 512;

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

            foreach (var finding in InspectResources(module, entry))
                yield return finding;
        }

        await Task.CompletedTask;
    }

    private IEnumerable<Finding> InspectResources(ModuleDefinition module, PackageEntry entry)
    {
        foreach (var resource in module.Resources)
        {
            if (!resource.IsEmbedded) continue;

            byte[]? data;
            try { data = resource.GetData(); }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "{RuleId}: could not read embedded resource in {Path}", RuleId, entry.Pathname);
                continue;
            }

            if (data is null || data.Length < MinResourceBytes) continue;

            var entropy = ComputeEntropy(data);
            var resourceName = resource.Name?.ToString() ?? "<unnamed>";

            logger.LogDebug("{RuleId}: {Path} resource '{Name}' size={Size} entropy={Entropy:F2}",
                RuleId, entry.Pathname, resourceName, data.Length, entropy);

            if (entropy >= EntropyThreshold)
            {
                yield return new Finding
                {
                    RuleId = RuleId,
                    Severity = DefaultSeverity,
                    Title = Title,
                    Description =
                        $"Embedded resource '{resourceName}' has a Shannon entropy of {entropy:F2} bits/byte " +
                        $"across {data.Length:N0} bytes. Entropy this high is unusual for normal " +
                        ".NET resources and may indicate an encrypted payload stored for runtime decryption.",
                    Entry = entry,
                    Evidence = $"Resource '{resourceName}': {data.Length:N0} bytes, entropy {entropy:F2}/8.00",
                };
            }
        }
    }

    private static double ComputeEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var freq = new int[256];
        foreach (var b in data)
            freq[b]++;

        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
