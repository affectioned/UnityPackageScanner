using System.Runtime.CompilerServices;
using AsmResolver.DotNet;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects managed DLLs that reference network types: HttpClient, WebClient, and raw Sockets.
/// Unity plugins rarely need direct network access; when present it warrants investigation.
/// </summary>
public sealed class NetworkAccessRule(ILogger<NetworkAccessRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.NetworkAccess;
    public string Title => "Suspicious network access";
    public Severity DefaultSeverity => Severity.HighRisk;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects managed assemblies that reference networking types such as System.Net.Http.HttpClient, " +
        "System.Net.WebClient, or System.Net.Sockets.Socket in their method bodies. " +
        "Unity plugins that make outbound network calls can exfiltrate data or download " +
        "additional payloads after import. Detection is based on method-body metadata — " +
        "only direct type references are flagged, not calls via reflection.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Analytics SDKs, crash reporters, and multiplayer packages legitimately use HttpClient. " +
        "Check whether the publisher is known and whether the network call targets a documented endpoint.",
        "Editor tools that fetch Unity version or package update info may also use HttpClient.",
    ];

    private static readonly HashSet<string> SuspiciousTypeNames =
        new(StringComparer.Ordinal) { "HttpClient", "WebClient", "Socket", "TcpClient", "UdpClient" };

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

            var hit = FindNetworkTypeRef(module);
            if (hit is not null)
                yield return MakeFinding(entry, hit.Value);
        }

        await Task.CompletedTask;
    }

    private (string typeName, string memberName)? FindNetworkTypeRef(ModuleDefinition module)
    {
        foreach (var type in module.GetAllTypes())
            foreach (var method in type.Methods)
            {
                if (method.CilMethodBody is null) continue;
                foreach (var instr in method.CilMethodBody.Instructions)
                {
                    if (instr.Operand is not MemberReference mr) continue;
                    if (mr.DeclaringType is not TypeReference tr) continue;

                    if (SuspiciousTypeNames.Contains(tr.Name ?? ""))
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
            $"This managed assembly references '{hit.typeName}', a network-access type. " +
            "A Unity plugin that makes outbound network calls could exfiltrate project data or " +
            "download additional malicious payloads after import.",
        Entry = entry,
        Evidence = $"{hit.typeName}.{hit.memberName} referenced in method body",
    };
}
