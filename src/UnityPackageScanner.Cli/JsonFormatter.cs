using System.Text.Json;
using System.Text.Json.Serialization;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Cli;

internal static class JsonFormatter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Format(ScanResult result)
    {
        var dto = new
        {
            packagePath = result.PackagePath,
            packageSha256 = result.PackageSha256,
            packageSize = result.PackageSize,
            entryCount = result.EntryCount,
            scanDurationMs = result.ScanDuration.TotalMilliseconds,
            scannedAt = result.ScannedAt,
            verdict = result.Verdict,
            findings = result.Findings.Select(f => new
            {
                ruleId = f.RuleId,
                severity = f.Severity,
                title = f.Title,
                description = f.Description,
                isAdvisory = f.IsAdvisory ? (bool?)true : null,
                file = f.Entry?.Pathname,
                evidence = f.Evidence,
            }).ToList(),
        };

        return JsonSerializer.Serialize(dto, Options);
    }
}
