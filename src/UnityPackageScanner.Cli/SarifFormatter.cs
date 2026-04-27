using System.Text.Json;
using System.Text.Json.Serialization;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Cli;

internal static class SarifFormatter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Format(ScanResult result)
    {
        var rules = result.Findings
            .Select(f => f.RuleId)
            .Distinct()
            .Select(id =>
            {
                var sample = result.Findings.First(f => f.RuleId == id);
                return new SarifRule(id, sample.Title, ToLevel(sample.Severity));
            })
            .ToList();

        var sarif = new
        {
            version = "2.1.0",
            schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "UnityPackageScanner",
                            informationUri = "https://github.com/abbey/UnityPackageScanner",
                            rules = rules.Select(r => new
                            {
                                id = r.Id,
                                name = ToPascalCase(r.Title),
                                shortDescription = new { text = r.Title },
                                defaultConfiguration = new { level = r.Level },
                            }).ToArray(),
                        },
                    },
                    results = result.Findings.Select(f => BuildResult(f)).ToArray(),
                    artifacts = new[]
                    {
                        new
                        {
                            location = new { uri = Uri.EscapeDataString(result.PackagePath) },
                            hashes = new { sha256 = result.PackageSha256 },
                        },
                    },
                },
            },
        };

        return JsonSerializer.Serialize(sarif, Options);
    }

    private static object BuildResult(Finding f)
    {
        var loc = f.Entry is not null
            ? new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = f.Entry.NormalizedPathname },
                    },
                },
            }
            : null;

        return new
        {
            ruleId = f.RuleId,
            level = ToLevel(f.Severity),
            message = new { text = string.IsNullOrEmpty(f.Evidence) ? f.Description : $"{f.Description} Evidence: {f.Evidence}" },
            locations = loc,
        };
    }

    private static string ToLevel(Severity severity) => severity switch
    {
        Severity.Critical => "error",
        Severity.HighRisk => "error",
        Severity.Suspicious => "warning",
        _ => "note",
    };

    private static string ToPascalCase(string title) =>
        string.Concat(title.Split(' ', '-', '_')
            .Where(w => w.Length > 0)
            .Select(w => char.ToUpperInvariant(w[0]) + w[1..]));

    private sealed record SarifRule(string Id, string Title, string Level);
}
