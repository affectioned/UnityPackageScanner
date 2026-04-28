using System.Text;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Cli;

internal static class MarkdownFormatter
{
    public static string Format(ScanResult result)
    {
        var sb = new StringBuilder();

        var verdictLabel = result.Verdict switch
        {
            Verdict.Clean => "CLEAN",
            Verdict.Suspicious => "SUSPICIOUS",
            Verdict.HighRisk => "HIGH RISK",
            Verdict.Critical => "CRITICAL",
            _ => result.Verdict.ToString().ToUpperInvariant(),
        };

        sb.AppendLine($"# Scan Result: {verdictLabel}");
        sb.AppendLine();
        sb.AppendLine("| Field | Value |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| Package | `{result.PackagePath}` |");
        sb.AppendLine($"| SHA-256 | `{result.PackageSha256}` |");
        sb.AppendLine($"| Entries | {result.EntryCount} |");
        sb.AppendLine($"| Duration | {result.ScanDuration.TotalMilliseconds:F0}ms |");
        sb.AppendLine();

        if (result.Findings.Count == 0)
        {
            sb.AppendLine("No findings.");
            return sb.ToString();
        }

        sb.AppendLine("## Findings");
        sb.AppendLine();

        var grouped = result.Findings
            .GroupBy(f => f.Severity)
            .OrderByDescending(g => g.Key);

        foreach (var group in grouped)
        {
            var label = group.Key switch
            {
                Severity.Critical => "CRITICAL",
                Severity.HighRisk => "HIGH RISK",
                Severity.Suspicious => "SUSPICIOUS",
                _ => "INFO",
            };

            sb.AppendLine($"### {label}");
            sb.AppendLine();

            foreach (var finding in group)
            {
                sb.AppendLine($"#### {finding.Title}");
                sb.AppendLine();
                sb.AppendLine("| Field | Value |");
                sb.AppendLine("|---|---|");
                if (finding.IsAdvisory)
                    sb.AppendLine("| Note | Advisory — DLL could not be reliably analyzed |");
                sb.AppendLine($"| Rule | {finding.RuleId} |");
                if (finding.Entry is not null)
                    sb.AppendLine($"| File | `{finding.Entry.Pathname}` |");
                if (finding.Evidence is not null)
                    sb.AppendLine($"| Evidence | {finding.Evidence} |");
                sb.AppendLine();
                sb.AppendLine(finding.Description);
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }
}
