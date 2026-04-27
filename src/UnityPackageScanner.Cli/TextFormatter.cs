using Spectre.Console;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Cli;

internal static class TextFormatter
{
    public static void WriteResult(ScanResult result, bool quiet, IAnsiConsole console)
    {
        var (verdictColor, verdictLabel) = result.Verdict switch
        {
            Verdict.Clean => ("green", "CLEAN"),
            Verdict.Suspicious => ("yellow", "SUSPICIOUS"),
            Verdict.HighRisk => ("darkorange", "HIGH RISK"),
            Verdict.Critical => ("red", "CRITICAL"),
            _ => ("white", result.Verdict.ToString().ToUpperInvariant()),
        };

        console.MarkupLine(
            $"[bold]Verdict:[/] [{verdictColor}]{verdictLabel}[/]  " +
            $"[grey]{result.PackagePath}[/]");

        if (quiet) return;

        console.MarkupLine(
            $"[grey]SHA-256:[/] {result.PackageSha256}  " +
            $"[grey]Entries:[/] {result.EntryCount}  " +
            $"[grey]Duration:[/] {result.ScanDuration.TotalMilliseconds:F0}ms");

        if (result.Findings.Count == 0)
        {
            console.MarkupLine("[grey]No findings.[/]");
            return;
        }

        console.WriteLine();

        var grouped = result.Findings
            .GroupBy(f => f.Severity)
            .OrderByDescending(g => g.Key);

        foreach (var group in grouped)
        {
            var (sev, sevColor) = group.Key switch
            {
                Severity.Critical => ("CRITICAL", "red"),
                Severity.HighRisk => ("HIGH RISK", "darkorange"),
                Severity.Suspicious => ("SUSPICIOUS", "yellow"),
                _ => ("INFO", "grey"),
            };

            console.MarkupLine($"[bold {sevColor}]── {sev} ──[/]");

            foreach (var finding in group)
            {
                var advisory = finding.IsAdvisory ? " [grey](advisory — DLL could not be reliably analyzed)[/]" : "";
                console.MarkupLine($"  [{sevColor}]•[/] [bold]{Markup.Escape(finding.Title)}[/]{advisory}");
                if (finding.Entry is not null)
                    console.MarkupLine($"    [grey]File:[/] {Markup.Escape(finding.Entry.Pathname)}");
                if (finding.Evidence is not null)
                    console.MarkupLine($"    [grey]Evidence:[/] {Markup.Escape(finding.Evidence)}");
                console.MarkupLine($"    {Markup.Escape(finding.Description)}");
                console.WriteLine();
            }
        }
    }

    public static int ToExitCode(Verdict verdict, string failOn) => failOn switch
    {
        "never" => 0,
        "clean" => verdict == Verdict.Clean ? 0 : 1,
        "suspicious" => verdict >= Verdict.Suspicious ? 1 : 0,
        "high" => verdict >= Verdict.HighRisk ? 1 : 0,
        "critical" => verdict == Verdict.Critical ? 1 : 0,
        _ => 0,
    };
}
