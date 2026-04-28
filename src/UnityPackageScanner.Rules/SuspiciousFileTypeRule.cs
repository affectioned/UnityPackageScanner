using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects files with extensions that have no legitimate role in a Unity package:
/// Windows executables, shell scripts, and Windows shortcut/autorun files.
/// </summary>
public sealed class SuspiciousFileTypeRule(ILogger<SuspiciousFileTypeRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.SuspiciousFileType;
    public string Title => "Suspicious file type";
    public Severity DefaultSeverity => Severity.Critical;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects files whose extension indicates they are directly executable or self-executing on a " +
        "target platform: Windows executables (.exe, .com, .scr), Windows script files (.bat, .cmd, " +
        ".ps1, .vbs, .wsf), Unix shell scripts (.sh), Windows shortcut files (.lnk), and Java " +
        "archives (.jar). None of these file types belong in a Unity package. Their presence is a " +
        "strong indicator that the package is attempting to deliver malware that runs outside of " +
        "the Unity runtime.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Packages that ship build tooling (e.g. a native code generator invoked from a pre/post-build " +
        "step) might legitimately contain a .bat or .sh helper. Inspect the script content before dismissing.",
        "Sample projects may include a standalone launcher (.exe) as a pre-built demo. " +
        "These are unusual and still warrant scrutiny.",
    ];

    // Extensions mapped to the severity they trigger.
    // Critical: files that execute directly on Windows without user confirmation.
    // HighRisk: script files that require a host but are commonly used in malware.
    private static readonly Dictionary<string, Severity> DangerousExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Windows executables
            { ".exe", Severity.Critical },
            { ".com", Severity.Critical },
            { ".scr", Severity.Critical },    // screen-saver — runs as executable

            // Windows script files
            { ".bat", Severity.Critical },
            { ".cmd", Severity.Critical },
            { ".ps1", Severity.HighRisk },    // PowerShell — blocked by default policy, but not always
            { ".vbs", Severity.HighRisk },    // VBScript
            { ".wsf", Severity.HighRisk },    // Windows Script File

            // Unix scripts
            { ".sh",  Severity.HighRisk },

            // Windows shortcuts / autorun
            { ".lnk", Severity.HighRisk },    // shortcut — can point to arbitrary code
            { ".scf", Severity.Suspicious },  // Shell Command File — can trigger credential theft

            // Java / cross-platform archives
            { ".jar", Severity.Suspicious },
        };

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (!DangerousExtensions.TryGetValue(entry.Extension, out var severity)) continue;

            logger.LogDebug("{RuleId}: suspicious extension '{Ext}' at {Path}", RuleId, entry.Extension, entry.Pathname);

            yield return new Finding
            {
                RuleId = RuleId,
                Severity = severity,
                Title = Title,
                Description =
                    $"This package contains a '{entry.Extension}' file, which has no legitimate role " +
                    "in a Unity package. Such files can execute arbitrary code outside of the Unity " +
                    "runtime — on some systems automatically, on others with a single click.",
                Entry = entry,
                Evidence = $"File type: {entry.Extension}",
            };
        }

        await Task.CompletedTask;
    }
}
