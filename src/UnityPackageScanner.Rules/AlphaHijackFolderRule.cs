using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects DLLs and C# source files placed inside folders whose name begins with '!', '~', or '#'.
/// These characters sort before all letters in ASCII, so Unity's asset import order processes
/// the folder before any alphabetically-normal folder — a technique used by VRChat malware
/// (e.g. the !Temmie / TOS.dll family) to guarantee editor-code execution before the user
/// can inspect the package.
/// </summary>
public sealed class AlphaHijackFolderRule(ILogger<AlphaHijackFolderRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.AlphaHijackFolder;
    public string Title => "Executable in priority-ordered folder";
    public Severity DefaultSeverity => Severity.Suspicious;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects DLLs and C# source files stored inside folders whose name starts with '!', '~', " +
        "or '#'. These characters have ASCII values below uppercase 'A', so Unity's asset pipeline " +
        "and editor startup process files in such folders before any alphabetically-normal folder. " +
        "Malicious packages exploit this ordering to ensure their editor scripts run — and can " +
        "establish persistence or exfiltrate data — before the developer has a chance to read the " +
        "other files in the package. The most widely-distributed variant uses a '!' prefix " +
        "(e.g. Assets/!Author/Editor/payload.dll).";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Some legitimate packages use a '!' prefix purely to group their assets at the top of the " +
        "Project window for visibility (e.g. '!MyTool/'). If the DLL inside performs only standard " +
        "editor tooling (setup wizards, importer helpers) with no network access or reflection, " +
        "the '!' naming alone is not sufficient evidence of malice.",
    ];

    // Characters that sort before 'A' in ASCII and are used to hijack Unity's import order.
    private static readonly char[] HijackPrefixes = ['!', '~', '#'];

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (entry.DetectedType is not (DetectedType.ManagedDll
                or DetectedType.NativePE
                or DetectedType.NativeElf
                or DetectedType.NativeMachO
                or DetectedType.CSharpSource))
                continue;

            var hijackFolder = FindHijackComponent(entry.Pathname);
            if (hijackFolder is null) continue;

            logger.LogDebug("{RuleId}: priority-prefix folder '{Folder}' contains executable at {Path}",
                RuleId, hijackFolder, entry.Pathname);

            yield return new Finding
            {
                RuleId = RuleId,
                Severity = DefaultSeverity,
                Title = Title,
                Description =
                    $"A DLL or script at '{entry.Pathname}' is stored inside folder '{hijackFolder}', " +
                    "whose name begins with a character that sorts before 'A'. Unity processes these " +
                    "folders first during editor startup, guaranteeing that any editor code inside " +
                    "executes before the developer can review the package contents.",
                Entry = entry,
                Evidence = $"Priority-prefix folder: '{hijackFolder}'",
            };
        }

        await Task.CompletedTask;
    }

    private static string? FindHijackComponent(string pathname)
    {
        var parts = pathname.Replace('\\', '/').Split('/');
        // Skip the last segment (the file name itself) — only flag directory components.
        for (int i = 0; i < parts.Length - 1; i++)
        {
            var part = parts[i];
            if (part.Length > 1 && HijackPrefixes.Contains(part[0]))
                return part;
        }
        return null;
    }
}
