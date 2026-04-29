using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;

namespace UnityPackageScanner.Rules;

/// <summary>
/// Detects files with text-format extensions (.json, .xml, .txt, .csv, .yaml, .yml) that contain
/// binary or encrypted data instead of valid UTF-8 text. Malicious packages sometimes embed
/// encrypted configuration (C2 addresses, license keys, payloads) as a file disguised with an
/// innocent-looking text extension.
/// </summary>
public sealed class BinaryMasqueradeRule(ILogger<BinaryMasqueradeRule> logger) : IDetectionRule
{
    public string RuleId => KnownRuleIds.BinaryMasquerade;
    public string Title => "Binary data in text-format file";
    public Severity DefaultSeverity => Severity.Suspicious;
    public bool IsEnabled { get; set; } = true;

    public string LongDescription =>
        "Detects package entries whose file extension declares a text format (.json, .xml, .txt, " +
        ".csv, .yaml, .yml) but whose content is not valid UTF-8. All of these formats require " +
        "UTF-8 encoding by their respective specifications. A file that fails UTF-8 validation is " +
        "binary data in disguise — most commonly an encrypted payload, a C2 configuration blob, " +
        "or key material stored alongside the package's runtime code.";

    public IReadOnlyList<string> FalsePositivePatterns =>
    [
        "Legacy text files encoded in ISO-8859-1 (Latin-1) or Windows-1252 contain byte sequences " +
        "that are invalid UTF-8. These are uncommon in Unity packages but can occur in third-party " +
        "assets originally authored on older Windows tools. Inspect the file — if it looks like " +
        "readable text in a Western European language, it is likely a benign encoding issue.",
        "Some Unity YAML binary-format serialized files (.asset, .prefab) may be stored with unusual " +
        "extensions by mistake. Check whether the content begins with the YAML header '%YAML 1.1'.",
    ];

    private static readonly HashSet<string> TextExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".json", ".xml", ".txt", ".csv", ".yaml", ".yml",
        };

    // Minimum file size to bother checking — tiny files (e.g. empty or single-char) are noise.
    private const int MinBytes = 16;

    public async IAsyncEnumerable<Finding> AnalyzeAsync(
        IReadOnlyList<PackageEntry> entries,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (!IsEnabled) yield break;

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();

            if (!TextExtensions.Contains(entry.Extension)) continue;
            if (entry.AssetBytes is null || entry.AssetBytes.Length < MinBytes) continue;

            if (!IsValidUtf8(entry.AssetBytes))
            {
                logger.LogDebug("{RuleId}: {Path} has text extension but failed UTF-8 validation ({Size} bytes)",
                    RuleId, entry.Pathname, entry.AssetBytes.Length);

                yield return new Finding
                {
                    RuleId = RuleId,
                    Severity = DefaultSeverity,
                    Title = Title,
                    Description =
                        $"'{entry.Pathname}' has a {entry.Extension} extension (a text format) but " +
                        "its content is not valid UTF-8. Text-format files must be UTF-8 by " +
                        "specification. This file likely contains binary or encrypted data hidden " +
                        "behind an innocuous extension.",
                    Entry = entry,
                    Evidence = $"Extension: {entry.Extension}, Size: {entry.AssetBytes.Length:N0} bytes, Content: not valid UTF-8",
                };
            }
        }

        await Task.CompletedTask;
    }

    // UTF-8 decoder that throws on invalid byte sequences instead of silently replacing them.
    private static readonly Encoding Utf8Strict =
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static bool IsValidUtf8(byte[] data)
    {
        // Strip UTF-8 BOM if present — it is valid.
        var span = data.AsSpan();
        if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
            span = span[3..];

        try
        {
            Utf8Strict.GetString(span);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
