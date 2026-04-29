using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;

// Out-of-process DLL analysis worker.
// Protocol: newline-delimited JSON on stdin/stdout. One request line → one response line.
// Stdin EOF signals end of batch; worker exits cleanly. All internal errors go to stderr.

// Use BOM-free UTF-8: pipes must not start with a BOM or the parent's JSON deserializer will reject the first line.
var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
Console.InputEncoding = utf8NoBom;
Console.OutputEncoding = utf8NoBom;

var jsonOpts = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
};

IDetectionRule[] rules =
[
    new ObfuscatedDllRule(NullLogger<ObfuscatedDllRule>.Instance),
    new InitializeOnLoadRule(NullLogger<InitializeOnLoadRule>.Instance),
    new NativePluginRule(NullLogger<NativePluginRule>.Instance),
    new NetworkAccessRule(NullLogger<NetworkAccessRule>.Instance),
    new ProcessSpawnRule(NullLogger<ProcessSpawnRule>.Instance),
    new ReflectionLoadRule(NullLogger<ReflectionLoadRule>.Instance),
    new SuspiciousPInvokeRule(NullLogger<SuspiciousPInvokeRule>.Instance),
    new EmbeddedEncryptedResourceRule(NullLogger<EmbeddedEncryptedResourceRule>.Instance),
];

string? line;
while ((line = Console.ReadLine()) is not null)
{
    WorkerRequest? req;
    try
    {
        req = JsonSerializer.Deserialize<WorkerRequest>(line, jsonOpts);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"ups-dll-worker: deserialize error: {ex.Message}");
        continue;
    }

    if (req is null) continue;

    byte[]? bytes = null;
    if (req.AssetBytes is not null)
    {
        try { bytes = Convert.FromBase64String(req.AssetBytes); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ups-dll-worker: base64 error for {req.Pathname}: {ex.Message}");
        }
    }

    if (!Enum.TryParse<DetectedType>(req.DetectedType, out var detectedType))
    {
        Console.Error.WriteLine($"ups-dll-worker: unknown DetectedType '{req.DetectedType}'");
        detectedType = DetectedType.Unknown;
    }

    var entry = new PackageEntry
    {
        Guid = req.Id,
        Pathname = req.Pathname,
        Size = req.Size,
        DetectedType = detectedType,
        AssetBytes = bytes,
    };

    var wFindings = new List<WorkerFinding>();

    foreach (var rule in rules)
    {
        try
        {
            await foreach (var f in rule.AnalyzeAsync([entry]))
                wFindings.Add(new WorkerFinding(f.RuleId, f.Severity.ToString(), f.Title, f.Description, f.Evidence, f.IsAdvisory));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ups-dll-worker: rule {rule.RuleId} error on {req.Pathname}: {ex.Message}");
        }
    }

    Console.WriteLine(JsonSerializer.Serialize(new WorkerResponse(req.Id, [.. wFindings]), jsonOpts));
}

record WorkerRequest(string Id, string Pathname, string? AssetBytes, string DetectedType, long Size);
record WorkerResponse(string Id, WorkerFinding[] Findings);
record WorkerFinding(string RuleId, string Severity, string Title, string Description, string? Evidence, bool IsAdvisory);
