using System.CommandLine;
using System.CommandLine.Invocation;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;
using Spectre.Console;
using UnityPackageScanner.Core.Analysis;
using UnityPackageScanner.Core.Extraction;
using UnityPackageScanner.Core.Logging;
using UnityPackageScanner.Core.Models;
using UnityPackageScanner.Rules;

var pathArg = new Argument<FileSystemInfo?>(
    name: "path",
    description: "Path to a .unitypackage file or a directory to scan recursively.")
{
    Arity = ArgumentArity.ZeroOrOne,
};

var formatOption = new Option<string>(
    aliases: ["--format", "-f"],
    description: "Output format: text (default), json, sarif, markdown.",
    getDefaultValue: () => "text");
formatOption.FromAmong("text", "json", "sarif", "markdown");

var outputOption = new Option<FileInfo?>(
    aliases: ["--output", "-o"],
    description: "Write output to a file instead of stdout.");

var failOnOption = new Option<string>(
    name: "--fail-on",
    description: "Exit non-zero when verdict meets this threshold: clean, suspicious, high, critical (default), never.",
    getDefaultValue: () => "critical");
failOnOption.FromAmong("clean", "suspicious", "high", "critical", "never");

var quietOption = new Option<bool>(
    name: "--quiet",
    description: "Only emit the verdict line; suppress finding details.");

var verboseOption = new Option<bool>(
    name: "--verbose",
    description: "Enable debug-level logging.");

var noColorOption = new Option<bool>(
    name: "--no-color",
    description: "Disable ANSI color output.");

var listRulesOption = new Option<bool>(
    name: "--list-rules",
    description: "Print all rules with IDs and enabled status, then exit.");

var root = new RootCommand("Unity Package Scanner — static analysis for .unitypackage files.")
{
    pathArg, formatOption, outputOption, failOnOption, quietOption, verboseOption, noColorOption, listRulesOption
};

root.SetHandler(async (InvocationContext ctx) =>
{
    var path = ctx.ParseResult.GetValueForArgument<FileSystemInfo?>(pathArg);
    var format = ctx.ParseResult.GetValueForOption(formatOption)!;
    var output = ctx.ParseResult.GetValueForOption(outputOption);
    var failOn = ctx.ParseResult.GetValueForOption(failOnOption)!;
    var quiet = ctx.ParseResult.GetValueForOption(quietOption);
    var verbose = ctx.ParseResult.GetValueForOption(verboseOption);
    var noColor = ctx.ParseResult.GetValueForOption(noColorOption) || !Console.IsOutputRedirected is false;
    var listRules = ctx.ParseResult.GetValueForOption(listRulesOption);

    var console = noColor
        ? AnsiConsole.Create(new AnsiConsoleSettings { ColorSystem = ColorSystemSupport.NoColors })
        : AnsiConsole.Console;

    // --- Logging ---
    var serilog = LoggingConfiguration.CreateBaseConfiguration(verbose)
        .WriteTo.Sink(new UnityPackageScanner.Cli.SpectreConsoleSink())
        .CreateLogger();

    using var loggerFactory = new SerilogLoggerFactory(serilog, dispose: true);

    // --- Rules ---
    var rules = new IDetectionRule[]
    {
        new InitializeOnLoadRule(loggerFactory.CreateLogger<InitializeOnLoadRule>()),
        new NativePluginRule(loggerFactory.CreateLogger<NativePluginRule>()),
        new PathAnomalyRule(loggerFactory.CreateLogger<PathAnomalyRule>()),
        new NetworkAccessRule(loggerFactory.CreateLogger<NetworkAccessRule>()),
        new ProcessSpawnRule(loggerFactory.CreateLogger<ProcessSpawnRule>()),
        new ReflectionLoadRule(loggerFactory.CreateLogger<ReflectionLoadRule>()),
        new SuspiciousPInvokeRule(loggerFactory.CreateLogger<SuspiciousPInvokeRule>()),
    };

    if (listRules)
    {
        var table = new Table().AddColumn("ID").AddColumn("Severity").AddColumn("Enabled").AddColumn("Title");
        foreach (var r in rules)
            table.AddRow(r.RuleId, r.DefaultSeverity.ToString(), r.IsEnabled ? "yes" : "no", r.Title);
        console.Write(table);
        ctx.ExitCode = 0;
        return;
    }

    if (path is null)
    {
        console.MarkupLine("[red]Error:[/] path is required.");
        ctx.ExitCode = 64;
        return;
    }

    var packages = ResolvePackages(path);
    if (packages.Count == 0)
    {
        console.MarkupLine("[red]Error:[/] No .unitypackage files found at the specified path.");
        ctx.ExitCode = 65;
        return;
    }

    var extractor = new UnityPackageExtractor(loggerFactory.CreateLogger<UnityPackageExtractor>());
    var pipeline = new ScanPipeline(extractor, rules, loggerFactory.CreateLogger<ScanPipeline>());

    var ct = ctx.GetCancellationToken();
    int exitCode = 0;

    foreach (var packagePath in packages)
    {
        try
        {
            var result = await pipeline.ScanAsync(packagePath, ct);
            WriteOutput(result, format, output, quiet, console);
            var code = UnityPackageScanner.Cli.TextFormatter.ToExitCode(result.Verdict, failOn);
            if (code != 0) exitCode = code;
        }
        catch (FileNotFoundException ex)
        {
            console.MarkupLine($"[red]Error:[/] {Markup.Escape(ex.Message)}");
            exitCode = 65;
        }
        catch (InvalidDataException ex)
        {
            console.MarkupLine($"[red]Error:[/] Not a valid .unitypackage: {Markup.Escape(ex.Message)}");
            exitCode = 65;
        }
        catch (Exception ex)
        {
            console.MarkupLine($"[red]Internal error:[/] {Markup.Escape(ex.Message)}");
            serilog.Fatal(ex, "Unhandled exception scanning {Path}", packagePath);
            exitCode = 70;
        }
    }

    ctx.ExitCode = exitCode;
});

return await root.InvokeAsync(args);

static List<string> ResolvePackages(FileSystemInfo path)
{
    if (path is FileInfo f)
        return f.Exists && f.Extension.Equals(".unitypackage", StringComparison.OrdinalIgnoreCase)
            ? [f.FullName]
            : [];

    if (path is DirectoryInfo d && d.Exists)
        return d.GetFiles("*.unitypackage", SearchOption.AllDirectories)
            .Select(fi => fi.FullName)
            .ToList();

    return [];
}

static void WriteOutput(ScanResult result, string format, FileInfo? outputFile, bool quiet, IAnsiConsole console)
{
    if (format == "text")
    {
        UnityPackageScanner.Cli.TextFormatter.WriteResult(result, quiet, console);
        return;
    }

    var text = format switch
    {
        "json" => UnityPackageScanner.Cli.JsonFormatter.Format(result),
        "sarif" => UnityPackageScanner.Cli.SarifFormatter.Format(result),
        _ => $"Format '{format}' not yet implemented.",
    };

    if (outputFile is not null)
        File.WriteAllText(outputFile.FullName, text);
    else
        Console.WriteLine(text);
}
