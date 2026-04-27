# CLI Reference

`unity-package-scanner` is a headless command-line tool for scanning `.unitypackage` files. It runs without a display, produces structured output, and exits with a meaningful status code — making it suitable for CI pipelines, server-side scanning, and batch processing.

## Synopsis

```
unity-package-scanner <path> [options]
unity-package-scanner --list-rules
unity-package-scanner --version
```

## Arguments

### `<path>`

Path to a `.unitypackage` file, or a directory. Directories are scanned recursively for every file matching `*.unitypackage`. Glob patterns are not supported directly — use shell expansion (`*.unitypackage`) instead.

## Options

### `--format`, `-f`

Output format. Default: `text`.

| Value | Description |
|---|---|
| `text` | Human-readable, color-coded terminal output. Falls back to plain text when stdout is not a TTY. |
| `json` | Machine-readable JSON, same schema as the GUI export. Stable across versions. |
| `sarif` | SARIF 2.1.0. Consumed natively by GitHub Advanced Security, GitLab, Codacy. |
| `markdown` | For posting in PR comments and incident channels. |

### `--output`, `-o`

Write formatted output to a file instead of stdout. Useful when piping log output elsewhere and you want the scan report in a separate file.

### `--fail-on`

Exit non-zero when the package verdict reaches this level. Default: `critical`.

| Value | Behavior |
|---|---|
| `never` | Always exit 0 (unless usage/data/internal error). |
| `critical` | Exit 1 only for Critical verdict. |
| `high` | Exit 1 for HighRisk or Critical. |
| `suspicious` | Exit 1 for Suspicious, HighRisk, or Critical. |
| `clean` | Exit 1 whenever any finding exists. |

### `--quiet`

Suppress all output except the verdict line. Useful in scripts where you only need the exit code.

### `--verbose`

Bump the runtime log level from Information to Debug. Log output goes to stderr and the rolling file. Enables heuristic-level detail (obfuscation score breakdown, per-signal weights). Re-scan with this flag when diagnosing a false positive.

### `--no-color`

Disable ANSI escape codes. Auto-enabled when stdout is not a TTY.

### `--list-rules`

Print a table of all rules (ID, severity, enabled status, title) and exit. Does not require a path argument.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All packages passed the `--fail-on` threshold. |
| `1` | At least one package failed the threshold. |
| `64` | Usage error — bad arguments, conflicting flags, unknown option. |
| `65` | Data error — file not found, not a valid `.unitypackage`, corrupted. |
| `70` | Internal error — unhandled exception. File a bug. |

## Output formats

### Text (default)

Color-coded for terminal reading. Verdict first, then findings grouped by severity. Each finding includes the filename, evidence string, and a one-sentence description.

```
Verdict: CRITICAL  SomeAsset.unitypackage
SHA-256: 338870b9...  Entries: 3  Duration: 120ms

── CRITICAL ──
  • Auto-executing editor code
    File: Assets/Editor/AutoRun.cs
    Evidence: [InitializeOnLoad] attribute found
    This script will execute automatically when the package is imported.
```

### JSON

Structured output with the full scan result. Schema matches the GUI's JSON export.

```json
{
  "PackagePath": "SomeAsset.unitypackage",
  "PackageSha256": "338870b9...",
  "Verdict": "Critical",
  "Findings": [
    {
      "RuleId": "UPS002",
      "Severity": "Critical",
      "Title": "Auto-executing editor code",
      "Evidence": "[InitializeOnLoad] attribute found"
    }
  ]
}
```

## Worked examples

### Scan a single file

```bash
unity-package-scanner SomeAsset.unitypackage
```

### Batch scan a directory, exit non-zero on any High or Critical finding

```bash
unity-package-scanner ./packages/ --fail-on high
```

### GitHub Actions step — gate a PR on scan results

```yaml
- name: Scan Unity packages
  run: |
    unity-package-scanner ./Assets/Packages/ \
      --format sarif \
      --output scan.sarif \
      --fail-on high

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
  if: always()
```

### Docker scan of a mounted volume

```bash
docker run --rm \
  -v /path/to/packages:/packages:ro \
  ghcr.io/your-org/unity-package-scanner:latest \
  /packages --format json --fail-on critical
```

### Verbose mode for diagnosing a false positive

```bash
unity-package-scanner suspicious.unitypackage --verbose 2>debug.log
# Inspect debug.log to see heuristic scores and per-signal weights
```

## Troubleshooting

**My package triggered a false positive. How do I investigate?**

Re-run with `--verbose` to see the full heuristic breakdown, then check the log file at `~/.config/UnityPackageScanner/logs/` (Linux/macOS) or `%APPDATA%\UnityPackageScanner\logs\` (Windows).

When opening a bug report, attach the log file (not the package, unless you are certain it contains no private work). Include the SHA-256 hash shown in the output so the package can be identified without needing the binary.

**The tool exits with code 70 (Internal error).**

That's a bug. Open an issue with the log file attached. The full exception and stack trace are in the rolling log.
