# Unity Package Scanner

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

Static analysis for `.unitypackage` files — detect potentially malicious content before you import it into a Unity project.

Malicious packages are a recurring problem in the VRChat and broader Unity asset-sharing community. A `.unitypackage` can contain C# editor scripts that run automatically the moment it's imported, obfuscated DLLs that fetch payloads from the network, and native binaries that Unity loads on startup. This tool inspects a package's contents without importing it, and flags anything that looks dangerous.

**11 detection rules** covering obfuscation, auto-execution, native plugins, path traversal, network access, process spawning, reflection loading, suspicious P/Invoke, encrypted embedded resources, hidden directories, and dangerous file types.

<img width="1113" height="894" alt="image" src="https://github.com/user-attachments/assets/8d75de29-9223-4b7d-a7f5-665ab019e54c" />

## Install

Download a release archive from the [Releases](../../releases) page. Two archives per platform: one for the GUI and one for the CLI. No installer, no runtime required — extract and run.

| Platform | GUI archive | CLI archive |
|---|---|---|
| Windows x64 | `UnityPackageScanner-<version>-win-x64.zip` | `unity-package-scanner-cli-<version>-win-x64.zip` |
| Linux x64 | `UnityPackageScanner-<version>-linux-x64.tar.gz` | `unity-package-scanner-cli-<version>-linux-x64.tar.gz` |
| macOS x64 | `UnityPackageScanner-<version>-osx-x64.tar.gz` | `unity-package-scanner-cli-<version>-osx-x64.tar.gz` |
| macOS ARM64 | `UnityPackageScanner-<version>-osx-arm64.tar.gz` | `unity-package-scanner-cli-<version>-osx-arm64.tar.gz` |

## Quick start

**GUI:** Open `UnityPackageScanner.exe` (Windows) or `UnityPackageScanner` (macOS). Drag a `.unitypackage` onto the window, or click **Open…**.

**CLI:**
```
unity-package-scanner SomeAsset.unitypackage
```

## Example output

**Text (default):**
```
Verdict: CRITICAL  SomeAsset.unitypackage
SHA-256: 338870b9...  Entries: 3  Duration: 120ms

── CRITICAL ──
  • Auto-executing editor code
    File: Assets/Editor/AutoRun.cs
    Evidence: [InitializeOnLoad] or [InitializeOnLoadMethod] attribute found
    This script will execute automatically when the package is imported.
```

**JSON** (`--format json`), **SARIF** (`--format sarif`), and **Markdown** (`--format markdown`) are also supported. SARIF integrates directly with GitHub code-scanning. Markdown is useful for pasting into issue comments or PR descriptions. Use `--output report.md` to write to a file instead of stdout.

## Documentation

- [CLI reference](docs/cli.md) — all flags, output formats, exit codes, worked examples
- [Detection rules](docs/rules.md) — every rule, what it detects, false positive patterns

## Releasing

```
git tag v0.2.0 && git push origin v0.2.0
```

The release workflow builds, tests, and publishes all platform artifacts automatically.

## License

MIT — see [LICENSE](LICENSE).

## Contributing / Issues

Open an issue at the [issue tracker](../../issues). When reporting a false positive or missed detection, **do not attach the package itself** unless you are certain it contains no private or sensitive assets.
