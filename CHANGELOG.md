# Changelog

User-visible package changes are listed below, newest first. Historical version entries describe
development milestones; they do not imply that a Git tag or hosted release exists for each version.
The current package version is recorded in [plugin.json](plugin.json) and synchronized with the host overlays.

## 0.15.0

### Request rewriter

- Add `read-the-lips`, a skill that rewrites a vague request into a clear prompt: it states the intent it
  read, returns the improved prompt ready to copy, lists what changed, and marks assumptions,
  placeholders and the few questions that would change the result. It rewrites only and carries the
  prompt out only if asked next. It reads files only to ground names in the open project and runs no
  commands. Invoke it as `/read-the-lips <request>` in Claude Code after a copy install,
  `/instinct:read-the-lips` from the plugin, `$read-the-lips` in Codex, or in plain words.
- `install.py` installs it by default with the other skills; `--skill read-the-lips` installs it alone.
- The package description now mentions the rewriter.

## 0.14.0

### Command shortcut

- Add `security-check`, a skill that runs the audit as a command with a target:
  `/security-check ../candidate-skill` in Claude Code after a copy install, `/instinct:security-check`
  from the Claude Code plugin, `$security-check` in Codex. It loads `how-deep-the-rabbit-hole-goes`
  from its sibling folder and adds no checks of its own. Claude Code offers it only as a command
  (`disable-model-invocation`), so plain-language requests still go to the audit skill.
- `install.py` installs both skills by default, and `--skill security-check` also installs the audit
  skill it loads.

## 0.13.1

### Scanner output

- Write the text report as UTF-8 when `pwsh -File` output is redirected, as `-Json` and `-ListRules`
  output already was. Git Bash on Windows no longer shows the report's separators and non-English
  evidence as `�`, and legacy console code pages no longer replace non-ASCII paths. On a console the
  report keeps its severity colors. A regression reads the raw text report under code page 437 (a
  Latin-1 locale on macOS and Linux).
- Document that the `scan.sh` wrapper works in Git Bash on Windows.

## 0.13.0

### Portable packaging and installation

- Add an Agent Plugins 1.0 root manifest and a Codex compatibility manifest alongside the Claude Code
  plugin. All share the same identity and version; validation checks their consistency.
- Add a Python 3.10+ installer that copies complete skills into Codex or Claude project/user discovery
  directories, or a custom directory for another agent. It uses the standard library, preserves file
  bytes, needs no symlinks or shell-specific copy commands, and requires `--update` before replacement.
- Resolve skill resources relative to the loaded `SKILL.md`, describe work by available capabilities,
  and report manual-review limits when shell, runtime, image viewing or hashing is unavailable.
- Make `AGENTS.md` the shared repository instructions and retain `CLAUDE.md` as the Claude entry point.
- Remove newer .NET hashing API dependencies so the scanner matches its PowerShell 7.0+ requirement.
- Write `-Json` and `-ListRules` output as UTF-8 when `pwsh -File` output is redirected. Windows
  consoles with a legacy code page (866, 437 …) no longer turn non-ASCII paths and evidence into
  look-alike or `?` characters. The test runners decode child output as UTF-8.
- Add CI for Windows, Linux and macOS, including installer checks, scanner regressions and comparison
  of scanner output across operating systems. A configured CI matrix is not a completed host test.

### Documentation

- Add two AI-generated Alice in Wonderland illustrations to the README, with alt text and saved
  [artwork notes and generation prompts](docs/assets/README.md).
- Brand both README illustrations with the owner-supplied “БЕЗ ДУШІ / WITHOUT SOUL” logo without its
  exterior white background.
- Remove the Ukrainian README; `README.md` is now the single, English user guide. The skill still
  triggers on Ukrainian requests and reports in the user's language.
- Update the README for this release: the rule-ID count, UTF-8 JSON output when redirected, and the
  portable installer and portability test in the contributor workflow.

## 0.12.0

### Agent and OS portability

- Make the skill agent-neutral: steps name actions instead of Claude Code tools, and the inventory,
  cleanup and dynamic-command guidance covers Codex, Gemini CLI, Cursor, GitHub Copilot, Windsurf,
  Cline and other agents. Document installing the skill folder in any agent that loads `SKILL.md`.
- Recognize other agents' auto-run and always-loaded files: `gemini-extension.json`,
  `claude_desktop_config.json` and `cline_mcp_settings.json` (MCP), `.codex/config.toml` and
  `opencode.json` (settings), `prompts/`, `chatmodes/` and `commands/*.toml`, plus Cursor, Windsurf,
  Cline, Roo, Kiro and Copilot instruction files. New rule T21-006 flags `!{…}` shell injection in
  Gemini CLI command files. Agent credential and API-redirect rules now include Gemini CLI, Copilot and
  OpenCode.
- Make the tree hash identical on every OS and locale: paths are sorted ordinally (the culture-aware
  sort gave different hashes for the same files under, for example, Lithuanian and Swedish locales).
  `TreeHashVersion` is now 3; a multi-file hash from 0.11.0 or earlier can differ for the same files,
  so rebaseline stored hashes.
- Walk and hash target files through .NET instead of PowerShell path cmdlets, which treat `\` as a
  folder separator even on macOS/Linux: such files could not be hashed and such folders were skipped.
  Hash empty files without opening them, and identify named pipes, devices and sockets with the system
  `find` (T19-919) without opening them, so that a FIFO cannot hang the scan.
- List findings, inventory, components, coverage issues and skills in a total ordinal order, so that the
  same target gives byte-identical JSON on every OS and in every locale.
- Treat Finder/Explorer metadata (`.DS_Store`, AppleDouble `._*`, `Thumbs.db`) whose header matches as
  LOW (T19-918) instead of a HIGH binary. Add macOS, Windows and systemd launcher extensions, and count
  extensionless files with a shebang as scripts.
- Add `scan.sh`, a POSIX `sh` wrapper for macOS, Linux and other Unix-like systems. It finds `pwsh`
  (`$PWSH`, `PATH`, common install folders), takes Unix-style options (`--json`, `--min-severity`,
  `--list-rules`, `--`), returns the scanner's exact output and exit code, and exits `127` with
  per-OS install hints when PowerShell is missing. It is kept LF in Windows checkouts.
- Give OS-neutral scanner instructions: one command for every shell, exit-code capture per shell,
  PowerShell install options per OS, a manual fallback without `pwsh`, and cloning with
  `core.autocrlf=false`, with a symlink check for Windows checkouts.
- Expand the rule catalog to 232 stable IDs while preserving all 229 earlier IDs. Add agent, OS and
  locale regression probes. Verified on Windows 11 and on Linux (Ubuntu 24.04 in WSL, PowerShell
  7.7.0), for both a CRLF and an LF checkout; macOS is not yet verified.

### Documentation

- Reorganize English and Ukrainian READMEs around installation, first use, audit results and limits.
- Replace the marketplace owner placeholder with `Vilintritenmert/instinct`; document plugin updates
  and uninstallation separately from marketplace refreshes.
- Surface experimental status and the limited external baseline in both languages.
- Move scanner options, hashes and verified output examples to [docs/SCANNER.md](docs/SCANNER.md).
- Add [contribution guidance](CONTRIBUTING.md) and a [security reporting policy](SECURITY.md).
- Open both READMEs with the risk the plugin addresses, add a "How it works" section with the verdict
  table, and show real abridged scanner findings from the inert `evil-plugin` fixture.

## 0.11.0

- Add a second separately authored and blind-reviewed paraphrase development source: 80 cases in
  English, German and Ukrainian, including 40 positive examples and 40 controls.
- Add nine mechanism-level rules for instruction reset, task replacement, rule-free personas, forced
  output, fake system turns, AI-directed text and setup/hidden-instruction disclosure.
- Increase that source's HIGH+ positive detections from 4/40 to 38/40, with 1/40 control alerts in the
  resulting scanner. These are tuned development results.
- Preserve earlier development and external findings case by case. The external baseline remains
  TP 1 / FN 59 / FP 0 / TN 56, with all original misses retained.
- Expand the rule catalog to 229 stable IDs while preserving all 220 earlier IDs.

See the [round-2 context review](tests/how-deep-the-rabbit-hole-goes/CONTEXT_REVIEW.md).

## 0.10.0

- Add a trust-context review of the fixed external dataset by two isolated AI reviewers. Conditional
  types and severities supplement the original labels without replacing them or recovering missing
  source context.
- Add a separate frozen 60-case paraphrase development source and eight new rules. Its HIGH+ positive
  detections improve from 1/30 to 30/30, with 0/30 control alerts; these are tuned development results.
- Retain the external result of 1/60 positive detections and all 59 original misses.
- Expand the rule catalog from 212 to 220 stable IDs.

See the [context-review protocol and results](tests/how-deep-the-rabbit-hole-goes/CONTEXT_REVIEW.md).

## 0.9.0

- Give all 212 scanner checks stable IDs and expose a versioned, hashed catalog with `-ListRules`.
- Add an offline evaluator for the frozen local development set and the independently sourced,
  pinned deepset public test split. The local 60-case holdout remains unscored.
- Record raw alert TP/FN/FP/TN, topic/file matches, minimum versus exact severity, coverage gaps and
  per-rule evidence, with annotation and provenance limits kept explicit.
- Keep scanner JSON schema and tree-hash version at 2.

See the [measurement guide](tests/how-deep-the-rabbit-hole-goes/EVALUATION.md).

## 0.8.0

- Refine signals for private transfers, approval bypass, persistence and concealed output.
- Reduce warnings on narrow explicit prohibitions and literal examples while retaining later
  dangerous actions on the same line.
- Keep frozen development data and the unscored holdout separate from focused regressions.

These checks are review heuristics, not authorization or data-flow analysis. See the
[coverage contract](skills/how-deep-the-rabbit-hole-goes/references/coverage.md) for historical evidence.
