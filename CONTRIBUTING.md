# Contributing to instinct

instinct is an experimental skill for auditing agent skills and plugins. Keep one shared Agent Skills
folder, a portable plugin manifest and thin host compatibility manifests. Read the
[README](README.md), [coverage contract](skills/how-deep-the-rabbit-hole-goes/references/coverage.md)
and [security policy](SECURITY.md) before proposing a change.

## Development setup

- Git for the checkout and checkout-integrity tests.
- PowerShell 7+ (`pwsh`) for the scanner, helper scripts and regression suite.
- Python 3.10+ for the portable installer and evaluation and corpus/review tests; these use the
  standard library.
- The relevant host, such as Codex or Claude Code, for manual discovery and integration checks.

Run commands below from the repository root. Windows and Linux are verified so far; macOS is not.
The CI matrix targets all three operating systems; its configuration alone is not evidence of a
passing run or native agent integration.
Include your PowerShell, Python and operating-system versions when reporting results. To check the
Unix-only probes from Windows, run the suite in WSL with PowerShell for Linux, on the Linux file system
(not `/mnt/c`).

## Repository layout

```text
instinct/
├── plugin.json            portable Agent Plugins manifest
├── .claude-plugin/        Claude Code compatibility and marketplace manifests
├── .codex-plugin/         Codex compatibility manifest
├── AGENTS.md              shared contributor instructions
├── CLAUDE.md              Claude Code entrypoint for those instructions
├── docs/                  scanner and portability guides
├── skills/                one folder per skill, each with a SKILL.md
├── tests/                 inert fixtures, regressions and frozen evaluation data
├── templates/             template for a new skill
└── scripts/               portable installer, skill scaffolding and validation
```

## Adding or editing a skill

Create new skills with the helper, then fill in their actual instructions:

```powershell
pwsh -NoProfile -File ./scripts/new-skill.ps1 -Name my-skill -Description "What the skill does and when to use it."
pwsh -NoProfile -File ./scripts/validate.ps1
```

- `name` is kebab-case, at most 64 characters, and matches the folder name.
- `description` is at most 1024 characters and explains what the skill does and when to use it, using
  phrases a user would actually type.
- Write skills, reference material and helper output in English. Ukrainian trigger phrases are
  welcome. Update `README.md`, the only README, when user-facing behavior changes.
- Keep `SKILL.md` short; put long reference material in `references/`. Do not add placeholder skills.
- Keep skills agent- and OS-neutral. Describe a step by what it does ("read the file", "run the
  command"), not by one agent's tool name, and name agent-specific files only as examples next to
  their equivalents. Resolve bundled scripts relative to the loaded `SKILL.md`, not the checkout or
  agent's working directory. Give commands that work in every shell, or one variant per OS.
- Audit any third-party or borrowed skill with `how-deep-the-rabbit-hole-goes` before adding it.

## Changing installation or packaging

Keep shared instructions and scanner logic in `skills/`. Host manifests describe the same package;
do not fork the skill for each agent or make a scanner invocation depend on an agent-specific tool.
Keep `name`, `version`, `description` and `license` aligned in `plugin.json`,
`.codex-plugin/plugin.json` and `.claude-plugin/plugin.json` wherever those fields are present.

The Python installer copies complete skill folders and uses explicit destinations. New host presets
need a current official discovery-path reference and regression coverage. Preserve existing skills
unless the user passes `--update`; do not alter global agent settings or install runtimes as a side
effect. Check both project and user scopes without writing to the real home directory. See
[PORTABILITY.md](docs/PORTABILITY.md) for the supported installation contract.

Run the portable checks when changing packaging or installation:

```text
python -B tests/test_portability.py -v
pwsh -NoProfile -File ./scripts/validate.ps1
```

Use `py -3` on Windows or `python3` on Unix if that is the available Python 3 command. Verify at least
one installed copy from a different working directory so checkout-relative assumptions are caught.

## Changing the scanner

A new detection rule needs a threat-catalog entry and a regression with an inert positive example and
a near-benign control. Keep `benign-skill` at LOW or below. Give new rules unused stable IDs; never
renumber, reassign or reuse existing IDs. Update structural metadata for structural checks.

Keep the scanner portable: compare and sort paths ordinally (never by the current culture), report
paths with `/`, check a file's type before opening it, and give an OS-only probe an explicit skip, as
the link and Unix probes do. Handle target paths with .NET (`[IO.Path]`, `[IO.File]`,
`DirectoryInfo`), not PowerShell path cmdlets: `Join-Path`, `Get-ChildItem` and `Get-FileHash` treat
`\` as a separator even on macOS/Linux, where it is a legal file-name character. When a check is about
one agent's file layout, look for the equivalent files of other agents too. Keep `scripts/scan.sh` to
POSIX `sh` (test it with dash, not only bash) and give it no logic beyond finding `pwsh` and
translating options. The scanning stays in `scan.ps1`.

Run skill validation after any skill change, and the regression suite after editing `scan.ps1`:

```powershell
pwsh -NoProfile -File ./scripts/validate.ps1
pwsh -NoProfile -File ./tests/how-deep-the-rabbit-hole-goes/run.ps1
```

The runner includes focused security regressions. To retain per-case evidence, pass
`-SecurityReportPath work/security.json` to `run.ps1`. Link probes explicitly skip if the host cannot
create links; report those skips and verify on a capable host when changing link behavior.

## Changing evaluation or frozen-data handling

Run the relevant integrity and measurement tests when modifying evaluation, review logic or corpus
handling:

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/test_evaluate.py -v
python -B tests/how-deep-the-rabbit-hole-goes/test_review_context.py -v
python -B tests/how-deep-the-rabbit-hole-goes/corpus/test_validate.py -v
```

For measurements, use a fresh output directory:

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/evaluate.py --output work/evaluation
```

Do not rewrite frozen cases, labels, thresholds or locks after seeing outcomes. The local holdout
remains unscored. Separate tuned development results from the fixed external baseline and retain
misses, control alerts, errors and unchecked content. See the
[evaluation guide](tests/how-deep-the-rabbit-hole-goes/EVALUATION.md) and
[context review](tests/how-deep-the-rabbit-hole-goes/CONTEXT_REVIEW.md) for provenance and interpretation.

## Documentation and release checks

- Keep the README current on setup, usage, status and limitations. Verify local links and run
  documented read-only examples; keep output excerpts consistent with the current scanner.
- For documentation-only changes, check links, examples and `git diff --check`; detection suites are
  needed when the corresponding code or fixtures change.
- Record user-visible changes in [CHANGELOG.md](CHANGELOG.md). Bump and synchronize all three plugin
  manifests for a new package release; unreleased documentation edits do not change the package version.
- Before publishing a package, run `claude plugin validate .`, then install the local marketplace
  in a separate Claude Code test environment and check the documented audit flow.
- Before public release, verify that GitHub private vulnerability reporting is enabled and the
  private report link in [SECURITY.md](SECURITY.md) works for a signed-in reporter.

## Reporting and test safety

Open an [issue](https://github.com/Vilintritenmert/instinct/issues) for ordinary bugs and false
positives, with the version, command, expected behavior and a minimal sanitized sample. Sensitive
vulnerabilities and bypass details follow [SECURITY.md](SECURITY.md).

Tests contain deliberately malicious instructions, hooks and scripts. Read them as data; never
install fixtures or execute their payloads. Keep new samples inert with `example.invalid` and
reserved documentation IP ranges. Never include real credentials, personal data or working endpoints.
