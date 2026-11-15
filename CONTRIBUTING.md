# Contributing to instinct

instinct is an experimental Claude Code plugin for auditing agent skills and plugins. Read the
[README](README.md), [coverage contract](skills/how-deep-the-rabbit-hole-goes/references/coverage.md)
and [security policy](SECURITY.md) before proposing a change.

## Development setup

- Git for the checkout and checkout-integrity tests.
- PowerShell 7+ (`pwsh`) for the scanner, helper scripts and regression suite.
- Python 3.10+ for evaluation and corpus/review tests; these use the standard library.
- Claude Code with plugin support for manual plugin integration checks.

Run commands below from the repository root. Windows is the verified platform so far; include your
PowerShell, Python and operating-system versions when reporting results on macOS or Linux.

## Repository layout

```text
instinct/
├── .claude-plugin/        plugin and marketplace manifests
├── docs/                  standalone scanner guide
├── skills/                one folder per skill, each with a SKILL.md
├── tests/                 inert fixtures, regressions and frozen evaluation data
├── templates/             template for a new skill
└── scripts/               new-skill.ps1 and validate.ps1
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
  welcome. Maintain `README.md` and `README.uk.md` together when user-facing behavior changes.
- Keep `SKILL.md` short; put long reference material in `references/`. Do not add placeholder skills.
- Audit any third-party or borrowed skill with `how-deep-the-rabbit-hole-goes` before adding it.

## Changing the scanner

A new detection rule needs a threat-catalog entry and a regression with an inert positive example and
a near-benign control. Keep `benign-skill` at LOW or below. Give new rules unused stable IDs; never
renumber, reassign or reuse existing IDs. Update structural metadata for structural checks.

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

- Keep both READMEs aligned on setup, usage, status and limitations. Verify local links and run
  documented read-only examples; keep output excerpts consistent with the current scanner.
- For documentation-only changes, check links, examples and `git diff --check`; detection suites are
  needed when the corresponding code or fixtures change.
- Record user-visible changes in [CHANGELOG.md](CHANGELOG.md). Bump `.claude-plugin/plugin.json`
  for a new package release; unreleased documentation edits do not change the package version.
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
