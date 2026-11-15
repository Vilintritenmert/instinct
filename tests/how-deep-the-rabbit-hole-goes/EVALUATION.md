# Reproducible scanner measurement

Requires PowerShell 7, Python 3.10+ and Git for the checkout-integrity regression test. The evaluator
uses the Python standard library. It installs nothing and runs no target commands. All measurements
are offline once the pinned external corpus is present.

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/evaluate.py --output work/evaluation
```

The default runs **140 local development cases and all 116 deepset public test rows**. `--suite
development` and `--suite external` select one dataset. No local holdout option exists: the 60 local
holdout cases are integrity-checked, never scanned. Choose a fresh output path; earlier results are
never overwritten. Exit 0 means the evaluation completed, not that detection quality passed a gate.
Input/integrity/process errors exit nonzero and remain explicitly unassessed.

## Metrics fixed before the external baseline

`evaluation-policy.json` fixes HIGH+ as the primary raw-alert threshold and MEDIUM+ as a secondary
threshold. Case-level TP/FN/FP/TN compare alert presence with supplied labels. These are signal metrics,
not automated SAFE/UNSAFE agent verdicts. A benign hook can legitimately produce a review warning.
Errors are not counted as TN; incomplete negatives remain explicitly unchecked, never SAFE.

- Expected topic plus minimum severity, anywhere in the target, is separate from the stricter annotated
  evidence-file match. Missing annotation is unassessed, not a successful detection.
- Minimum severity annotations allow higher findings. They cannot establish over-severity accuracy.
  An optional expected finding's `severity` field permits exact correct/under/over/not-detected scoring;
  `minimum_severity` alone scores threshold compliance. Both current real corpora lack exact severity.
- The report records every miss, benign-label alert, triggered RuleId, severity distribution, error and
  unchecked file/reason. Category-level expected-signal results exist only where labels provide them.
- No corpus labels, rationale, expected findings, topics or provenance enter the scan target. Only
  embedded file bytes are materialized in an owned temporary directory and checked before/after scans.

`report.md` is the human report; `summary.json` is the unified machine report. `cases.jsonl`,
`cases.csv`, `findings.csv`, `errors.json`, `raw/`, `rule-coverage.json`, `run-policy.json`,
`inputs-lock.json`, `rule-catalog.json` and `artifacts-sha256.json` retain evidence. Spreadsheet exports
escape formula-leading evidence. No untrusted target text is embedded into the Markdown report.

## Independent external corpus: what is and is not established

[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), revision
`4f61ecb038e9c3fb77e21034b22511b523772cdd`, has a public test split with **60 positive and 56 negative
labels**. The complete split is retained without scanner-based selection or label changes.

The importer verifies the dataset viewer's `x-revision` header, row indices, counts and truncation,
retains both raw pages and the pinned upstream Parquet/card, and freezes all bytes in `lock.json`.
Evaluation rechecks the adapter against original text/labels and verifies checksums. Refetch only to
a fresh directory, using an explicitly invoked network operation:

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/fetch_external.py --destination work/deepset-refetch
```

These texts and labels were sourced independently of this scanner's author. This does **not** establish
independent adjudication, absence from model pretraining or a blind/private holdout. English/German
prompt-injection text is narrower than installed skills, executable configurations and T01–T26. User
authorization/system context and threat/severity annotations are absent; some role-play labels may
not transfer directly to a skill-auditing task. Keep upstream labels and disclose this limitation.

The upstream card declares Apache-2.0 at top level and CC-BY-4.0 inside dataset metadata. Both original
declarations and attribution are retained; this project does not resolve that discrepancy. Do not
claim externally measured CWE/OWASP or severity accuracy when those annotations do not exist.

## Stable rule identity

```powershell
pwsh -NoProfile -File skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1 -ListRules
```

Every finding has `RuleId` and its broader `Threat`. IDs are explicit, not derived from rule position,
regex text or evidence. The current catalog (0.11.0) has **171 pattern rules and 58 structural checks**.
`Txx-001` through `Txx-899` identify pattern rules; the `Txx-9xx` range identifies structural checks.
New rules receive unused IDs; do not renumber, reassign or reuse retired IDs. Pattern IDs live beside
their definitions; `references/structural-rules.json` supplies structural metadata. `-ListRules`
exports the catalog without reading a target. JSON schema/tree-hash stay at 2; additive catalog fields
are `RuleCatalogVersion: 1`, `RuleCatalogSha256`, and `Findings[].RuleId`.

Rule hits/unhit IDs are observations, not branch or vulnerability-class coverage. Context adjustments,
normalization, decoding and suppressed extra-match summaries retain the originating pattern ID.
Combined checks have their own structural ID. A changed catalog hash identifies catalog changes;
stable IDs still support comparisons after a rule is deliberately revised.

`--baseline <previous cases.jsonl>` requires the same case metadata/payload hashes and compares finding
behavior with RuleId omitted. `--allow-legacy-scanner --scanner <old scan.ps1>` is only for recording
a pre-ID reference; it does not silently relax ID validation on current scans.

## Validation

The 0.11.0 second development source (`--suite paraphrase --paraphrase-root
tests/how-deep-the-rabbit-hole-goes/paraphrase-development-v2`) and its before/after results are in the
"Round 2" section of [CONTEXT_REVIEW.md](CONTEXT_REVIEW.md); its expected composition is read from its
frozen lock. The 0.10.0 trust-context review and separate development source are documented in
[CONTEXT_REVIEW.md](CONTEXT_REVIEW.md). They add conditional sidecar annotations and an explicit
`--suite paraphrase`; the default 256-case cohort, original labels and frozen policy stay unchanged.
Run `test_review_context.py -v` for review integrity, disagreement and denominator safeguards.

```powershell
pwsh -NoProfile -File scripts/validate.ps1
pwsh -NoProfile -File tests/how-deep-the-rabbit-hole-goes/run.ps1 -SecurityReportPath work/security.json
python -B tests/how-deep-the-rabbit-hole-goes/test_evaluate.py -v
python -B tests/how-deep-the-rabbit-hole-goes/corpus/test_validate.py -v
```

`.gitattributes` prevents line-ending conversions in both frozen corpora. The measurement tests verify
a local Git checkout with `core.autocrlf=true`, without touching this repository's index or invoking
hooks. Rule reordering checks require the same catalog and findings. Windows is verified; macOS/Linux
remain separate validation work. Do not tune against this external baseline in the measurement change.
