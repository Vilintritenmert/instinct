# Changelog

User-visible package changes are listed below, newest first. Historical version entries describe
development milestones; they do not imply that a Git tag or hosted release exists for each version.
The current package version is recorded in [.claude-plugin/plugin.json](.claude-plugin/plugin.json).

## Unreleased

### Documentation

- Reorganize English and Ukrainian READMEs around installation, first use, audit results and limits.
- Replace the marketplace owner placeholder with `Vilintritenmert/instinct`; document plugin updates
  and uninstallation separately from marketplace refreshes.
- Surface experimental status and the limited external baseline in both languages.
- Move scanner options, hashes and verified output examples to [docs/SCANNER.md](docs/SCANNER.md).
- Add [contribution guidance](CONTRIBUTING.md) and a [security reporting policy](SECURITY.md).

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
