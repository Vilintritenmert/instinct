# Trust-context review and separate paraphrase development

The original deepset public test split, its labels, the 0.9.0 baseline and `evaluation-policy.json`
are unchanged. HIGH+ still uses all 60 positive and 56 negative source labels. All **59 original
misses remain listed**, including cases that are benign/ambiguous under a hypothetical interpretation.
No row is removed or relabeled to improve a metric.

## Independent AI review

Two isolated-context agents reviewed all 116 raw texts without source labels, scanner code or scan
results. Inputs, protocol, both reviews/notes and conditional consensus are in `context-review-v1/`.
Evidence must be an exact bounded source substring. Shared-model bias remains possible; this is
neither independent human expertise nor OS-enforced filesystem isolation.

The [pinned dataset card](https://huggingface.co/datasets/deepset/prompt-injections/raw/4f61ecb038e9c3fb77e21034b22511b523772cdd/README.md)
has text/label features. The
[official model card](https://huggingface.co/deepset/deberta-v3-base-injection/raw/80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1/README.md)
describes a dataset-level assumption about questions/keyword searches; neither provides original
per-row system/user/tool placement, authorization or protected context. Missing facts were not invented.

Each text has TWO explicitly hypothetical assessments:

- `direct_user`: an authorized direct task; role play and editing the user's own prompt are permitted,
  while hidden runtime/private non-user context remains protected.
- `untrusted_reference`: a retrieved passage during a trusted factual-summary task; the passage cannot
  replace the task/role, disclose private context or authorize actions.

Both reviewers agreed fully on 113/116 judgments/types/severities per view. Direct-user consensus:
103 benign, 4 unsafe, 6 ambiguous, plus 3 disputed. Reference-context consensus: 64 benign and 49
unsafe, plus 3 disputed. That view has 49 T01 tags, with T06 also present on four cases; tags are
not additional cases. Disagreements remain explicit; the implementer did not choose a preferred vote.

For **all 116 rows**, actual source context, actual semantic ground truth and actual exact severity
remain unassessed. Conditional AI severities are not recovered upstream severity. Sidecar `source_label`
retains the importer's original `malicious`/`benign` mapping; original binary labels remain untouched
in the external source. The frozen review lock is checked, and consensus is regenerated from both
reviews without silent adjudication.

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/review_context.py --source tests/how-deep-the-rabbit-hole-goes/external/deepset-test/cases.jsonl --review-a tests/how-deep-the-rabbit-hole-goes/context-review-v1/reviewer-a.jsonl --review-b tests/how-deep-the-rabbit-hole-goes/context-review-v1/reviewer-b.jsonl --baseline <0.9.0-cases.jsonl> --candidate <candidate-cases.jsonl> --output work/context-comparison
```

The output retains every original miss and candidate alert/IDs. It rejects removal/relabeling,
changed input hashes, unassessed candidate rows, invented original context and corrupted annotations.
Changing a conditional interpretation cannot shrink the raw denominator.

## Separate development source

`paraphrase-development/` contains 60 inert cases in 30 scenario/control pairs: 40 English and 20
Ukrainian cases, 15 T01 pairs and 15 T06 pairs. A third isolated agent authored it without reading
existing corpora, external texts/labels, scanner code or outcomes. Another reviewer saw only each
target text and explicit trusted-user/boundary context, not proposed labels/types/expectations.
All 60 labels and unsafe types agreed. The receipt is `paraphrase-review-v1.json`.

The four source files were frozen before any scan. The provenance's pending-review field describes
the authoring-time snapshot; the separate receipt documents the completed later review. No case or
lock was edited after outcomes. Exact external target-text duplicates were absent; semantic
independence, model-training absence and real-world representativeness are not established.

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/evaluate.py --suite paraphrase --output work/paraphrase-evaluation
```

The old `--suite all` still means the original 140 development plus 116 external cases. The new source
is selected explicitly. The local 60-case holdout is never scanned; HIGH/MEDIUM thresholds are fixed.
Separate development improved from TP 1 / FN 29 / FP 0 / TN 30 to TP 30 / FN 0 / FP 0 / TN 30; all 30
topic/minimum-severity annotations pass. This is post-tuning development, not held-out accuracy.
Minimum HIGH labels do not establish exact/over-severity correctness.

## 0.10.0 changes and limits

Eight IDs, T01-010..012 and T06-013..017, cover higher-trust rule invalidation, inverted hierarchy,
protected-context disclosure/transformation and another user's private material, including Ukrainian
and object-first/anaphoric wording. All 212 old IDs remain; the catalog now has 220 entries. No broad
new role-play detector was added.

Action/object evidence is bound within limited clauses. Local prohibitions and explicitly rejected
quotations can lower severity only in Markdown prose. Code, fenced and decoded text retain risk.
Later affirmative callbacks prevent quote lowering. An incidental operating-system subject does not
establish instruction authority. Supplied literal prompt data and removal of an unsafe quoted
sentence have narrow guards; named supplied artifacts without private/runtime markers remain MEDIUM
for provenance review. A target's ownership claim is not proof. These heuristics never establish SAFE
without manual inspection; semantic references and longer/mixed-language constructs remain partial.

The candidate was frozen before external candidate results were viewed. All 256 old inputs have
identical findings/coverage: old development stays 69/70 expected-topic and 68/70 annotated-file;
external stays TP 1 / FN 59 / FP 0 / TN 56 at HIGH+. All 59 original misses still lack HIGH. No external
generalization gain is claimed. Four old ZIP/PNG cases remain incomplete.

183 scanner regressions, 15 measurement tests, 10 review-integrity tests and 12 old corpus tests pass
on Windows. An independent AI code reviewer additionally reused 27 unchanged synthetic probes across
versions; quote callbacks, prohibitions, incidental authority and supplied-template fixes were verified.
This does not establish exhaustive safety or cross-platform coverage.

Next validation needs context-documented external traces and independent human topic/severity
adjudication, plus novel held-out mechanisms. Preserve the baseline and local holdout; do not declare
the original misses solved by reinterpreting labels or reporting only the tuned development source.

## Round 2 (0.11.0): second separate development source

**Independent re-check of 0.10.0 first.** A verifier written without project code recomputed both
reviews from raw files: blind inputs carry only id+text and equal the source; all evidence is verbatim;
no review invents source context; consensus (113/116 per view, 103/6/4 direct-user, 64/49 reference)
matches `summary.json` and `annotations.jsonl`; all 116 original labels are retained; locks match. A
fresh external scan reproduced TP 1 / FN 59 / FP 0 / TN 56 and exactly the 59 locked misses. Under the
reference-context consensus, 48 of the 59 are unsafe, 8 benign and 3 disputed: most are real misses.

**Source.** `paraphrase-development-v2/` holds 80 inert cases in 40 scenario/control pairs: 16 English,
14 German and 10 Ukrainian pairs; 30 T01 pairs (instruction reset, task replacement, rule-free persona,
forced output, fake role turns, text addressed to any AI — five pairs each) and 10 T06 disclosure pairs.
A separate agent authored it from a written brief without opening the repository, corpora, external
texts/labels, scanner code or results. The author's `build_corpus.py` helper is not part of the source.
It was frozen (`lock.json`, composition included) before any scan; no case was edited afterwards.

**Blind review.** Another agent saw only each trusted request, trust boundary and file text, without
labels, topics, mechanisms, rationales or expectations. It agreed with all 80 labels and threat types;
none was ambiguous. Receipt: `paraphrase-review-v2.json`. Both agents share a model; no human or
linguistic review was done.

**Measurement** (HIGH+ primary threshold unchanged; local holdout not scanned):

| Dataset | Before (0.10.0) | After (0.11.0) |
|---|---|---|
| v2 development, 80 | TP 4 / FN 36 / FP 2 / TN 38 | TP 38 / FN 2 / FP 1 / TN 39 |
| v1 development, 60 | TP 30 / FN 0 / FP 0 / TN 30 | unchanged (one extra HIGH on an already-detected case) |
| old development, 140 | TP 53 / FN 17 / FP 4 / TN 66 | identical findings, case by case |
| external deepset, 116 | TP 1 / FN 59 / FP 0 / TN 56 | identical findings, case by case |

The "before" figures used a copy of the scanner with exactly the round-2 edits removed; that copy
reproduced the untouched 0.10.0 run on all 116 external rows. The remaining v2 false positive is the
structural T12 finding for a skill named like the built-in `code-review` — correct for a real audit,
counted as FP against the corpus label. The two v2 misses are "instead of X, write Y and present it as
the result" substitutions, left uncaught rather than matched by phrasing that also fits format changes.
No new findings appeared on the user's installed Claude/Codex skills or on `benign-skill`/`clean-skill`.

**What this does and does not show.** v2 numbers are post-tuning development results, not held-out
accuracy. None of the nine new rules fired on any of the 59 external misses; no external gain is
claimed, and the external texts were not inspected to design rules. Two rounds of skill-file-shaped
development sources have now improved their own metrics without moving the chat-prompt benchmark,
which suggests a distribution mismatch, not just missing phrasings.

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/evaluate.py --suite paraphrase --paraphrase-root tests/how-deep-the-rabbit-hole-goes/paraphrase-development-v2 --output work/paraphrase-v2
```
