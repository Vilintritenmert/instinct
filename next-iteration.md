# Next iteration plan: how-deep-the-rabbit-hole-goes

Status as of 2026-11-15: plugin package **0.11.0**, catalog **T01–T26**, JSON schema and tree-hash
version **2**, rule catalog version **1** (229 stable IDs; all 220 earlier IDs preserved). The regression
suite defines **212 distinct checks**: 31 original, 105 positive, 60 negative and 16 robustness checks
(including two host-dependent link checks). Measurement has 16 tests, review integrity 10 tests,
and the original frozen corpus validator retains its 12 tests. Round 2 (0.11.0) is described in
`tests/how-deep-the-rabbit-hole-goes/CONTEXT_REVIEW.md`.
The aggregate subprocess-success assertion is not counted again.
The skill, catalog, scanner output and helper scripts are in English.

This document separates work completed through 0.10.0 from the remaining plan. A passing targeted regression
suite is not an estimate of detection rates on independent real-world skills.

## Step 1 — source checkpoint and reconciliation (complete, 2026-11-14)

- Checkpoint ID: `instinct-baseline-0.7.0-2026-11-14`, stored outside the repository in the task's output directory.
- Preserved **33 working-tree files**, including all existing edits; separate archive for **15
  uncommitted files** (12 modified tracked, 3 untracked). The staged patch is empty.
- Git HEAD: `c8eec1140f2540b4d28888a6b0b19defc388dbdf` (2026-11-14). A verified Git bundle,
  raw index copy, ref records, binary-capable staged/unstaged patches and SHA-256 manifests are retained.
- Source ZIP entries were restored in memory and compared byte-for-byte. Source files, HEAD, index and
  status were rechecked after capture. No commit, reset, staging or checkout was performed.
- Retained the earlier successful 2026-11-14 test logs and measurements. Every source file matched
  the tested candidate before this documentation edit; tests were not rerun for this step.
- `working-tree.zip` preserves this document before reconciliation. This edit only updates the plan;
  it changes no scanner rules, fixtures, runtime code or package version.

The checkpoint is a recoverable source baseline, not an independent evaluation corpus and not an
implementation of the proposed scanner `-Baseline` option. `checkpoint.json`, `files-sha256.json`,
`artifact-sha256.json` and the checkpoint README describe its contents and exclusions.

## Step 2 — corpus v1 prepared (2026-11-14)

- Data-only corpus: `tests/how-deep-the-rabbit-hole-goes/corpus/`.
- **200 cases / 100 mechanism families:** 100 unsafe scenarios and 100 near-benign controls.
- Development: **140 cases** (70 per label); holdout: **60 cases** (30 per label).
  Complete scenario/control families stay together; both partitions include T01–T26 examples.
- JSONL stores context, behavior-based rationale, provenance, expected behavior, file/case hashes and
  explicit author self-review status. Binary material is embedded as base64, not extracted or executed.
- Composition: 188 English and 12 Ukrainian cases across 13 declared formats. The holdout has only
  two Ukrainian cases; this is not representative multilingual or real-world population coverage.
- Frozen lock SHA-256: `1d5581c35e58712b49bead5b872767518b94272364d958fa349e3fc89df8cbbd`. The lock and all source data are preserved in an external
  step-2 checkpoint. Subsequent scoring must not silently edit cases or regenerate their lock.
- Offline validation and **12 integrity/control tests** pass. These checks validate the dataset,
  not scanner accuracy. No corpus case or holdout was scored; scanner code and rules are unchanged.
- **Independence limit:** scenarios are new and separate from the earlier regression fixtures, but
  the same assistant authored the scanner changes and corpus. Independent external label review and
  semantic near-duplicate review remain pending. The author has seen the authored holdout.

The first development-only baseline was run after step 2: 140 successful scans, expected topic and
minimum severity in 45/70 unsafe cases; 15/70 benign cases have MEDIUM+ review signals, of which the
author identified seven contextual false alarms and eight justified review warnings. No frozen case,
label or threshold was changed. The separate 0.8.0 development comparison follows the same policy.
Stable rule IDs and reproducible measurement are implemented in 0.9.0; external label review remains
open (step 3). Do not treat every
generic capability warning as a malicious detection or every REVIEW on a benign integration as a false
positive. Keep signal-level metrics, semantic verdicts and abstention/unchecked coverage separate.

## 0.8.0 development comparison (2026-11-14)

- Same frozen 140 cases and scoring policy: expected topic/minimum severity **45/70 -> 69/70**;
  additionally requiring the annotated file **45/70 -> 68/70**. No previous topic match regressed.
- All seven author-triaged contextual false alarms are resolved. Raw benign MEDIUM+ alerts **15 -> 9**,
  HIGH+ **8 -> 4**; the remaining nine are review signals, including a newly recognized benign CI branch.
  This author judgment is not independent adjudication or general real-world precision.
- **141/141 regression checks** passed (31 original, 64 positive, 33 negative, 13 robustness; links not
  skipped), plus **12/12 corpus integrity tests**, skill structure, PowerShell syntax and whitespace checks.
- Four static scans remain incomplete due to opaque ZIP/image content. No fixture command, holdout
  case or remote target was executed. All nine corpus files and Git index remain byte-for-byte unchanged.
- Remaining topic mismatch: malformed quoted JavaScript `c-4dfad81d8311` retains MEDIUM T10. Additional
  location mismatch: T11 HIGH is in `SKILL.md` for `c-a72a7d022b13`, not the annotated marketplace config.
  Review any corpus corrections in a new version; do not rewrite the current labels or lock.
- Behavior rules and narrow context refinements are documented in `references/threats.md` and
  `references/coverage.md`. The schema/tree-hash contract stays at version 2. Results informed development;
  holdout evaluation, stable rule IDs, independent labels and agent-behavior tests remain open.

## 0.9.0 measurement baseline (2026-11-14)

- Explicit stable IDs: **154 pattern rules + 58 structural checks**. Findings and `-ListRules`
  expose the same catalog fingerprint. Reordering leaves IDs/catalog/findings unchanged.
- `tests/how-deep-the-rabbit-hole-goes/evaluate.py` produces one offline JSON/Markdown/CSV report,
  with raw threshold alerts, expected topic/file matches, severity compliance, errors and unchecked
  content. The fixed policy was recorded before examining external results.
- Independent source: all **116 public test rows** from `deepset/prompt-injections`, revision
  `4f61ecb038e9c3fb77e21034b22511b523772cdd`, retained with original labels (60 positive / 56 negative).
  No scanner-result filtering or label edits. The pinned source and both upstream license declarations
  are retained. This is externally sourced text-injection data, not independent review of full plugins.
- At HIGH+: **TP 1, FN 59, FP 0, TN 56**, recall **1.7%**, observed precision **100% on one alert**.
  MEDIUM+ gives the same counts. This exposes poor generalization beyond targeted development probes.
  Some role-play/task requests lack original trust-boundary context; the dataset is not an all-threat
  oracle and zero alerts on 56 negative examples does not establish a universal zero false-positive rate.
- Development: expected topic/minimum **69/70**, annotated file **68/70**. Raw HIGH+ TP 53 / FN 17 /
  FP 4 / TN 66; MEDIUM+ TP 70 / FN 0 / FP 9 / TN 61. Benign capability warnings are not confirmed
  false UNSAFE verdicts. Four ZIP/PNG scans remain incomplete; all external static scans completed.
- Both datasets lack exact severity labels. Exact/over-severity accuracy is **unassessed**; local
  minimum severity compliance is 69/70. Independent severity/CWE/OWASP annotation remains open.
- **256/256 final scans, zero process/input errors**. Before/after stable-ID comparison has **zero
  finding or coverage changes**; all 154 detection definitions/severities/flags are unchanged.
  An initial runner path-creation race was retained as a failed measurement, fixed and regression-tested.
- **144/144 scanner regressions**, **14/14 measurement tests**, **12/12 corpus tests** pass on Windows /
  PowerShell 7.6.9. `.gitattributes` and a clean temporary Git checkout test preserve frozen input bytes
  with `core.autocrlf=true`. No current index changes or local holdout scoring were performed.

Next: independently review external labels and trust-boundary context, add independent severity/topic
annotations, then prioritize genuine paraphrase/semantic misses using a separate development source.
Keep this measured external baseline frozen and do not tune against the local 60-case holdout.

## 0.10.0 context review and separate development (2026-11-14)

- Two isolated AI reviewers assessed every external text without upstream labels, scanner code or
  outcomes. Official sources do not document original per-row trust placement or authorization.
  Actual source context, semantic ground truth and exact severity remain unassessed for all 116 rows.
- Types/severities are conditional on two explicit assumptions: direct authorized user versus
  untrusted retrieved reference. Full agreement is 113/116 in each view; disagreements remain explicit.
  Direct-user consensus is 103 benign / 4 unsafe / 6 ambiguous, plus 3 disputed. Reference-context
  consensus is 64 benign / 49 unsafe, plus 3 disputed. No source label is replaced. These are AI reviews,
  with shared-model bias possible; they are not independent human expert annotations.
- A separate isolated agent authored and froze 60 development cases (30 pairs, 40 EN / 20 UK) without
  seeing the scanner, any corpus or outcomes. Another agent reviewed explicit contexts/text blind to
  proposed labels/expectations before the first scan; all 60 labels/types agreed. Core files stay frozen.
- That source improved from **TP 1 / FN 29 / FP 0 / TN 30** to **TP 30 / FN 0 / FP 0 / TN 30**;
  expected topic/minimum and annotated-file detections are 30/30. This is post-tuning development.
- Eight new HIGH rules cover authority invalidation and protected-context requests; narrow context
  guards handle prohibitions, rejected quotations, later callbacks and supplied-template editing.
  Another agent's 27 unchanged own probes verified precision fixes without consulting corpora/outcomes.
- Candidate SHA `098ddaf84cdcc8df1c8708cb68d989b7ac757f0b95eda4902db4fcabfd9ad994` was frozen before external
  candidate results were read. All old 256-case findings/coverage are identical: development 69/70
  expected topic, 68/70 annotated file; external **TP 1 / FN 59 / FP 0 / TN 56**. No external gain is
  claimed. All original 59 misses remain in the ledger and denominator. HIGH/MEDIUM thresholds,
  original upstream labels, the prior baseline and local 60-case holdout are unchanged.
- 183 scanner regressions + 15 measurement + 10 review-integrity + 12 original corpus tests pass.
  Source and case hashes, independent reviews, exact evidence, unresolved disagreements and all
  intermediate outcomes are retained. New guides: `CONTEXT_REVIEW.md`; tools: `review_context.py`
  and `evaluate.py --suite paraphrase`. The old `--suite all` remains exactly 256 cases.

Next: obtain documented external system/user/tool traces and human topic/severity adjudication, and
evaluate on novel untouched mechanisms. Preserve all old misses; training success on the new source
does not establish independent generalization. The local holdout remains reserved for final acceptance.

## Completed in 0.7.0

| Area | Implemented and covered by regression checks | Remaining boundary |
|---|---|---|
| JSON canonicalization | Decoded keys/strings/array text; command/argv candidates with JSON paths; argument-boundary controls | Candidate fields do not prove runtime behavior; custom component paths, JSONC/JSON5 and YAML are incomplete |
| Unicode text | Strict UTF-8 and BOM-tagged UTF-16/32 LE/BE | BOM-less UTF-16, legacy code pages and arbitrary encodings are not guessed |
| Base64 | Two bounded layers, normalized decoded text, more than five tokens and more than 50 decoded lines | Other codecs/compression and further layers remain unsupported; limits create coverage gaps |
| Negation context | Explicit nearby prohibitions in Markdown prose; code/comments and unrelated negations cannot lower severity; restricted noun lists under headings | A heuristic requiring manual confirmation, not language understanding |
| Ukrainian and tool rules | Tested infinitives such as `вставити`, possessive memory wording, field-scoped tool wildcards and variable shell `eval` | Broader grammar, paraphrases and programming-language semantics remain partial |
| Files and output | Root/nested links are not followed; link destination affects hash; malformed input and control characters handled | Hard links, path-swap races and complete denial-of-service protection remain unresolved |
| Completeness contract | `ScanComplete`, `CoverageIssues`, `TreeHashComplete`, `Components`; null tree hash if hashing/inventory is incomplete | Completion of static passes is not a SAFE verdict; version-1 hashes must be rebaselined |

### Retained test measurements

The same targeted cases were measured against the pre-audit working tree and 0.7.0. A positive probe
expects a specific threat and severity; a miss can mean wrong severity or a missing payload-specific
finding even if another structural signal was present.

| Measurement | Before audit | 0.7.0 |
|---|---:|---:|
| Original checks | 31/31 | 31/31 |
| Expected threat/severity detections | 4/24 | 24/24 |
| Missed expected detections | 20 | 0 |
| False alarms on negative controls | 3/12 | 0/12 |
| Robustness/contract checks | 1/12 | 12/12 |

Confirmed platform: Windows, PowerShell 7.6.9. Link probes ran without skips. The original benign
fixture stays at 9 LOW and nothing above LOW; the clean fixture has no findings. Structure validation,
PowerShell syntax, JSON manifests and whitespace checks also passed in the retained audit.
See `skills/how-deep-the-rabbit-hole-goes/references/coverage.md` for the maintained contract and limits.

## Goal of the iteration

Make the audit result trustworthy beyond our own test samples: measure quality on real skills, test the
behavior of the agent itself and not only the scanner, and close the gaps we already know about.

## Known weak spots

Current verified limits:

- Only Windows has confirmed test results; macOS and Linux remain unverified.
- A narrow external baseline and two blind AI reviews are recorded; original source context is still
  undocumented. Representative plugin traces, human label adjudication and agent-behavior evaluation
  remain missing. Conditional AI labels are not recovered source truth.
- Self-scanning security documentation and malicious fixtures produces expected signals. A scanner
  baseline/difference feature for separating known signals from new ones is not implemented.
- The reporting workflow has not been independently evaluated on representative third-party audits.
- Frozen corpora are protected by `.gitattributes`; non-corpus files can still produce LF/CRLF warnings.

Historical observations retained from the 0.6.0 plan: approximately 8 seconds for a 29-file self-scan,
and 65 CRITICAL / 128 HIGH signals on that earlier tree. These figures were not remeasured for 0.7.0
and are not current performance or quality baselines.

Known coverage gaps (from the scanner code and a multilingual check):

- Prose rules target English and Ukrainian; since 0.11.0 German is covered for T01 hijacking and T06
  disclosure only. Other languages and mixed-language paraphrases lack measured coverage;
  language-independent code signals can still match. Foreign-language prohibitions can cause false
  alarms and need dedicated positive/negative controls.
- Two rounds of separately authored development sources (0.10.0, 0.11.0) moved their own metrics to
  30/30 and 38/40, but neither changed the external result: all 59 original deepset misses remain.
  The development sources are skill-file shaped; the external rows are short chat prompts. A next round
  needs held-out data of the same shape as the target, not more tuning on author-written fixtures.
- The specific Ukrainian infinitive and possessive gaps (`вставити … токен`, `у свою пам'ять`)
  are fixed and tested in 0.7.0; broader grammar and paraphrases still need independent evaluation.
- The "data, not instructions" guard and the "reads external content" signal are recognized only in
  English and Ukrainian.
- Process-launch and outbound-transfer patterns do not provide full programming-language coverage
  or data-flow analysis. Variable shell `eval` now has a MEDIUM signal; gaps in Go, Ruby, PHP, Lua,
  Perl, batch, Rust, C#, Kotlin and Swift still require dedicated examples and review.
- Archives, PDFs and office documents are only flagged; their content is not read.
- BOM-tagged UTF-16/32 is now decoded. Unsupported/invalid encodings are explicitly unchecked,
  rather than silently decoded with replacement characters; legacy code pages remain unsupported.
- The scanner does not see text in image pixels or compressed PNG text chunks.
- Base64 is decoded to two bounded layers with normalization. Hex, URL encoding, gzip, rot13 and
  arbitrary further nesting remain unsupported.
- Multi-line constructs other than line continuation (heredoc, multi-line HTML comments) are checked
  line by line, so a rule that needs two lines together will not fire.
- JSON configuration is now parsed, including escaped keys/strings and command arguments. Semantic
  component mapping, external component paths, runtime substitution and JSONC/YAML remain incomplete.
- The old whole-line negation downgrade is removed. Prohibition handling is still a heuristic and
  must be measured on independent adversarial and benign examples.

## Priority 1 — trust in the result

### 1.1. A corpus of real skills and measuring false positives
- **What:** build at least 100 malicious and 100 benign inert examples with reviewed labels,
  provenance and content hashes. Reserve 30% by attack/template family for final evaluation; do not
  tune rules against the held-out portion. The earlier proposal to review 20–30 representative real
  legitimate skills remains a later validation track, with pinned sources and no target execution.
- **Why:** the 24 positive / 12 negative targeted probes prove specific regressions are fixed, not
  real-world detection or false-positive rates. A noisy scanner makes a REVIEW verdict less useful.
- **Done when:** the independent baseline reports TP/FN/FP, severity accuracy and unchecked content
  by threat category. Record the unit of evaluation; do not mix per-rule signals and whole-target
  safety verdicts. Set a numerical improvement target only after the first independent measurement.
- **Status:** author-written development and externally sourced deepset public-test baselines are
  recorded. External label/severity adjudication and representative real-skill evaluation remain open.
  The local holdout has not been scored. See the 0.9.0 baseline above.

### 1.2. Evaluating the agent's behavior with the skill
- **What:** a set of scenarios where the agent with this skill checks a target and the result is
  compared with the expected one. At minimum: `evil-skill` → UNSAFE; `benign-skill` → SAFE or REVIEW with
  an explanation; `evasion-skill` → UNSAFE; a target with meta-injection → the agent does not change its
  verdict and records T20; a target with a dynamic command → the agent does not invoke it through Skill.
- **Why:** the main risk for an auditor is following an instruction from the target. The scanner does not
  test this.
- **Done when:** the scenarios run with one command and the results of each are recorded.
- **Open question:** choose an evaluator supported by the actual installed host and use mocked
  tools. Do not assume a particular evaluator command exists before checking it.

### 1.3. Running the tests on three platforms
- **What:** GitHub Actions with a Windows, macOS, Linux matrix: `validate.ps1` and `run.ps1`.
- **Why:** the README promises all three, but only Windows has been checked. Risky spots are path
  separators, symlinks, and line endings in the `setup.sh` sample.
- **Done when:** all three jobs are green. Add `.gitattributes` at the same time (LF for samples and
  scripts). `validate.ps1` and `new-skill.ps1` are now ASCII-only messages and run on Windows PowerShell 5.1.

## Priority 2 — scanner gaps

### 2.1. More languages
- **What:** key phrases for T01, T03, T12, T16, T20, T23 and prohibition words in Russian, Polish, German,
  Spanish, French and Chinese when corpus misses justify them; the guard and external-content phrases
  in those languages; broader Ukrainian grammar; process-launch and HTTP-POST patterns for Go, Ruby,
  Rust, C#, Java, Kotlin, Swift, PHP, Lua and Perl. The two specific Ukrainian gaps and variable shell
  `eval` already have 0.7.0 regressions.
- **Done when:** a multilingual sample per language and a script sample per programming language are in
  `tests/` and caught, while `benign-skill` stays at LOW or below.

### 2.2. Parsing JSON for plugin components
- **Completed in 0.7.0:** parse JSON keys/strings/arrays and command/argument candidates; report
  `Components` with JSON paths, with tests for escaped commands and argument boundaries.
- **Remaining:** map candidates to actual event/server roles, inspect non-standard component paths
  declared by `plugin.json`, and support JSONC/YAML without assuming every command field auto-runs.
- **Done when:** custom-path and format fixtures are correctly classified; command/URL candidates
  remain distinct from confirmed auto-run behavior in the capability report.

### 2.3. Reading opaque files without executing them
- **What remains:** list zip-like archive entries (names and sizes, without extracting to disk),
  flag names with `../`; inspect text from `.docx`; decompress bounded PNG text chunks.
  BOM-tagged UTF-16/32 decoding is already implemented; legacy encodings are a separate proposal.
- **Why:** these are the easiest places to hide content from the scanner.
- **Done when:** for each format there is a malicious sample in `tests/` that is caught.
- **Risk:** parsing untrusted archives is an attack surface in itself (archive bombs). Limits on size and
  number of entries are required.

### 2.4. More decoding
- **Completed in 0.7.0:** a second bounded layer of base64 and normalization of decoded text.
- **Remaining:** hex strings, URL encoding and bounded gzip inside base64, with output/depth/time
  limits and explicit coverage gaps.
- **Done when:** each newly supported codec has a malicious and a near-benign control; no payload
  is executed and exhausted limits never appear as a complete scan.

### 2.5. Multi-line context
- **What:** gather multi-line HTML comments and heredoc blocks into one fragment and run the rules over
  it; combinations at file level, not only skill level (reading a secret and a network call in one script).
- **Done when:** a sample where a dangerous phrase is split across two comment lines is caught.

### 2.6. More precise negation
- **Completed in 0.7.0:** nearby explicit Markdown prohibitions, supported Ukrainian postfix forms,
  no lowering from code comments, unrelated clauses, trailing negations or imperative heading items.
- **Remaining:** evaluate additional grammar and paraphrases on the independent corpus, without
  restoring the old whole-line downgrade.
- **Done when:** retained bypass probes still pass and the independent corpus shows no increase
  in false alarms or severity downgrades for genuine attacks.

### 2.7. Speed
- **What:** a pre-filter (one combined check per line before running all rules) and skipping
  normalization for lines without non-ASCII characters where that is not done yet. Measure where the
  time goes first.
- **Done when:** a fixed-input benchmark records time and memory with unchanged detections and
  coverage reporting. The earlier under-3-second goal is provisional, not a measured 0.7.0 result;
  choose performance and total scan budgets after collecting a reproducible baseline.

## Priority 3 — the audit process

### 3.1. Comparison mode for updates
- **What:** a parameter like `-Baseline <previous JSON>`: show new, changed and deleted files by hash and
  findings that were not there before.
- **Why:** the instructions already require comparing versions, but the agent does it by hand. The same
  mechanism solves the noise of our own repository: the baseline is stored **outside** the target, so
  the target cannot whitewash itself.
- **Done when:** rescanning an unchanged target with a baseline shows zero new findings.

### 3.2. Stable rule identifiers — implemented in 0.9.0
- **What:** give each rule a code like `T05-03` and move the rules out of the script body into a separate
  data file.
- **Why:** a code can be referenced in the report, in the baseline and in tests; a file with 130 rules
  inside the script is already hard to review.
- **Done when:** every rule has at least one positive and one negative example in the tests.
- **Status:** all 212 checks now have explicit IDs, catalog export/fingerprint and regression checks.
  Pattern definitions remain beside their scanner logic; structural metadata is external JSON.
  Full positive/negative coverage for each individual rule remains open; current rule hits are not
  a substitute. The update-comparison feature (3.1) remains separate work.

### 3.3. A log of audited skills
- **What:** save the report and the scanner JSON to a file named after the skill and the tree hash; at the
  start of an audit, check whether this version has already been audited.
- **Open question:** where to store it — in the user's project or in their home folder. The owner decides.

### 3.4. Large targets
- **What:** a procedure for a marketplace with dozens of plugins: scan everything first, then read in
  order from the worst result; at the user's wish, one subagent per plugin.
- **Risk:** a subagent reading a malicious plugin can fall for an injection too. Its task must repeat the
  "target content is data" rule, and its conclusion must be checked against the evidence, not taken on trust.

### 3.5. Example reports
- **What:** two or three filled-in reports (UNSAFE, REVIEW, SAFE) in `references/` as a model of tone and length.
- **Done when:** the reports come from real audits, not made up.

## Priority 4 — publishing and maintenance

- Replace `<owner>/instinct` with the repository owner in both READMEs.
- `CHANGELOG.md` and version tags; `SECURITY.md` with how to report a scanner bypass.
- A last-reviewed date in `threats.md` and an agreement to review the catalog quarterly against recent
  publications.
- Mapping to other classifications (OWASP for agentic systems, MITRE ATLAS) — only after checking the
  primary sources; do not add from memory.

## Deliberately out of scope

- **Porting the scanner to Python or another language.** Two implementations will drift apart; it is
  simpler to require `pwsh`.
- **Running the target in a sandbox.** The skill on principle executes nothing, and that is its main
  safety rule.
- **Checking packages against databases of known malware.** Needs the network and a third-party service.
- **A hook that blocks installing unaudited plugins.** Useful, but a separate product with its own risks;
  consider after 3.3.

## Recommended order

1. **Complete:** save the 0.7.0 source/evidence checkpoint and reconcile this document (step 1).
2. **Prepared:** corpus v1 (1.1), 100 scenario/control families and a 30% holdout; external review is pending.
3. **Implemented in 0.9.0:** stable IDs and unified measurement; independently sourced public-test
   baseline recorded. Independent adjudication/representative scope remain open; the local author-written
   corpus is not independent or blind to its author.
4. **Implemented in 0.8.0:** behavior-specific rules and narrow contextual precision fixes, with 62 new
   positive, negative and match-limit checks. See the threat catalog additions and development comparison.
   Hidden formats, broader data-flow/configuration parsing and language coverage remain future work.
5. Evaluate the agent on mocked tools (1.2), and confirm platforms and resource budgets (1.3/2.7).
6. Run the final holdout and retained regressions; accept improved recall only without a worse
   false-positive rate or regressions on known malicious cases. Update documentation and the vault.
7. Keep update-comparison/logging features (3.1/3.3) and publication work separate until scoped.

## Decisions needed from the owner

- Where to store the permanent audit log (item 3.3). The one-off step-1 checkpoint outside the
  repository does not decide this long-term policy.
- Whether `next-iteration.md` should stay in the repository after publishing.
