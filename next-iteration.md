# Next iteration plan: how-deep-the-rabbit-hole-goes

Status as of 2026-11-14: plugin package **0.8.0**, catalog **T01–T26**, JSON schema and tree-hash
version **2**. The regression suite now defines **141 distinct checks**: the original 31 plus 64 positive,
33 negative and 13 robustness checks (including two host-dependent link checks).
The aggregate subprocess-success assertion is not counted again.
The skill, catalog, scanner output and helper scripts are in English.

This document separates work completed in 0.7.0 and 0.8.0 from the remaining plan. A passing targeted regression
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
Stable rule IDs and external label review remain open (step 3). Do not treat every
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
- There is no independent corpus measurement or automated agent-behavior evaluation yet.
- Self-scanning security documentation and malicious fixtures produces expected signals. A scanner
  baseline/difference feature for separating known signals from new ones is not implemented.
- The reporting workflow has not been independently evaluated on representative third-party audits.
- Git still warns about LF being replaced with CRLF; there is no `.gitattributes` file.

Historical observations retained from the 0.6.0 plan: approximately 8 seconds for a 29-file self-scan,
and 65 CRITICAL / 128 HIGH signals on that earlier tree. These figures were not remeasured for 0.7.0
and are not current performance or quality baselines.

Known coverage gaps (from the scanner code and a multilingual check):

- Prose rules target English and Ukrainian. Other languages and mixed-language paraphrases lack
  measured coverage; language-independent code signals can still match. Foreign-language prohibitions
  can cause false alarms and need dedicated positive/negative controls.
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
- **Status:** corpus v1 is frozen and integrity-checked; the author-run development baseline and 0.8.0
  comparison are complete. External label review and independent evaluation remain pending. The holdout has not been scored.

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

### 3.2. Stable rule identifiers
- **What:** give each rule a code like `T05-03` and move the rules out of the script body into a separate
  data file.
- **Why:** a code can be referenced in the report, in the baseline and in tests; a file with 130 rules
  inside the script is already hard to review.
- **Done when:** every rule has at least one positive and one negative example in the tests.
- **Dependency:** easier to do before 3.1.

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
3. **Baseline recorded:** development-only measurements and author triage are retained. Stable rule IDs
   (3.2) and external review remain open; the corpus is not independently authored or blind to its author.
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
