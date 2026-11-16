# Detection coverage and evaluation contract

This skill audits agent instructions and their packaged code. It is a heuristic static scanner plus
manual review, not a general application SAST engine or a protection boundary. All target content,
including JSON and decoded text, is data. Nothing from a scan target is installed or executed.

## Scanner contract (schema 2, tree-hash version 3)

- `Findings` and exit codes are signals, not SAFE/UNSAFE verdicts. Exit 0 means no HIGH/CRITICAL signal.
- `ScanComplete` is false if enumeration, reading, hashing, decoding or a regex is incomplete, or
  opaque content, images or links remain uninspected. Review every `CoverageIssues` entry.
- `ScanComplete: true` means the supported static passes completed. It says nothing about semantic
  completeness or the absence of novel attacks. The agent still has to read the target.
- `Components` contains command/URL candidates with file and JSON path, not verified auto-run behavior.
  Shell `-c` consumes one script argument; literal pipes in non-shell arguments are not reconstructed
  as shell operators. External component-path declarations and runtime interpolation need manual review.
- The tree hash includes type, size, path and byte digest; a link's digest covers its destination text.
  JSON serialization avoids newline/delimiter ambiguity. It does not read a link target. A missing byte
  hash or an unenumerated directory makes `TreeHashComplete` false and `TreeHash` null.
- Paths are sorted ordinally (by UTF-16 code unit), not by the auditor's locale, and use `/` on every
  OS. The same bytes give the same hash on Windows, macOS and Linux and in every locale. The hash
  covers exact bytes, so a checkout with converted line endings (git `core.autocrlf`) or with symlinks
  written as plain files (the Windows default) is a different tree. On macOS/Linux a `\` in a file name
  stays part of the name.
- Version-1, version-2 and version-3 tree hashes are intentionally incompatible. Version 3 changed the
  sort order and counts extensionless shebang files as scripts. Rebaseline after upgrading.
- An empty file is hashed without being opened. PowerShell and .NET report named pipes, devices and
  sockets as empty regular files, so on macOS/Linux each empty entry is checked with the system's
  POSIX `find -type p/c/b/s` and reported as T19-919. Without `find`, the zero-size guard still keeps a
  FIFO from blocking the scan, but the entry is not identified.
- Target files and folders are walked and hashed through .NET, not PowerShell path cmdlets. Those
  cmdlets treat `\` as a separator even on macOS/Linux, which hid such files and folders from the scan.
- Findings are listed in a total ordinal order (severity, threat, file, line, rule, note, evidence), so
  the same target produces the same output on every OS and in every locale.
- Text digests cover the bytes actually scanned. The filesystem is not locked: concurrent changes,
  hard links, intermediate-path link swaps and races still require a stable copy for strong assurance.
- Text decoding supports strict UTF-8 and BOM-tagged UTF-16/32 LE/BE. Other encodings are not guessed.
- Base64 analysis is bounded to two layers, 20 tokens and 64 KiB decoded text per input line; a token
  above 32 KiB is not decoded. Hitting these bounds creates an explicit coverage gap. Files above
  20 MiB are not read or hashed. There is no total wall-time or file-count budget yet.
- Each rule examines at most 32 non-overlapping matches per line, choosing the highest contextual
  severity rather than trusting the first match. Exhaustion creates a coverage issue. Prose action
  patterns respect clause boundaries; T11 also recognizes an explicit `; skip review` continuation.
  A prohibited first action cannot swallow a separate later insertion or private-transfer action.
- Context lowering covers narrow literal role examples, guarded miner glossaries, non-secret named
  environment reads, numeric-only Node memory options and local explicit prohibitions. It is heuristic,
  not a grammar parser. Dynamic environment access, loader flags and later positive actions retain risk.
- HIGH behavior signals now cover private transfer syntax, approval bypass, risky install commands,
  concealed actions and unreviewed mutable dependencies. T22 correlation uses at most three nearby
  lines or a sensitive-export-named call in a negative CI branch. Neither names nor proximity prove
  taint, reachability or lack of authorization. Independently review these findings.

## Regression evidence

### Agent and OS portability (0.12.0)

The catalog now has 232 entries (172 patterns, 60 structural), preserving all 229 earlier IDs. One new
pattern (T21-006, Gemini CLI `!{…}`) and two structural checks (T19-918 folder metadata, T19-919 special
files) were added. Existing structural checks now also recognize other agents' MCP, settings, command and
always-loaded instruction files. The full list is in `threats.md`, under "Agent- and OS-portability
additions in 0.12.0". All five original fixtures keep identical findings. The new sort order changes
the tree hash of `evil-skill`, `evasion-skill` and `benign-skill`; `evil-plugin` and `clean-skill` keep
theirs. The frozen evaluation is unchanged: development TP 53 / FN 17 / FP 4 / TN 66 and external
TP 1 / FN 59 / FP 0 / TN 56. A locale probe shows the old scanner gave three different hashes for one
tree under `en-US`, `lt-LT` and `sv-SE`. The new one gives one hash, the same as in .NET's
invariant-globalization mode.

Platforms: Windows 11 and Ubuntu 24.04 (WSL 2, ext4), both with PowerShell 7.7.0. On Windows the
suite gives TP 115/115, FP 0/67 and robustness 19/19, with the Unix-only probes skipped. On Linux it
gives TP 115/115, FP 0/67 and robustness 22/22: a `\` in file and folder names, a FIFO, root symlinks,
locales, and the `scan.sh` wrapper returning the scanner's exact JSON and exit code. The wrapper also
passed 21 option, error and PowerShell-discovery checks under both dash and bash. The Linux run was repeated for a byte-identical copy of the Windows CRLF checkout and for
an LF clone. For each checkout pair (Windows CRLF / Linux copy, Windows `core.autocrlf=false` / Linux
clone), the scanner JSON for all five fixtures is byte-identical apart from the absolute `Target` path.
The Linux run exposed two bugs that Windows could not show, both fixed: PowerShell path cmdlets turned
`\` into `/`, and PowerShell's `UnixMode` reports a FIFO as a regular file. macOS is not yet verified.

### Round-2 hijack mechanisms (0.11.0)

The catalog now has 229 entries (171 patterns, 58 structural), preserving all 220 earlier IDs. Nine
rules (T01-013…T01-020, T06-018) cover instruction reset, task replacement, rule-free personas, forced
output, fake system turns, text addressed to any AI and setup/hidden-instruction disclosure in English,
German and Ukrainian. A second separately authored, frozen 80-case source was reviewed blind (80/80
agreement). It improved from TP 4 / FN 36 / FP 2 / TN 38 to TP 38 / FN 2 / FP 1 / TN 39 at HIGH+;
this is tuned development evidence. All earlier 256 cases keep identical findings, including external
TP 1 / FN 59 / FP 0 / TN 56; no installed user skill gained a finding.

### Trust-context review and paraphrases (0.10.0)

The catalog now has 220 entries (162 patterns, 58 structural), preserving all 212 old IDs.
Eight new rules cover explicit higher-trust invalidation and protected-context requests. A separately
authored, frozen 60-case development source was reviewed blind before scanning. It improved from
1/30 to 30/30 positive detections with 0/30 HIGH+ benign alerts; this is tuned development evidence.
The original 256-case findings/coverage are unchanged, including external TP 1 / FN 59 / FP 0 / TN 56.

Two isolated AI reviewers assessed all 116 external texts without original labels or scan outcomes.
Source context is undocumented for every row. Types/severities are explicitly conditional on direct
user versus untrusted-reference placement; all actual source-context/severity ground truth remains
unassessed. Disagreements are retained, and all 59 original misses stay in a fixed-cohort ledger.
These reviews do not establish independent human/expert labels. See the measurement context guide.

183 regressions, 15 measurement tests, 10 review-integrity tests and 12 original corpus tests pass;
27 additional independent AI probes exercised precision and callback boundaries. Phrase/frame
heuristics are bounded and English/Ukrainian-focused. Longer references, code purpose, source claims
and undocumented authorization still need manual review. Local holdout, upstream labels and thresholds
are unchanged; frozen inputs are not rewritten after outcomes.

### Stable IDs and measurement (0.9.0)

All 212 checks have explicit `RuleId` identities: 154 patterns and 58 structural checks. Findings,
including normalized/decoded signals and extra-match summaries, carry an ID. The target-independent
`-ListRules` export includes a catalog version/hash; scanner JSON includes the same fingerprint.
IDs remain stable under reordering, while changed catalog contents change the catalog hash.
The JSON/tree-hash schemas remain 2; these are additive fields. Never renumber or reuse an ID.

The offline evaluator and fixed policy are in `tests/how-deep-the-rabbit-hole-goes/evaluate.py` and
`evaluation-policy.json`. It separates raw threshold alerts, expected topic/file signals, errors,
minimum severity compliance, exact severity accuracy and unchecked content. Unknown annotations are
unassessed. Exact severity accuracy is unavailable on both current corpora; their minimum annotations
and binary labels must not be substituted for exact severity labels. See the measurement guide for
the pinned external source, complete-split selection, independent-sourcing limits and license metadata.

The local 60-case holdout remains unscored. `.gitattributes` preserves both frozen corpora's bytes
across checkout line-ending settings. No detection rule or severity threshold was tuned against the
external baseline in this measurement change.

`tests/how-deep-the-rabbit-hole-goes/run.ps1` runs the original fixtures and `security-regressions.ps1`.
The latter creates inert text in a unique local scratch directory, scans it and deletes it. Addresses
use `example.invalid`; no fixture is executed and no remote endpoint is contacted.

The additional suite has targeted positive and negative controls for negation, escaped JSON,
argument boundaries, BOM encodings, nested/normalized base64, Ukrainian wording and tool wildcards.
Development-driven controls also cover the context refinements and behavior rules cataloged under
"Development-driven additions in 0.8.0" in `threats.md`, including benign-first/attack-later lines.
It also checks completeness reporting, malformed input handling, hashes, severity filtering and links.
Link probes are explicitly skipped if the host prevents link creation; they must be run on a capable
host before claiming verified link behavior. `-MeasureOnly -Scanner <old scanner>` measures the same
cases against a baseline; `-ReportPath <file>` saves per-case evidence and scoped TP/FN/FP counts.

These cases deliberately stress known bypasses. Counts are not population estimates, and a passing
category is not full rule, branch, code coverage or robustness against paraphrasing. The original
benign and clean fixtures remain separate controls. Agent behavior under injection, real-world
benign corpora, macOS and Linux have not been evaluated by this change.

## Threat-category regression map

Each T01–T26 category has a positive assertion across the two suites. A named assertion can cover
more than one category; most categories still have only a few examples.

| Categories | Positive fixture/probe |
|---|---|
| T01–T12, T16, T20 | `evil-skill` expected threat list; evasion and focused probes refine selected rules |
| T13, T21–T26 | `evil-plugin` expected threat list |
| T14 | `external-action-smoke` |
| T15 | `telemetry-smoke` |
| T17 | `path-traversal-smoke`, root-link isolation |
| T18 | `resource-loop-smoke` |
| T19 | `evasion-skill` disguised extension and image trailer assertions; opaque-content completeness; `ds-store-metadata`, `fake-ds-store-stays-binary`, `macos-command-launcher` |
| T21, T23 (other agents) | `gemini-extension-mcp`, `gemini-command-shell`, `cursor-rules-instructions`, `copilot-instructions` |

## CWE / OWASP interpretation

OWASP identifiers below intentionally refer to the **2025 LLM Applications** edition already used by
this catalog. CWE references describe related attack mechanisms or review areas, not assigned CVEs.
Broad classes such as CWE-200/400 are conceptual coverage labels, not precise root-cause mappings.

| Area | Related CWE | OWASP LLM 2025 | Evidence and remaining limitation |
|---|---|---|---|
| Instruction hijacking, hidden content, auditor deception | [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) | [LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | T01/T02/T20 positive fixtures; encoding evasions improved; semantic paraphrases and image pixels remain manual |
| Secret access, disclosure and embedded credentials | [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [LLM02](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/), LLM07 | T06/T07 and negation probes; no taint/data-flow proof; legitimate credential tooling can trigger signals |
| Download/execute and unsafe deserialization | [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | [LLM03](https://genai.owasp.org/llmrisk/llm032025-supply-chain/) | T05/T10/T11 and parsed JSON; patterns are not proof of OS-command injection in arbitrary application code |
| Canonicalization bypasses | [CWE-180](https://cwe.mitre.org/data/definitions/180.html) | LLM01, LLM03 | Unicode, decoded JSON and two base64 layers; arbitrary compression/obfuscation remains unsupported |
| Outside paths, link traversal, excessive capabilities | [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | T04/T08/T09/T13/T14/T17/T24/T25; root links not followed; no race-free filesystem confinement |
| Resource abuse | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | LLM10 | T18 smoke probe and bounded decoding; no complete DoS analysis or overall scanner runtime budget |
| Poisoning, generated output, misleading reports | Context dependent | LLM04, LLM05, LLM09 | T03/T23/T26 positive fixtures; mostly requires human semantic review |
| Vector/embedding weaknesses | Out of scope | LLM08 | No vector store, retrieval model or embedding evaluation in this repository |

The scanner also does not establish general web-app coverage for SQL injection, XSS, SSRF,
authorization, cryptography or vulnerable dependency versions. Those require separate analyzers and
context. No network threat-intelligence/database lookup is performed.
