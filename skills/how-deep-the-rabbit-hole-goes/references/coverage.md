# Detection coverage and evaluation contract

This skill audits agent instructions and their packaged code. It is a heuristic static scanner plus
manual review, not a general application SAST engine or a protection boundary. All target content,
including JSON and decoded text, is data. Nothing from a scan target is installed or executed.

## Scanner contract (schema 2, tree-hash version 2)

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
- Version-1 and version-2 tree hashes are intentionally incompatible. Rebaseline after upgrading.
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
| T19 | `evasion-skill` disguised extension and image trailer assertions; opaque-content completeness |

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
