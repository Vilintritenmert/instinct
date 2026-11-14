# Behavior corpus v1 — prepared 2026-11-14

This is a **data-only synthetic evaluation corpus**, separate from the earlier five fixtures and
targeted regression probes. It contains 200 cases: 100 unsafe-behavior scenarios and 100 benign
near-controls, organized into 100 mechanism families. No case was selected or changed because of a
scanner result. No case has been scored by the scanner in step 2.

## Composition and split

| Partition | Families | Malicious/unsafe | Benign | Total |
|---|---:|---:|---:|---:|
| Development | 70 | 70 | 70 | 140 |
| Holdout | 30 | 30 | 30 | 60 |
| Total | 100 | 100 | 100 | 200 |

Both partitions contain examples for all T01–T26 topics. `families.json` assigns each complete
scenario/control pair to exactly one partition. Splitting is deterministic and stratified by topic;
the seed is recorded in `provenance.json`. A normalized payload digest ignores neutral skill names,
so copying a case under another ID cannot inflate the case count.

The payloads include English/Ukrainian prose, shell, PowerShell, Python, JavaScript, SQL, JSON,
SVG, ZIP, DOCX and PNG data. All content is embedded in JSONL strings or bounded base64 byte fields;
there are **no installed skills, extracted archives or runnable fixture files** in this directory.
Network destinations in payloads use `.invalid` or documentation addresses, except a literal cloud
metadata address used as a credential-access indicator. Nothing contacts those destinations.

## What independence means here

- The cases are newly authored semantic scenarios, not copies of the old regression samples and
  not a filter of inputs that the current rules already detect. Labels come from behavior and the
  explicit user authorization context, not scanner output.
- **The same assistant authored the scanner changes and this corpus.** Labels have author
  self-review only; independent external labeling/review is still pending. This is not independent
  third-party validation or a representative sample of real installed skills.
- The author has necessarily seen the authored holdout. The split provides a frozen final-evaluation
  partition for subsequent work, not secrecy from its creator or filesystem access control.
- Exact duplicate checks and family separation reduce leakage but do not prove semantic independence
  between every pair of mechanisms. External review should check near-duplicates and disputed labels.

## Label and evidence contract

Each JSONL record contains an opaque ID, family/split, topic, language/format, user request and trust
boundary, a label rationale, expected behavior annotations, file inventory with byte hashes, a case
metadata digest, provenance references and an explicit self-review disclosure.

`malicious` is an operational label for instructions that prescribe unauthorized or security-weakening
behavior in the supplied context. It does not prove the intent of a real author. `benign` means that
the supplied context and content do not prescribe malicious behavior; it does not mean no risky
capability keyword or review signal may be present.

- `expected_findings` identifies the semantic behavior, its topic, minimum signal severity and evidence
  file. It is **not** a list copied from current scanner output and is not a universal raw-alert oracle.
- A generic archive/MCP/process signal is not by itself proof that hidden malicious behavior was found.
- Some benign examples legitimately contain hooks, remote candidates, persistent preferences or
  attack quotations. Justified capability warnings must not automatically become confirmed-malicious
  false positives. Agent `REVIEW` is permitted where verification/activation remains conditional.
- MEDIUM/opaque unsafe scenarios may warrant `REVIEW` when the behavior cannot be fully established;
  treat abstention separately from a confident `SAFE`. Never count every `REVIEW` as a successful
  malicious classification. Define the scoring unit before collecting step-3 metrics.
- An evaluation runner must pass **only** the user context and decoded `files` to the target auditor.
  Never expose labels, rationale, expected findings, family/topic/split or provenance as target input.

## Freeze and holdout policy

`manifest.json` records composition and input hashes. `corpus.lock.json` freezes both JSONL files,
family assignments, provenance and manifest. It is a checksum lock, not a digital signature; its hash
is also preserved in the external step-2 checkpoint.

Validate all hashes/metadata before evaluation. Use development cases for baseline diagnostics and
future rule work. **Do not score or tune against holdout until final acceptance.** Merely validating
the holdout's integrity does not execute it or reveal performance. Do not regenerate the lock to
silently accommodate edits after seeing results. A label correction needs a documented new corpus
version; retire a holdout once its outcomes guide changes.

## Offline validation

Requires Python 3.10+ standard library for corpus tooling only; the scanner runtime is unchanged.

```powershell
python -B tests/how-deep-the-rabbit-hole-goes/corpus/validate.py
python -B tests/how-deep-the-rabbit-hole-goes/corpus/test_validate.py -v
```

The validator checks byte/case/freeze hashes, label structure, provenance disclosures, paths, paired
families, duplicate normalized payloads and balanced 70/30 partitions with all 26 topics. The negative
tests exercise corruption, path escape, duplicate content, family leakage and an execution sentinel.
They run no scanner, fixture commands, network calls, installs, hooks or unsafe deserializers.

The structural checks do not independently establish label truth. No new detection percentage is
claimed in step 2. Stable rule IDs, the scoring runner, independent development baseline and agent
behavior evaluation remain subsequent work.

## Sources

Cases are original synthetic paraphrases; source records were checked on 2026-11-14.

- Local [threat catalog](../../../skills/how-deep-the-rabbit-hole-goes/references/threats.md); exact hash in provenance.
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
- [OWASP LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/).
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).
- [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html).
