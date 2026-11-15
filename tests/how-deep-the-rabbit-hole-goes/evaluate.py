"""Offline, read-only scanner evaluation. Targets are data; the local holdout is never scored."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from corpus import validate as corpus_validator

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
SCANNER = REPO/'skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1'
RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    return corpus_validator.read_json(path.read_bytes())


def save(path, obj):
    path.write_bytes((json.dumps(obj, ensure_ascii=False, indent=2)+'\n').encode('utf-8'))


def safe_ratio(numerator, denominator):
    return numerator/denominator if denominator else None


def load_external(root):
    lock = read_json(root/'lock.json')
    if lock.get('schema_version') != 1:
        raise ValueError('Unsupported external lock schema')
    names = [item['path'] for item in lock['files']]
    if len(names) != len(set(names)) or not {'cases.jsonl', 'provenance.json'} <= set(names):
        raise ValueError('Invalid external lock inventory')
    for item in lock['files']:
        corpus_validator.safe_path(item['path'])
        path = root/item['path']
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8*1024*1024:
            raise ValueError('Invalid external input file')
        raw = path.read_bytes()
        if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
            raise ValueError('External input checksum differs from frozen lock')
    provenance = read_json(root/'provenance.json')
    cases = [corpus_validator.read_json(line) for line in (root/'cases.jsonl').read_bytes().splitlines()]
    if len(cases) != 116 or len({case['id'] for case in cases}) != 116 or {c['source_row'] for c in cases} != set(range(116)):
        raise ValueError('External public test split is not complete')
    if Counter(c['label'] for c in cases) != {'malicious': 60, 'benign': 56}:
        raise ValueError('Unexpected external labels')
    # Independently verify adaptation against the retained, revision-checked source pages.
    upstream = [row for name in ('rows-0.json', 'rows-100.json') for row in read_json(root/name)['rows']]
    for case, row in zip(cases, upstream):
        if case['source_row'] != row['row_idx'] or case['files'][0]['content'] != row['row']['text'] or case['source_label'] != row['row']['label']:
            raise ValueError('External adapter changed a source row')
        if case['label'] != ('malicious' if row['row']['label'] == 1 else 'benign'):
            raise ValueError('External label changed')
    return cases, provenance, sha((root/'lock.json').read_bytes())


# Separate development sources: lock corpus id -> dataset name used in reports. v1 keeps its old name.
PARAPHRASE_SOURCES = {'paraphrase-development-draft': 'paraphrase-development',
                      'paraphrase-development-v2': 'paraphrase-development-v2'}


def paraphrase_dataset_name(root):
    lock = read_json(root/'lock.json')
    if lock.get('corpus') not in PARAPHRASE_SOURCES:
        raise ValueError('Unsupported paraphrase lock schema')
    return PARAPHRASE_SOURCES[lock['corpus']]


def load_paraphrase(root):
    """Load a separate, fully frozen development source; never replace external labels.

    The expected composition (record and pair counts) comes from the frozen lock, which is written
    before any scan, so a case cannot be dropped or added after outcomes are seen.
    """
    lock = read_json(root/'lock.json')
    if lock.get('corpus') in PARAPHRASE_SOURCES and lock.get('version') == 1 and lock.get('state') == 'frozen-before-scanner-measurement':
        entries = lock['inputs']
    else:
        raise ValueError('Unsupported paraphrase lock schema')
    validation = lock.get('validation') or {}
    n_cases, n_pairs = validation.get('jsonl_records'), validation.get('paired_families')
    if not isinstance(n_cases, int) or not isinstance(n_pairs, int) or n_cases != 2*n_pairs or n_cases < 2:
        raise ValueError('Paraphrase lock lacks a frozen composition')
    names = [item['path'] for item in entries]
    if len(names) != len(set(names)) or not {'cases.jsonl', 'provenance.json'} <= set(names):
        raise ValueError('Invalid paraphrase lock inventory')
    for item in entries:
        corpus_validator.safe_path(item['path'])
        path = root/item['path']
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8*1024*1024:
            raise ValueError('Invalid paraphrase input file')
        raw = path.read_bytes()
        if len(raw) != item['bytes'] or sha(raw) != item['sha256']:
            raise ValueError('Paraphrase source differs from frozen lock')
    cases = [corpus_validator.read_json(line) for line in (root/'cases.jsonl').read_bytes().splitlines()]
    if len(cases) != n_cases or len({c['id'] for c in cases}) != n_cases or any(c['split'] != 'development' for c in cases):
        raise ValueError(f'Expected all {n_cases} separate development cases')
    if Counter(c['label'] for c in cases) != {'malicious':n_pairs, 'benign':n_pairs}:
        raise ValueError('Unexpected paraphrase labels')
    families = {}
    for case in cases:
        families.setdefault(case['family_id'], []).append(case)
        if case['topic'] not in ('T01', 'T06') or not case.get('context') or not case.get('rationale'):
            raise ValueError('Paraphrase case lacks context or mechanism rationale')
        if bool(case['expected_findings']) != (case['label'] == 'malicious'):
            raise ValueError('Invalid paraphrase expected signal annotations')
        for file in case['files']:
            corpus_validator.safe_path(file['path'])
            raw = corpus_validator.decode_file(file)
            if len(raw) != file['bytes'] or sha(raw) != file['sha256']:
                raise ValueError('Paraphrase payload checksum mismatch')
    if len(families) != n_pairs or any(len(rows) != 2 or {r['label'] for r in rows} != {'malicious','benign'} for rows in families.values()):
        raise ValueError('Scenario/control pair changed')
    return cases, read_json(root/'provenance.json'), sha((root/'lock.json').read_bytes())


def best_rank(findings, expected, location=False):
    values = [RANK[f['Severity']] for f in findings if f['Threat'] == expected['threat']
              and (not location or f['File'] == expected.get('evidence_file'))]
    return max(values) if values else None


def score_expectations(findings, expectations):
    results = []
    for expected in expectations:
        actual = best_rank(findings, expected)
        annotated = best_rank(findings, expected, True)
        severity = expected.get('severity')
        minimum = expected.get('minimum_severity')
        target = severity or minimum
        if target not in RANK:
            raise ValueError('Expected finding needs exact severity or minimum_severity')
        exact = None
        if severity:
            exact = ('not_detected' if actual is None else 'correct' if actual == RANK[severity]
                     else 'under' if actual < RANK[severity] else 'over')
        results.append({'threat': expected['threat'], 'expected_severity': severity,
                        'minimum_severity': minimum, 'actual_highest_severity': next((s for s,r in RANK.items() if r == actual), None),
                        'minimum_met': actual is not None and actual >= RANK[target],
                        'annotated_file_minimum_met': annotated is not None and annotated >= RANK[target],
                        'exact_severity_result': exact})
    return results


def classify(label, findings, threshold):
    predicted = any(RANK[f['Severity']] >= RANK[threshold] for f in findings)
    return ('TP' if predicted else 'FN') if label == 'malicious' else ('FP' if predicted else 'TN')


def summarize(results, threshold):
    assessed = [r for r in results if r['status'] == 'scanned']
    confusion = Counter(classify(r['label'], r['findings'], threshold) for r in assessed)
    tp, fn, fp, tn = (confusion[k] for k in ('TP', 'FN', 'FP', 'TN'))
    annotated = [r for r in assessed if r['label'] == 'malicious' and r['expectations']]
    severities = [e for r in assessed for e in r['expectations']]
    exact = Counter(e['exact_severity_result'] for e in severities if e['exact_severity_result'] is not None)
    found = [f for r in assessed for f in r['findings']]
    return {'cases': len(results), 'scanned': len(assessed), 'errors': len(results)-len(assessed),
            'threshold': threshold, 'confusion': {k: confusion[k] for k in ('TP', 'FN', 'FP', 'TN')},
            'signal_precision': safe_ratio(tp, tp+fp), 'signal_recall': safe_ratio(tp, tp+fn),
            'false_positive_rate': safe_ratio(fp, fp+tn),
            'expected_cases_annotated': len(annotated),
            'cases_without_expected_annotations': sum(not r['expectations'] for r in assessed),
            'expected_topic_cases_met': sum(all(e['minimum_met'] for e in r['expectations']) for r in annotated),
            'expected_file_cases_met': sum(all(e['annotated_file_minimum_met'] for e in r['expectations']) for r in annotated),
            'minimum_severity': {'annotations': len(severities), 'met_or_exceeded': sum(e['minimum_met'] for e in severities),
                                  'not_met': sum(not e['minimum_met'] for e in severities),
                                  'over_severity_assessable': sum(e['exact_severity_result'] is not None for e in severities)},
            'exact_severity': {'annotations': sum(exact.values()), 'accuracy': safe_ratio(exact['correct'], sum(exact.values())),
                               'cases_unassessed': sum(not any(e['exact_severity_result'] is not None for e in r['expectations']) for r in assessed),
                               **{k: exact[k] for k in ('correct', 'under', 'over', 'not_detected')}},
            'unchecked_cases': sum(not r['scan_complete'] for r in assessed),
            'unchecked_files': len({(r['id'], gap['File']) for r in assessed for gap in r['coverage_issues']}),
            'unchecked_reasons': dict(Counter(gap['Reason'] for r in assessed for gap in r['coverage_issues'])),
            'negative_with_unchecked_content': sum(not r['scan_complete'] and classify(r['label'], r['findings'], threshold) in ('TN', 'FN') for r in assessed),
            'findings_by_severity': dict(Counter(f['Severity'] for f in found)),
            'findings_by_threat': dict(sorted(Counter(f['Threat'] for f in found).items())),
            'triggered_rule_ids': sorted({f['RuleId'] for f in found if f.get('RuleId')}),
            'false_negative_ids': [r['id'] for r in assessed if classify(r['label'], r['findings'], threshold) == 'FN'],
            'false_positive_ids': [r['id'] for r in assessed if classify(r['label'], r['findings'], threshold) == 'FP']}


def scan_case(case, dataset, target_root, scanner, pwsh, timeout, catalog, legacy, raw_root):
    started = time.perf_counter()
    result = {'id': case['id'], 'dataset': dataset, 'label': case['label'], 'topic': case.get('topic'),
              'case_sha256': sha(json.dumps(case, ensure_ascii=False, sort_keys=True).encode('utf-8')),
              'findings': [], 'expectations': [], 'scan_complete': False, 'coverage_issues': []}
    try:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,100}', case['id']):
            raise ValueError('Unsafe case ID')
        target = target_root/dataset/case['id']
        # Validate lexically before creation. Resolving a nonexistent parent while another
        # worker creates it is unreliable on Windows; resolve again after creation.
        if not target.is_relative_to(target_root):
            raise ValueError('Case directory escaped target root')
        target.mkdir(parents=True)
        if not target.resolve().is_relative_to(target_root.resolve()):
            raise ValueError('Created case directory escaped target root')
        expected = {}
        for file in case['files']:
            corpus_validator.safe_path(file['path'])
            path = target/file['path']
            if not path.resolve().is_relative_to(target.resolve()):
                raise ValueError('Target file escaped case root')
            raw = corpus_validator.decode_file(file)
            if len(raw) != file['bytes'] or sha(raw) != file['sha256']:
                raise ValueError('Case payload checksum mismatch')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            expected[file['path']] = sha(raw)
        command = [pwsh, '-NoProfile', '-NonInteractive', '-File', str(scanner), '-Path', str(target), '-Json']
        process = subprocess.run(command, cwd=REPO, capture_output=True, timeout=timeout, shell=False)
        raw_name = dataset+'--'+case['id']
        (raw_root/(raw_name+'.stdout')).write_bytes(process.stdout)
        if process.stderr:
            (raw_root/(raw_name+'.stderr')).write_bytes(process.stderr)
        data = json.loads(process.stdout.decode('utf-8-sig'))
        if process.returncode not in (0, 1, 2) or data.get('SchemaVersion') != 2:
            raise ValueError('Invalid scanner result')
        if {i['File']: i['Sha256'] for i in data['Inventory']} != expected:
            raise ValueError('Scanner inventory/hash differs from materialized inputs')
        if {p.relative_to(target).as_posix(): sha(p.read_bytes()) for p in target.rglob('*') if p.is_file()} != expected:
            raise ValueError('Target changed during scanning')
        for finding in data['Findings']:
            if finding['Severity'] not in RANK:
                raise ValueError('Unknown finding severity')
            if not legacy and (finding.get('RuleId') not in catalog or catalog[finding['RuleId']]['Threat'] != finding['Threat']):
                raise ValueError('Missing or unknown stable rule ID')
        if not legacy and data['RuleCatalogSha256'] != result_catalog_hash(catalog):
            # The supplied catalog has the scanner's exact exported hash attached, not a JSON re-encoding.
            raise ValueError('Scanner catalog changed during evaluation')
        save(raw_root/(raw_name+'.json'), data)
        result.update(status='scanned', findings=data['Findings'], scan_complete=data['ScanComplete'],
                      coverage_issues=data['CoverageIssues'], counts=data['Counts'], exit_code=process.returncode,
                      expectations=score_expectations(data['Findings'], case.get('expected_findings') or []),
                      input_sha256=expected, raw_file='raw/'+raw_name+'.json')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, corpus_validator.CorpusError) as error:
        result.update(status='error', error=type(error).__name__+': '+str(error))
    result['elapsed_seconds'] = round(time.perf_counter()-started, 3)
    return result


class Catalog(dict):
    fingerprint = None


def result_catalog_hash(catalog):
    return catalog.fingerprint


def render_report(summary):
    lines = ['# Instinct evaluation', '', 'Raw scanner signals against frozen labels; not agent safety verdicts.', '',
             '| Dataset | N | TP | FN | FP | TN | Recall | Precision | Unchecked |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, info in summary['datasets'].items():
        s = info['primary']; c = s['confusion']
        pct = lambda x: 'unassessed' if x is None else f'{x:.1%}'
        lines.append(f"| {name} | {s['cases']} | {c['TP']} | {c['FN']} | {c['FP']} | {c['TN']} | {pct(s['signal_recall'])} | {pct(s['signal_precision'])} | {s['unchecked_cases']} |")
        lines += []
    lines += ['', f"Primary threshold: {summary['policy']['primary_threshold']}. Errors: {summary['errors']}; local holdout scanned: 0.", '',
              '## Annotation and independence limits', '',
              '- Development is author-written and informed earlier detector tuning; it is not independent accuracy.',
              '- External deepset texts/labels are independently sourced and pinned. This is a public text-injection subset, not all plugin vulnerabilities or a blind/private benchmark.',
              '- False positives below are raw threshold alerts on upstream benign labels. They are not automatically confirmed false UNSAFE agent verdicts.',
              '- Exact severity is unassessed without exact annotations. A minimum severity permits higher findings; it cannot measure over-severity.',
              '- An incomplete negative is never SAFE. Errors are unassessed, not TN; review every coverage issue.',
              '- No target code, hook, embedded command, archive payload or destination is executed/contacted.', '',
              '## Expected signals and severity', '']
    for name, info in summary['datasets'].items():
        s = info['primary']
        lines += [f'### {name}', '',
                  f"Expected annotated cases: {s['expected_cases_annotated']}; topic/minimum met: {s['expected_topic_cases_met']}; annotated file: {s['expected_file_cases_met']}.",
                  f"Minimum severity annotations: {s['minimum_severity']['annotations']}; met/exceeded: {s['minimum_severity']['met_or_exceeded']}; not met: {s['minimum_severity']['not_met']}.",
                  f"Exact severity annotations: {s['exact_severity']['annotations']}; accuracy: {s['exact_severity']['accuracy'] if s['exact_severity']['accuracy'] is not None else 'unassessed'}.",
                  f"Unchecked reasons: `{json.dumps(s['unchecked_reasons'], sort_keys=True)}`.", '',
                  'Missed positive-label cases: '+(', '.join(s['false_negative_ids']) or 'none')+'.', '',
                  'Benign-label alert cases: '+(', '.join(s['false_positive_ids']) or 'none')+'.', '']
    lines += ['## Evidence', '',
              '`summary.json` has per-suite metrics, secondary thresholds, exact/minimum severity separation and rule IDs.',
              '`cases.jsonl` and CSV files identify every alert, miss, annotation mismatch and unchecked file; `raw/` retains scanner evidence.',
              '`run-policy.json`, `rule-catalog.json`, `inputs-lock.json` and `artifacts-sha256.json` record reproducibility inputs.',
              'External provenance and both upstream license declarations are retained with the frozen corpus.']
    return '\n'.join(lines)+'\n'


def run(args):
    policy_raw = (ROOT/'evaluation-policy.json').read_bytes()
    policy = json.loads(policy_raw)
    scanner_raw = args.scanner.read_bytes()
    runner_raw = Path(__file__).read_bytes()
    pwsh = shutil.which('pwsh')
    if not pwsh:
        raise ValueError('PowerShell 7 is required')
    if args.output.exists():
        raise ValueError('Output already exists; keep prior measurements intact')
    datasets = {}; provenance = {}; locks = {}
    if args.suite in ('all', 'development'):
        records, families, manifest, prov = corpus_validator.load_corpus(ROOT/'corpus')
        corpus_validator.validate_records(records, families, manifest, prov)
        datasets['development'] = [c for c in records if c['split'] == 'development']
        if len(datasets['development']) != 140:
            raise ValueError('Unexpected development partition')
        provenance['development'] = {'independent': False, 'source': prov}
        locks['development'] = sha((ROOT/'corpus/corpus.lock.json').read_bytes())
    if args.suite in ('all', 'external'):
        cases, prov, lock = load_external(args.external_root)
        datasets['external'] = cases; provenance['external'] = prov; locks['external'] = lock
    para_name = None
    if args.suite == 'paraphrase':
        cases, prov, lock = load_paraphrase(args.paraphrase_root)
        para_name = paraphrase_dataset_name(args.paraphrase_root)
        datasets[para_name] = cases
        provenance[para_name] = prov; locks[para_name] = lock
    catalog = Catalog()
    exported = None
    if not args.allow_legacy_scanner:
        result = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', str(args.scanner), '-ListRules'], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('Scanner must export stable IDs; use --allow-legacy-scanner only for an old reference')
        exported = json.loads(result.stdout.decode('utf-8-sig'))
        for rule in exported['Rules']:
            if rule['RuleId'] in catalog:
                raise ValueError('Duplicate catalog rule ID')
            catalog[rule['RuleId']] = rule
        catalog.fingerprint = exported['RuleCatalogSha256']
    args.output.mkdir(parents=True)
    (args.output/'raw').mkdir()
    save(args.output/'run-policy.json', {'policy': policy, 'policy_sha256': sha(policy_raw),
         'scanner_sha256': sha(scanner_raw), 'scanner': str(args.scanner), 'rule_catalog_sha256': catalog.fingerprint,
         'corpus_locks': locks, 'holdout_cases_scanned': 0, 'workers': args.workers, 'timeout_seconds': args.timeout,
         'legacy_reference': args.allow_legacy_scanner, 'python': __import__('sys').version,
         'runner_sha256': sha(runner_raw),
         'pwsh': subprocess.check_output([pwsh,'-NoProfile','-Command','$PSVersionTable.PSVersion.ToString()']).decode().strip(),
         'started_utc': datetime.now(timezone.utc).isoformat()})
    save(args.output/'inputs-lock.json', {'locks': locks, 'datasets': provenance,
         'cases': {name: {c['id']: sha(json.dumps(c, ensure_ascii=False, sort_keys=True).encode('utf-8')) for c in cases} for name,cases in datasets.items()}})
    if exported:
        save(args.output/'rule-catalog.json', exported)
    results = []; started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix='targets-', dir=args.output) as scratch:
        target_root = Path(scratch).resolve()
        for name in datasets:
            (target_root/name).mkdir()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(scan_case,c,name,target_root,args.scanner,pwsh,args.timeout,catalog,args.allow_legacy_scanner,args.output/'raw') for name,cases in datasets.items() for c in cases]
            for future in as_completed(futures):
                results.append(future.result())
                if len(results) % 20 == 0:
                    print(f'Scanned {len(results)}/{len(futures)}; errors={sum(r["status"] == "error" for r in results)}', flush=True)
    results.sort(key=lambda r: (r['dataset'],r['id']))
    if args.scanner.read_bytes() != scanner_raw or (ROOT/'evaluation-policy.json').read_bytes() != policy_raw or Path(__file__).read_bytes() != runner_raw:
        raise ValueError('Scanner/policy/runner changed during measurement')
    if 'development' in locks:
        corpus_validator.load_corpus(ROOT/'corpus')
        if sha((ROOT/'corpus/corpus.lock.json').read_bytes()) != locks['development']:
            raise ValueError('Development lock changed during measurement')
    if 'external' in locks and load_external(args.external_root)[2] != locks['external']:
        raise ValueError('External lock changed during measurement')
    if para_name and load_paraphrase(args.paraphrase_root)[2] != locks[para_name]:
        raise ValueError('Paraphrase lock changed during measurement')
    summary = {'schema_version': 1, 'policy': policy, 'scanner_sha256': sha(scanner_raw), 'rule_catalog_sha256': catalog.fingerprint,
               'cases': len(results), 'errors': sum(r['status'] == 'error' for r in results),
               'holdout_cases_scanned': 0, 'elapsed_seconds': round(time.perf_counter()-started,3), 'datasets': {}}
    for name in datasets:
        rows = [r for r in results if r['dataset'] == name]
        summary['datasets'][name] = {'primary': summarize(rows,policy['primary_threshold']),
            'secondary': {level:summarize(rows,level) for level in policy['secondary_thresholds']}}
        topics = sorted({e['threat'] for r in rows for e in r['expectations']})
        summary['datasets'][name]['expected_by_threat'] = {topic: {
            'annotations': sum(e['threat'] == topic for r in rows for e in r['expectations']),
            'minimum_met': sum(e['threat'] == topic and e['minimum_met'] for r in rows for e in r['expectations']),
            'annotated_file_met': sum(e['threat'] == topic and e['annotated_file_minimum_met'] for r in rows for e in r['expectations'])} for topic in topics}
    if args.baseline:
        previous = [corpus_validator.read_json(line) for line in args.baseline.read_bytes().splitlines()]
        old = {(r['dataset'],r['id']):r for r in previous}; new = {(r['dataset'],r['id']):r for r in results}
        if old.keys() != new.keys() or any(old[k]['case_sha256'] != new[k]['case_sha256'] for k in old):
            raise ValueError('Baseline cases differ; do not compare changed inputs')
        def canonical(r):
            return sorted(json.dumps({k:v for k,v in f.items() if k != 'RuleId'},sort_keys=True) for f in r['findings'])
        summary['baseline_comparison'] = {'same_inputs': True,
            'finding_behavior_changes': [f'{k[0]}/{k[1]}' for k in old if canonical(old[k]) != canonical(new[k])],
            'coverage_changes': [f'{k[0]}/{k[1]}' for k in old if old[k]['scan_complete'] != new[k]['scan_complete'] or old[k]['coverage_issues'] != new[k]['coverage_issues']]}
    save(args.output/'summary.json',summary)
    (args.output/'cases.jsonl').write_bytes(('\n'.join(json.dumps(r,ensure_ascii=False,sort_keys=True) for r in results)+'\n').encode('utf-8'))
    save(args.output/'errors.json',[r for r in results if r['status'] == 'error'])
    save(args.output/'rule-coverage.json',{'registered':len(catalog), 'hit_rules':sorted({f['RuleId'] for r in results for f in r['findings'] if f.get('RuleId')}),
         'unhit_rules':sorted(set(catalog)-{f['RuleId'] for r in results for f in r['findings'] if f.get('RuleId')}),
         'note':'Observed rule hits, not full rule/branch or vulnerability coverage'})
    with (args.output/'cases.csv').open('w',encoding='utf-8-sig',newline='') as f:
        keys=['dataset','id','label','status','primary_result','scan_complete','expected_topic_met','expected_file_met']
        writer=csv.DictWriter(f,fieldnames=keys); writer.writeheader()
        for r in results:
            writer.writerow({k:r[k] for k in keys if k in r} | {'primary_result':classify(r['label'],r['findings'],policy['primary_threshold']) if r['status']=='scanned' else 'UNASSESSED',
                'expected_topic_met':all(e['minimum_met'] for e in r['expectations']) if r['expectations'] else None,
                'expected_file_met':all(e['annotated_file_minimum_met'] for e in r['expectations']) if r['expectations'] else None})
    with (args.output/'findings.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['dataset','case','RuleId','Threat','Severity','File','Line','Note','Evidence']
        writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader()
        for r in results:
            for finding in r['findings']:
                # Prevent spreadsheet formulas when exported evidence is opened in Excel.
                row={'dataset':r['dataset'],'case':r['id'],**finding}
                writer.writerow({k:("'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v) for k,v in row.items()})
    (args.output/'report.md').write_bytes(render_report(summary).encode('utf-8'))
    save(args.output/'artifacts-sha256.json',{p.relative_to(args.output).as_posix():sha(p.read_bytes()) for p in sorted(args.output.rglob('*')) if p.is_file()})
    print(json.dumps({'cases':len(results),'errors':summary['errors'],'output':str(args.output)},sort_keys=True))
    return 2 if summary['errors'] else 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite',choices=['all','development','external','paraphrase'],default='all')
    parser.add_argument('--scanner',type=Path,default=SCANNER)
    parser.add_argument('--external-root',type=Path,default=ROOT/'external/deepset-test')
    parser.add_argument('--paraphrase-root',type=Path,default=ROOT/'paraphrase-development')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--workers',type=int,choices=range(1,9),default=4)
    parser.add_argument('--timeout',type=int,default=30)
    parser.add_argument('--allow-legacy-scanner',action='store_true')
    parser.add_argument('--baseline',type=Path)
    args=parser.parse_args()
    args.scanner=args.scanner.resolve(); args.output=args.output.resolve(); args.external_root=args.external_root.resolve(); args.paraphrase_root=args.paraphrase_root.resolve()
    if not 1 <= args.timeout <= 300:
        parser.error('--timeout must be between 1 and 300 seconds')
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, corpus_validator.CorpusError) as error:
        parser.exit(2,'Evaluation failed: '+str(error)+'\n')


if __name__ == '__main__':
    raise SystemExit(main())
