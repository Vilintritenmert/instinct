"""Validate the frozen data-only corpus without running a scanner or executing fixture code."""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent
TOPICS = {f'T{i:02}' for i in range(1, 27)}
DATA_FILES = {'development.jsonl', 'holdout.jsonl', 'families.json', 'provenance.json', 'manifest.json'}
SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


class CorpusError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CorpusError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def case_digest(case):
    fields = {key: value for key, value in case.items() if key != 'case_sha256'}
    return digest(json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def read_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def decode_file(file):
    require(isinstance(file.get('content'), str), 'Fixture content must be a string')
    if file.get('encoding') == 'utf8':
        return file['content'].encode('utf-8', errors='strict')
    require(file.get('encoding') == 'base64', 'Unsupported fixture encoding')
    try:
        return base64.b64decode(file['content'], validate=True)
    except ValueError as error:
        raise CorpusError('Invalid fixture base64') from error


def safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value,
            'Invalid fixture path')
    require(not any(ord(char) < 32 for char in value), 'Invalid fixture path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and '.' not in value.split('/'),
            'Invalid fixture path')
    require(path.as_posix() == value and not value.endswith('/'), 'Invalid fixture path')


def payload_digest(case):
    """Ignore the neutral per-case name, so changing only an ID cannot inflate diversity."""
    files = []
    for file in sorted(case['files'], key=lambda item: item['path']):
        raw = decode_file(file)
        if file['path'] == 'SKILL.md':
            text = raw.decode('utf-8')
            text = re.sub(r'(?m)^name:.*$', 'name: <neutral>', text)
            raw = text.encode('utf-8')
        files.append([file['path'], digest(raw)])
    return digest(json.dumps(files, separators=(',', ':')).encode())


def validate_records(records, families, manifest, provenance):
    require(len(records) == 200 and len(families) == 100, 'Corpus v1 requires 200 cases and 100 families')
    require(provenance.get('review_status') == 'author self-review complete; external independent labeling/review pending',
            'Review status must disclose the lack of external review')
    seen_ids, seen_payloads = set(), set()
    grouped = defaultdict(list)
    reference_ids = set(provenance['sources'])
    for case in records:
        case_id = case.get('id')
        require(isinstance(case_id, str) and re.fullmatch(r'c-[0-9a-f]{12}', case_id), 'Invalid opaque case ID')
        require(case_id not in seen_ids, 'Duplicate case ID')
        seen_ids.add(case_id)
        require(case.get('case_sha256') == case_digest(case), 'Case metadata checksum mismatch')
        require(case.get('label') in {'malicious', 'benign'}, 'Invalid semantic label')
        require(case.get('split') in {'development', 'holdout'}, 'Invalid split')
        require(case.get('topic') in TOPICS, 'Invalid threat topic')
        require(isinstance(case.get('family_id'), str), 'Missing family ID')
        require(case.get('language') in {'en', 'uk', 'mixed'}, 'Invalid language label')
        require(isinstance(case.get('format'), str) and case['format'], 'Missing format')
        require(isinstance(case.get('rationale'), str) and len(case['rationale']) >= 20, 'Missing label rationale')
        require(case.get('context', {}).get('user_request'), 'Missing user authorization context')
        require(case['context'].get('authority'), 'Missing trust boundary')
        require(case.get('review') == {'method': 'author_semantic_review', 'status': 'self_reviewed',
                                     'external_independent_review': False}, 'Invalid self-review disclosure')
        origin = case.get('provenance', {})
        require(origin.get('origin') == 'locally_authored_synthetic' and origin.get('copied_from_prior_regression') is False,
                'Invalid case provenance')
        require(origin.get('reference_ids') and set(origin['reference_ids']) <= reference_ids, 'Unknown provenance source')
        files = case.get('files')
        require(isinstance(files, list) and 1 <= len(files) <= 8, 'Invalid file inventory')
        paths, total_bytes = set(), 0
        for file in files:
            safe_path(file.get('path'))
            require(file['path'] not in paths, 'Duplicate fixture path')
            paths.add(file['path'])
            raw = decode_file(file)
            require(len(raw) <= 1024 * 1024, 'Fixture file size exceeds corpus limit')
            require(file.get('bytes') == len(raw) and file.get('sha256') == digest(raw), 'Fixture byte checksum mismatch')
            total_bytes += len(raw)
        require(total_bytes <= 1024 * 1024, 'Fixture case size exceeds corpus limit')
        require(case.get('entrypoint') == 'SKILL.md' and 'SKILL.md' in paths, 'Missing neutral skill entrypoint')
        findings = case.get('expected_findings')
        require(isinstance(findings, list), 'Missing expected behavior annotations')
        if case['label'] == 'malicious':
            require(findings and any(item.get('threat') == case['topic'] for item in findings),
                    'Malicious case requires a topic-specific behavior annotation')
            require(case.get('expected_disposition') == 'reject_unauthorized_behavior', 'Invalid malicious disposition')
        else:
            require(not findings, 'Benign case must not require malicious findings')
            require(case.get('expected_disposition') == 'no_confirmed_malicious_behavior', 'Invalid benign disposition')
        for finding in findings:
            require(finding.get('threat') in TOPICS and finding.get('minimum_severity') in SEVERITIES,
                    'Invalid expected threat/severity')
            require(finding.get('evidence_file') in paths and finding.get('behavior'), 'Invalid behavior evidence annotation')
        verdicts = case.get('acceptable_agent_verdicts')
        require(isinstance(verdicts, list) and verdicts and set(verdicts) <= {'SAFE', 'REVIEW', 'UNSAFE'}, 'Invalid agent verdict contract')
        require(('SAFE' not in verdicts) if case['label'] == 'malicious' else ('UNSAFE' not in verdicts),
                'Verdict contract contradicts the semantic label')
        signature = payload_digest(case)
        require(signature not in seen_payloads, 'Duplicate payload after neutral-name normalization')
        seen_payloads.add(signature)
        grouped[case['family_id']].append(case)

    index = {family['id']: family for family in families}
    require(len(index) == 100 and set(index) == set(grouped), 'Family index mismatch')
    for family_id, cases in grouped.items():
        require(len(cases) == 2 and {case['label'] for case in cases} == {'malicious', 'benign'}, 'Invalid scenario/control pair')
        require(len({case['split'] for case in cases}) == 1, 'Family leaks across development and holdout')
        require(len({case['topic'] for case in cases}) == 1, 'Pair topics disagree')
        require(cases[0]['context'] == cases[1]['context'], 'Pair authorization contexts disagree')
        entry = index[family_id]
        require(entry['split'] == cases[0]['split'] and entry['topic'] == cases[0]['topic'], 'Family metadata mismatch')
        require(entry['case_ids'] == sorted(case['id'] for case in cases), 'Family case IDs mismatch')

    expected_splits = {'development': {'malicious': 70, 'benign': 70}, 'holdout': {'malicious': 30, 'benign': 30}}
    for split, expected in expected_splits.items():
        selected = [case for case in records if case['split'] == split]
        require(dict(Counter(case['label'] for case in selected)) == expected, 'Incorrect balanced 70/30 split')
        require({case['topic'] for case in selected} == TOPICS, 'Each split must cover T01–T26')
        require(manifest['splits'][split] == expected, 'Manifest split counts disagree')
        require(manifest['topic_counts'][split] == dict(Counter(case['topic'] for case in selected)), 'Manifest topic counts disagree')
    require(manifest.get('cases') == 200 and manifest.get('families') == 100, 'Manifest totals disagree')
    require(manifest['language_counts'] == dict(Counter(case['language'] for case in records)), 'Language counts disagree')
    require(manifest['format_counts'] == dict(Counter(case['format'] for case in records)), 'Format counts disagree')
    return {'cases': 200, 'families': 100, 'splits': expected_splits,
            'topics_per_split': 26, 'distinct_normalized_payloads': len(seen_payloads),
            'language_counts': manifest['language_counts'], 'format_counts': manifest['format_counts'],
            'language_counts_by_split': {split: dict(Counter(case['language'] for case in records if case['split'] == split))
                                        for split in ('development', 'holdout')},
            'independent_external_review': False, 'scanner_executed': False, 'holdout_scored': False}


def load_corpus(root=ROOT):
    root = Path(root)
    lock_raw = (root / 'corpus.lock.json').read_bytes()
    require(len(lock_raw) < 65536, 'Oversized lock file')
    lock = read_json(lock_raw)
    require(lock.get('schema_version') == 1 and lock.get('corpus_id') == 'instinct-behavior-corpus-v1', 'Unknown corpus lock')
    require({item['path'] for item in lock['files']} == DATA_FILES and len(lock['files']) == len(DATA_FILES), 'Invalid lock inventory')
    for item in lock['files']:
        path = root / item['path']
        require(not path.is_symlink() and path.is_file(), 'Corpus data file must be a regular file')
        require(path.stat().st_size <= 8 * 1024 * 1024, 'Corpus data exceeds input limit')
        raw = path.read_bytes()
        require(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'Frozen corpus checksum mismatch')
    manifest = read_json((root / 'manifest.json').read_bytes())
    require(manifest.get('schema_version') == 1, 'Unknown corpus schema')
    locked = {item['path']: item for item in lock['files']}
    require({item['path'] for item in manifest['files']} == DATA_FILES - {'manifest.json'}, 'Invalid manifest file inventory')
    for item in manifest['files']:
        require(item == locked[item['path']], 'Lock and manifest disagree')
    records = []
    for split in ('development', 'holdout'):
        for line in (root / (split + '.jsonl')).read_text(encoding='utf-8').splitlines():
            require(line, 'Empty case line')
            case = read_json(line)
            require(case.get('split') == split, 'Case is stored in the wrong split file')
            records.append(case)
    families = read_json((root / 'families.json').read_bytes())
    provenance = read_json((root / 'provenance.json').read_bytes())
    return records, families, manifest, provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    try:
        summary = validate_records(*load_corpus(args.root))
        summary['corpus_lock_sha256'] = digest((args.root / 'corpus.lock.json').read_bytes())
        if args.report:
            args.report.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (CorpusError, OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print('Corpus validation failed: ' + ascii(str(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
