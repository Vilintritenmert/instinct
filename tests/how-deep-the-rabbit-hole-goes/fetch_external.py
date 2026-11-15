"""Fetch the whole pinned deepset public test split as inert data; never run dataset code."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import urllib.request

REVISION = '4f61ecb038e9c3fb77e21034b22511b523772cdd'
SOURCE = 'https://huggingface.co/datasets/deepset/prompt-injections'
DEFAULT = Path(__file__).resolve().parent / 'external' / 'deepset-test'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fetch(url, revision_header=False):
    request = urllib.request.Request(url, headers={'User-Agent': 'instinct-offline-evaluation/1'})
    with urllib.request.urlopen(request, timeout=30) as response:
        if revision_header and response.headers.get('x-revision') != REVISION:
            raise ValueError('Dataset viewer revision differs from pinned source')
        raw = response.read(2*1024*1024 + 1)
        if len(raw) > 2*1024*1024:
            raise ValueError('Unexpectedly large source response')
        return raw


def prepare(destination):
    if destination.exists():
        raise ValueError('Destination exists; retain the frozen copy rather than overwriting it')
    # Retrieve all pages, without choosing rows by content or scanner outcome.
    source_files = {}
    rows = []
    urls = {}
    for offset in (0, 100):
        url = ('https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections'
               f'&config=default&split=test&offset={offset}&length=100')
        raw = fetch(url, revision_header=True)
        page = json.loads(raw)
        if page['num_rows_total'] != 116 or page['partial']:
            raise ValueError('Incomplete or changed public test split')
        name = f'rows-{offset}.json'
        source_files[name] = raw; urls[name] = url
        rows.extend(page['rows'])
    if [row['row_idx'] for row in rows] != list(range(116)):
        raise ValueError('Missing, duplicated or reordered source rows')
    url = f'{SOURCE}/raw/{REVISION}/README.md'
    source_files['upstream-card.md'] = fetch(url); urls['upstream-card.md'] = url
    url = f'{SOURCE}/resolve/{REVISION}/data/test-00000-of-00001-701d16158af87368.parquet'
    source_files['upstream-test.parquet'] = fetch(url); urls['upstream-test.parquet'] = url
    cases = []
    for item in rows:
        row = item['row']
        if item.get('truncated_cells') or set(row) != {'text', 'label'} or type(row['label']) is not int or row['label'] not in (0, 1) or not isinstance(row['text'], str):
            raise ValueError('Unexpected source schema or truncated text')
        raw = row['text'].encode('utf-8')
        cases.append({'id': f'deepset-test-{item["row_idx"]:03}', 'split': 'external-test',
                      'label': 'malicious' if row['label'] else 'benign', 'source_label': row['label'],
                      'source_row': item['row_idx'], 'topic': None, 'language': 'unannotated',
                      'expected_findings': [], 'files': [{'path': 'prompt.md', 'encoding': 'utf8',
                          'content': row['text'], 'bytes': len(raw), 'sha256': sha(raw)}]})
    payload = ('\n'.join(json.dumps(c, ensure_ascii=False, sort_keys=True) for c in cases)+'\n').encode('utf-8')
    source_files['cases.jsonl'] = payload
    provenance = {
        'schema_version': 1, 'dataset_id': 'deepset-prompt-injections-public-test',
        'source': SOURCE, 'revision': REVISION, 'source_split': 'test', 'cases': 116,
        'label_counts': dict(Counter(c['label'] for c in cases)), 'selection': 'Entire upstream test split in source order; no content/result filtering',
        'label_mapping': {'0': 'benign', '1': 'prompt injection (malicious operational label)'},
        'independence': 'Externally sourced labels and texts, not written by this scanner/corpus author; no new independent adjudication or proof of training-data absence',
        'license_declarations': {'top_level': 'apache-2.0', 'dataset_info': 'cc-by-4.0'},
        'license_note': 'Both upstream declarations retained with attribution; no claim resolving their discrepancy',
        'scope': 'Text prompt injection, English/German; not a representative plugin or T01-T26 security corpus',
        'missing_annotations': ['exact severity', 'minimum severity', 'T01-T26 topics', 'agent/user authorization context'],
        'materialization': 'Verbatim UTF-8 source text as prompt.md, without a skill header, label or rationale',
        'urls': urls}
    source_files['provenance.json'] = (json.dumps(provenance, ensure_ascii=False, indent=2)+'\n').encode('utf-8')
    lock = {'schema_version': 1, 'revision': REVISION, 'files': [
        {'path': name, 'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(source_files.items())]}
    destination.mkdir(parents=True)
    for name, raw in source_files.items():
        (destination/name).write_bytes(raw)
    (destination/'lock.json').write_bytes((json.dumps(lock, indent=2)+'\n').encode('utf-8'))
    print(json.dumps({'destination': str(destination), 'revision': REVISION, 'cases': len(cases),
                      'labels': provenance['label_counts'], 'lock_sha256': sha((destination/'lock.json').read_bytes())}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=DEFAULT)
    args = parser.parse_args()
    prepare(args.destination)


if __name__ == '__main__':
    main()
