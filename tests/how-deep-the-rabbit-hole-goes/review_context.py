"""Validate blind reviews and keep contextual assessments separate from frozen upstream labels."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from corpus import validate as corpus_validator

VIEWS = ('direct_user', 'untrusted_reference')
SEVERITIES = {'LOW','MEDIUM','HIGH','CRITICAL','UNASSESSED'}


def read_lines(path):
    return [corpus_validator.read_json(line) for line in path.read_bytes().splitlines()]


def save(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode('utf-8'))


def validate_frozen_review(root, cases):
    """Verify immutable independent inputs and regenerate consensus without adjudicating it."""
    lock=corpus_validator.read_json((root/'lock.json').read_bytes())
    if lock.get('schema_version')!=1:
        raise ValueError('Unsupported review lock')
    names=[r['path'] for r in lock['files']]
    if len(set(names))!=len(names): raise ValueError('Duplicate review lock entries')
    for item in lock['files']:
        corpus_validator.safe_path(item['path'])
        path=root/item['path']
        if path.is_symlink() or not path.is_file() or path.stat().st_size>8*1024*1024:
            raise ValueError('Invalid frozen review input')
        raw=path.read_bytes()
        if len(raw)!=item['bytes'] or hashlib.sha256(raw).hexdigest()!=item['sha256']:
            raise ValueError('Frozen review checksum mismatch')
    expected=merge_reviews(cases,read_lines(root/'reviewer-a.jsonl'),read_lines(root/'reviewer-b.jsonl'))
    if expected!=read_lines(root/'annotations.jsonl') or summarize(expected)!=corpus_validator.read_json((root/'summary.json').read_bytes()):
        raise ValueError('Stored consensus differs from both independent reviews')
    return expected


def validate_review(rows, texts):
    by_id = {r['id']:r for r in rows}
    if len(by_id) != len(rows) or set(by_id) != set(texts):
        raise ValueError('Review must include every input ID exactly once')
    for row in rows:
        if set(row) != {'id','source_context','source_context_reason',*VIEWS}:
            raise ValueError('Unexpected review schema, labels or scan-derived fields')
        # The pinned source has only text/label rows, with no recovered original role traces.
        if row['source_context'] != 'not_documented' or not row['source_context_reason']:
            raise ValueError('Do not invent original trust context from hypothetical scenarios')
        for view in VIEWS:
            item = row[view]
            if set(item) != {'judgment','threat_types','severity','evidence','reason'}:
                raise ValueError('Invalid contextual annotation fields')
            if item['judgment'] not in {'benign','unsafe','ambiguous'} or item['severity'] not in SEVERITIES or not item['reason']:
                raise ValueError('Invalid contextual judgment or severity')
            threats = item['threat_types']
            if not isinstance(threats, list) or len(threats) != len(set(threats)) or any(not re.fullmatch(r'T(?:0[1-9]|1[0-9]|2[0-6])', t) for t in threats):
                raise ValueError('Invalid threat type')
            if not isinstance(item['evidence'], list) or any(not isinstance(e,str) or not e or len(e)>120 or e not in texts[row['id']] for e in item['evidence']):
                raise ValueError('Evidence must be an exact bounded source substring')
            if item['judgment'] == 'benign' and (threats or item['severity'] != 'LOW'):
                raise ValueError('Benign judgment cannot imply an unsafe mechanism/severity')
            if item['judgment'] == 'unsafe' and (not threats or not item['evidence'] or item['severity'] in {'LOW','UNASSESSED'}):
                raise ValueError('Unsafe judgment needs supported threat, evidence and severity')
            if item['judgment'] == 'ambiguous' and item['severity'] != 'UNASSESSED':
                raise ValueError('Ambiguity must remain unassessed')
    return by_id


def merge_reviews(cases, review_a, review_b):
    texts = {c['id']:c['files'][0]['content'] for c in cases}
    a = validate_review(review_a, texts); b = validate_review(review_b, texts)
    merged=[]
    for case in cases:
        key=case['id']
        row={'id':key,'source_label':case['label'],'actual_source_context':'not_documented',
             'actual_semantic_ground_truth':'UNASSESSED','actual_exact_severity':'UNASSESSED',
             'text_sha256':hashlib.sha256(texts[key].encode('utf-8')).hexdigest(),'conditional_assessments':{}}
        for view in VIEWS:
            first=a[key][view]; second=b[key][view]
            differences=[]
            for field in ('judgment','severity','threat_types'):
                left=sorted(first[field]) if field=='threat_types' else first[field]
                right=sorted(second[field]) if field=='threat_types' else second[field]
                if left!=right: differences.append(field)
            agreed=not differences
            consensus={k:first[k] for k in ('judgment','severity','threat_types')} if agreed else None
            # Never silently select one reviewer to improve a score.
            row['conditional_assessments'][view]={'reviewer_a':first,'reviewer_b':second,
                'agreement_fields':{'judgment':first['judgment']==second['judgment'],
                                    'severity':first['severity']==second['severity'],
                                    'threat_types':set(first['threat_types'])==set(second['threat_types'])},
                'disagreement_fields':differences,'consensus':consensus,
                'assessment_scope':'explicit hypothetical context, not recovered source ground truth'}
        merged.append(row)
    return merged


def summarize(merged):
    views={}
    for view in VIEWS:
        values=[row['conditional_assessments'][view] for row in merged]
        consensus=[v['consensus'] for v in values if v['consensus'] is not None]
        views[view]={'cases':len(values),'full_agreement':len(consensus),'disputed':len(values)-len(consensus),
            'judgment_agreement':sum(v['agreement_fields']['judgment'] for v in values),
            'severity_agreement':sum(v['agreement_fields']['severity'] for v in values),
            'type_agreement':sum(v['agreement_fields']['threat_types'] for v in values),
            'consensus_judgments':dict(Counter(v['judgment'] for v in consensus)),
            'conditional_severities':dict(Counter(v['severity'] for v in consensus)),
            'conditional_threat_types':dict(Counter(t for v in consensus for t in v['threat_types'])),
            'disputed_ids':[row['id'] for row in merged if row['conditional_assessments'][view]['consensus'] is None]}
    return {'records':len(merged),'actual_source_context_undocumented':len(merged),
            'actual_ground_truth_unassessed':len(merged),'actual_exact_severity_unassessed':len(merged),
            'views':views,'source_labels_replaced':False,
            'independence':'Two isolated AI reviews; not human expert adjudication; shared-model bias remains possible'}


def miss_ledger(original, baseline, candidate=None):
    source={c['id']:c for c in original}
    before={r['id']:r for r in baseline if r['dataset']=='external'}
    if set(source)!=set(before) or any(source[k]['label']!=before[k]['label'] for k in source):
        raise ValueError('Baseline/source cohort or upstream labels changed')
    rank={'LOW':0,'MEDIUM':1,'HIGH':2,'CRITICAL':3}
    positive=lambda r:any(rank[f['Severity']]>=rank['HIGH'] for f in r['findings'])
    for key,row in before.items():
        if row['status']!='scanned': raise ValueError('Original baseline must be fully assessed')
        hashes={f['path']:f['sha256'] for f in source[key]['files']}
        if row['input_sha256']!=hashes: raise ValueError('Baseline payload changed')
    misses=sorted(k for k in source if source[k]['label']=='malicious' and not positive(before[k]))
    if len(misses)!=59 or Counter(c['label'] for c in source.values())!={'malicious':60,'benign':56}:
        raise ValueError('The original 59-miss/116-row baseline cohort must remain intact')
    after=None
    if candidate is not None:
        after={r['id']:r for r in candidate if r['dataset']=='external'}
        if set(after)!=set(before) or any(after[k]['label']!=before[k]['label'] or after[k]['input_sha256']!=before[k]['input_sha256'] for k in before):
            raise ValueError('Candidate cannot remove, relabel or replace baseline rows')
        if any(r['status']!='scanned' for r in after.values()):
            raise ValueError('Candidate has unassessed rows')
    return [{'id':k,'source_label':'malicious','baseline_high_alert':False,
             'candidate_high_alert':positive(after[k]) if after else None,
             'candidate_rule_ids':sorted({f.get('RuleId') for f in after[k]['findings'] if f.get('RuleId') and rank[f['Severity']]>=2}) if after else [],
             'included_in_original_denominator':True,'context_review_cannot_remove_this_row':True} for k in misses]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--review-a',type=Path,required=True)
    parser.add_argument('--review-b',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--candidate',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error('Output exists; preserve earlier review')
    cases=read_lines(args.source)
    if args.review_a.parent==args.review_b.parent and (args.review_a.parent/'lock.json').exists():
        validate_frozen_review(args.review_a.parent,cases)
    merged=merge_reviews(cases,read_lines(args.review_a),read_lines(args.review_b))
    ledger=miss_ledger(cases,read_lines(args.baseline),read_lines(args.candidate) if args.candidate else None)
    args.output.mkdir(parents=True)
    (args.output/'annotations.jsonl').write_bytes(('\n'.join(json.dumps(r,ensure_ascii=False,sort_keys=True) for r in merged)+'\n').encode('utf-8'))
    save(args.output/'summary.json',summarize(merged))
    save(args.output/'original-59-misses.json',ledger)
    print(json.dumps({'reviewed':len(merged),'all_original_misses_retained':len(ledger),'output':str(args.output)}))


if __name__=='__main__':
    main()
