"""Regression tests for measurement arithmetic, input integrity and stable IDs."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import evaluate


def finding(severity='HIGH', threat='T01', file='prompt.md'):
    return {'RuleId':threat+'-001','Threat':threat,'Severity':severity,'File':file,'Line':1,'Note':'synthetic','Evidence':'synthetic'}


def row(label='malicious', findings=None, status='scanned', complete=True, expectations=None):
    return {'id':'case-'+label,'label':label,'status':status,'findings':findings or [],
            'scan_complete':complete,'coverage_issues':[] if complete else [{'File':'image.png','Reason':'pixels unchecked'}],
            'expectations':expectations or []}


class MeasurementTests(unittest.TestCase):
    def test_confusion_and_threshold(self):
        rows=[row(findings=[finding()]),row(),row('benign',[finding()]),row('benign')]
        s=evaluate.summarize(rows,'HIGH')
        self.assertEqual(s['confusion'],{'TP':1,'FN':1,'FP':1,'TN':1})
        self.assertEqual((s['signal_precision'],s['signal_recall'],s['false_positive_rate']),(0.5,0.5,0.5))
        self.assertEqual(evaluate.classify('malicious',[finding('MEDIUM')],'HIGH'),'FN')
        self.assertEqual(evaluate.classify('malicious',[finding('MEDIUM')],'MEDIUM'),'TP')

    def test_errors_are_not_true_negatives(self):
        s=evaluate.summarize([row('benign',status='error')],'HIGH')
        self.assertEqual(s['errors'],1)
        self.assertEqual(sum(s['confusion'].values()),0)
        self.assertIsNone(s['signal_precision'])
        self.assertIsNone(s['false_positive_rate'])

    def test_incomplete_negative_remains_unchecked(self):
        s=evaluate.summarize([row('benign',complete=False)],'HIGH')
        self.assertEqual(s['confusion']['TN'],1)
        self.assertEqual(s['negative_with_unchecked_content'],1)
        self.assertEqual(s['unchecked_cases'],1)
        self.assertEqual(s['unchecked_reasons'],{'pixels unchecked':1})

    def test_missing_annotations_are_not_successes(self):
        s=evaluate.summarize([row(findings=[finding()])],'HIGH')
        self.assertEqual(s['expected_cases_annotated'],0)
        self.assertEqual(s['cases_without_expected_annotations'],1)
        self.assertEqual(s['exact_severity']['annotations'],0)
        self.assertIsNone(s['exact_severity']['accuracy'])

    def test_minimum_severity_does_not_measure_over_severity(self):
        scored=evaluate.score_expectations([finding('CRITICAL')],[{'threat':'T01','minimum_severity':'HIGH','evidence_file':'prompt.md'}])
        self.assertTrue(scored[0]['minimum_met'])
        self.assertIsNone(scored[0]['exact_severity_result'])

    def test_exact_severity_distinguishes_under_over_and_missing(self):
        expected=[{'threat':'T01','severity':'HIGH','evidence_file':'prompt.md'}]
        for severity, verdict in [('HIGH','correct'),('LOW','under'),('CRITICAL','over'),(None,'not_detected')]:
            with self.subTest(severity=severity):
                scored=evaluate.score_expectations([finding(severity)] if severity else [],expected)
                self.assertEqual(scored[0]['exact_severity_result'],verdict)

    def test_location_match_is_separate(self):
        expected=[{'threat':'T01','minimum_severity':'HIGH','evidence_file':'other.md'}]
        result=evaluate.score_expectations([finding()],expected)[0]
        self.assertTrue(result['minimum_met'])
        self.assertFalse(result['annotated_file_minimum_met'])

    def test_external_adapter_preserves_all_upstream_rows(self):
        cases,provenance,_=evaluate.load_external(evaluate.ROOT/'external/deepset-test')
        self.assertEqual(len(cases),116)
        self.assertEqual(Counter(c['label'] for c in cases),{'malicious':60,'benign':56})
        self.assertEqual(provenance['revision'],'4f61ecb038e9c3fb77e21034b22511b523772cdd')
        self.assertTrue(all(not c['expected_findings'] for c in cases))

    def test_external_checksum_rejects_changed_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'external'
            shutil.copytree(evaluate.ROOT/'external/deepset-test',root)
            path=root/'cases.jsonl'
            raw=path.read_bytes(); path.write_bytes(raw.replace(b'"label": "malicious"',b'"label": "benign"',1))
            with self.assertRaises(ValueError):
                evaluate.load_external(root)

    def test_separate_paraphrase_source_is_complete_and_frozen(self):
        source=evaluate.ROOT/'paraphrase-development'
        cases,provenance,_=evaluate.load_paraphrase(source)
        self.assertEqual(len(cases),60)
        self.assertEqual(Counter(c['language'] for c in cases),{'en':40,'uk':20})
        self.assertTrue(provenance['blind_authoring']['external_texts_or_labels_read'] is False)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'paraphrase'; shutil.copytree(source,root)
            path=root/'cases.jsonl'; path.write_bytes(path.read_bytes()+b'\n')
            with self.assertRaises(ValueError): evaluate.load_paraphrase(root)

    def test_second_paraphrase_source_is_complete_and_frozen(self):
        source=evaluate.ROOT/'paraphrase-development-v2'
        cases,provenance,_=evaluate.load_paraphrase(source)
        self.assertEqual(evaluate.paraphrase_dataset_name(source),'paraphrase-development-v2')
        self.assertEqual(len(cases),80)
        self.assertEqual(Counter(c['language'] for c in cases),{'en':32,'de':28,'uk':20})
        self.assertEqual(Counter(c['label'] for c in cases),{'malicious':40,'benign':40})
        self.assertTrue(provenance['blind_authoring']['external_texts_or_labels_read'] is False)
        receipt=json.loads((evaluate.ROOT/'paraphrase-review-v2.json').read_text(encoding='utf-8'))
        self.assertEqual(receipt['source_cases_sha256'],evaluate.sha((source/'cases.jsonl').read_bytes()))
        self.assertEqual(receipt['agreement_cases'],80)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'paraphrase'; shutil.copytree(source,root)
            # Dropping one case after outcomes must fail against the frozen lock.
            path=root/'cases.jsonl'; lines=path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b''.join(lines[:-1]))
            with self.assertRaises(ValueError): evaluate.load_paraphrase(root)

    def test_holdout_not_an_available_suite(self):
        process=subprocess.run([__import__('sys').executable,'-B',str(evaluate.ROOT/'evaluate.py'),'--suite','holdout','--output','unused'],capture_output=True)
        self.assertEqual(process.returncode,2)
        self.assertIn(b'invalid choice',process.stderr)

    def test_unsafe_case_id_never_reaches_scanner(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            case={'id':'../escape','label':'benign','files':[]}
            result=evaluate.scan_case(case,'external',root,Path('unused'),'not-executed',1,{},True,root)
            self.assertEqual(result['status'],'error')
            self.assertIn('Unsafe case ID',result['error'])
            self.assertFalse((root.parent/'escape').exists())

    def test_parallel_case_creation_keeps_owned_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'raw').mkdir()
            output={'SchemaVersion':2,'Inventory':[],'Findings':[],'ScanComplete':True,'CoverageIssues':[],'Counts':{}}
            fake=subprocess.CompletedProcess([],0,json.dumps(output).encode('utf-8'),b'')
            cases=[{'id':f'parallel-{i}','label':'benign','files':[]} for i in range(24)]
            with patch.object(evaluate.subprocess,'run',return_value=fake), ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(lambda c:evaluate.scan_case(c,'external',root,Path('unused'),'not-executed',1,{},True,root/'raw'),cases))
            self.assertTrue(all(r['status']=='scanned' for r in results),[r.get('error') for r in results])
            self.assertEqual(len(list((root/'external').iterdir())),24)

    def test_catalog_stability_under_rule_reordering(self):
        pwsh=shutil.which('pwsh')
        self.assertIsNotNone(pwsh)
        original=json.loads(subprocess.check_output([pwsh,'-NoProfile','-File',str(evaluate.SCANNER),'-ListRules']).decode('utf-8-sig'))
        ids={r['RuleId'] for r in original['Rules']}
        baseline=json.loads((evaluate.ROOT/'stable-rule-ids-v1.json').read_text(encoding='utf-8'))
        self.assertEqual(len(baseline['rule_ids']),212)
        self.assertTrue(set(baseline['rule_ids']) <= ids)
        self.assertEqual(len(ids),len(original['Rules']))
        self.assertIn('T01-001',ids)
        self.assertIn('T21-901',ids)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'scripts').mkdir(); (root/'references').mkdir()
            source=evaluate.SCANNER.read_text(encoding='utf-8-sig')
            marker='$rxOpts = '
            self.assertEqual(source.count(marker),1)
            source=source.replace(marker,"$rules = @($rules | Sort-Object RuleId -Descending)\n"+marker)
            scanner=root/'scripts/scan.ps1'; scanner.write_bytes(source.encode('utf-8'))
            shutil.copyfile(evaluate.SCANNER.parent.parent/'references/structural-rules.json',root/'references/structural-rules.json')
            reordered=json.loads(subprocess.check_output([pwsh,'-NoProfile','-File',str(scanner),'-ListRules']).decode('utf-8-sig'))
            self.assertEqual(original,reordered)
            # Normalized, decoded and structural findings retain identities under reordering.
            for fixture in ['evil-skill','evasion-skill']:
                def scan(path):
                    p=subprocess.run([pwsh,'-NoProfile','-File',str(path),'-Path',str(evaluate.ROOT/fixture),'-Json'],capture_output=True)
                    self.assertIn(p.returncode,(0,1,2))
                    result=json.loads(p.stdout.decode('utf-8-sig'))
                    self.assertTrue(all(f.get('RuleId') in ids for f in result['Findings']))
                    return sorted(json.dumps(f,sort_keys=True) for f in result['Findings'])
                self.assertEqual(scan(evaluate.SCANNER),scan(scanner))

    def test_git_checkout_keeps_frozen_bytes_with_autocrlf(self):
        git=shutil.which('git'); self.assertIsNotNone(git)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo'; root.mkdir()
            (root/'.gitattributes').write_bytes((evaluate.REPO/'.gitattributes').read_bytes())
            relative_files=['corpus/corpus.lock.json','external/deepset-test/lock.json',
                            'context-review-v1/lock.json','paraphrase-development/lock.json',
                            'paraphrase-development-v2/lock.json','paraphrase-review-v2.json']
            for relative in relative_files:
                path=root/'tests/how-deep-the-rabbit-hole-goes'/relative
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((evaluate.ROOT/relative).read_bytes())
            subprocess.run([git,'init','--quiet'],cwd=root,check=True,capture_output=True)
            subprocess.run([git,'-c','core.autocrlf=true','add','--','.gitattributes','tests'],cwd=root,check=True,capture_output=True)
            for relative in relative_files:
                blob=subprocess.check_output([git,'show',':tests/how-deep-the-rabbit-hole-goes/'+relative],cwd=root)
                self.assertEqual(blob,(evaluate.ROOT/relative).read_bytes())
                (root/'tests/how-deep-the-rabbit-hole-goes'/relative).unlink()
            subprocess.run([git,'-c','core.autocrlf=true','checkout-index','--all','--force'],cwd=root,check=True,capture_output=True)
            for relative in relative_files:
                self.assertEqual((root/'tests/how-deep-the-rabbit-hole-goes'/relative).read_bytes(),(evaluate.ROOT/relative).read_bytes())


if __name__ == '__main__':
    unittest.main()
