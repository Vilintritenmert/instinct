"""Negative integrity controls. All fixture bytes remain data, including the execution sentinel."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import validate


class CorpusIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = validate.load_corpus()

    def setUp(self):
        self.records, self.families, self.manifest, self.provenance = copy.deepcopy(self.original)

    def check(self):
        return validate.validate_records(self.records, self.families, self.manifest, self.provenance)

    def refresh(self, case):
        case['case_sha256'] = validate.case_digest(case)

    def test_complete_frozen_corpus(self):
        self.assertEqual(self.check()['cases'], 200)

    def test_pair_cannot_cross_splits(self):
        case = self.records[0]
        case['split'] = 'holdout' if case['split'] == 'development' else 'development'
        self.refresh(case)
        with self.assertRaisesRegex(validate.CorpusError, 'Family leaks'):
            self.check()

    def test_path_traversal_rejected(self):
        case = self.records[0]
        case['files'][0]['path'] = '../outside.txt'
        self.refresh(case)
        with self.assertRaisesRegex(validate.CorpusError, 'Invalid fixture path'):
            self.check()

    def test_changed_bytes_rejected(self):
        case = self.records[0]
        case['files'][0]['content'] += 'changed'
        self.refresh(case)
        with self.assertRaisesRegex(validate.CorpusError, 'Fixture byte checksum'):
            self.check()

    def test_changed_label_metadata_rejected(self):
        self.records[0]['rationale'] += 'changed'
        with self.assertRaisesRegex(validate.CorpusError, 'Case metadata checksum'):
            self.check()

    def test_benign_case_cannot_require_attack(self):
        case = next(item for item in self.records if item['label'] == 'benign')
        case['expected_findings'] = [{'threat': case['topic'], 'minimum_severity': 'HIGH',
                                      'evidence_file': 'SKILL.md', 'behavior': 'Unexpected attack assertion'}]
        self.refresh(case)
        with self.assertRaisesRegex(validate.CorpusError, 'Benign case must not require'):
            self.check()

    def test_duplicate_content_not_hidden_by_names(self):
        cases = [item for item in self.records if item['label'] == 'benign' and item['format'] == 'markdown']
        cases[1]['files'] = copy.deepcopy(cases[0]['files'])
        file = cases[1]['files'][0]
        file['content'] = file['content'].replace('name: helper-', 'name: other-')
        raw = file['content'].encode()
        file.update(bytes=len(raw), sha256=validate.digest(raw))
        self.refresh(cases[1])
        with self.assertRaisesRegex(validate.CorpusError, 'Duplicate payload'):
            self.check()

    def test_missing_case_rejected(self):
        self.records.pop()
        with self.assertRaisesRegex(validate.CorpusError, 'requires 200'):
            self.check()

    def test_claimed_external_review_rejected(self):
        self.provenance['review_status'] = 'independently verified'
        with self.assertRaisesRegex(validate.CorpusError, 'lack of external review'):
            self.check()

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(validate.CorpusError, 'Duplicate JSON key'):
            validate.read_json('{"label":"benign","label":"malicious"}')

    def test_lock_detects_even_whitespace_edits(self):
        with tempfile.TemporaryDirectory(prefix='instinct-corpus-integrity-') as directory:
            root = Path(directory)
            for name in validate.DATA_FILES | {'corpus.lock.json'}:
                shutil.copyfile(validate.ROOT / name, root / name)
            with (root / 'development.jsonl').open('ab') as stream:
                stream.write(b' ')
            with self.assertRaisesRegex(validate.CorpusError, 'Frozen corpus checksum'):
                validate.load_corpus(root)

    def test_fixture_python_never_executed(self):
        with tempfile.TemporaryDirectory(prefix='instinct-corpus-sentinel-') as directory:
            marker = Path(directory) / 'must-not-exist'
            case = next(item for item in self.records if item['label'] == 'benign' and item['format'] == 'markdown')
            file = case['files'][0]
            file['content'] += '\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n'
            raw = file['content'].encode()
            file.update(bytes=len(raw), sha256=validate.digest(raw))
            self.refresh(case)
            self.check()
            self.assertFalse(marker.exists(), 'Validation executed fixture code')


if __name__ == '__main__':
    unittest.main()
