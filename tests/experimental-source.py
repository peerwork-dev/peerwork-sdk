"""Offline source/cohort rejection tests; no CI runs or publication."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('experimental_source', ROOT/'tools/release/experimental-source.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

class SourceCohort(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 42, 'event': 'push', 'head_branch': 'main',
                    'head_repository': {'full_name': 'owner/sdk'},
                    'status': 'completed', 'conclusion': 'success', 'head_sha': 'a'*40}
        self.artifacts = {'total_count': 8, 'artifacts': [
            {'name': n, 'expired': False} for n in sorted(source.ARTIFACTS)]}
    def validate(self, **kwargs):
        return source.validate(kwargs.get('run', self.run), kwargs.get('artifacts', self.artifacts),
                               'owner/sdk', 42, kwargs.get('workflow_path', '.github/workflows/distribution-spike.yml'))
    def test_historical_push_and_explicit_main_dispatch(self):
        for event in ['push', 'workflow_dispatch']:
            self.run['event'] = event
            self.assertEqual(self.validate(), {'source_sha': 'a'*40, 'source_run_id': 42})
    def test_wrong_source_branch_origin_event_or_conclusion(self):
        changes = [{'id': 43}, {'event': 'pull_request'}, {'event': 'repository_dispatch'},
                   {'head_branch': 'feature'}, {'head_branch': 'v0.1.4'},
                   {'head_repository': {'full_name': 'fork/sdk'}},
                   {'status': 'in_progress'}, {'conclusion': 'failure'},
                   {'conclusion': 'cancelled'}, {'head_sha': 'not-a-sha'}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(run=dict(self.run, **change))
        with self.assertRaises(ValueError):
            self.validate(workflow_path='.github/workflows/checks.yml')
    def test_explicitly_withheld_source_cannot_publish_with_successful_builds(self):
        import json
        held = json.loads((ROOT/'.github/experimental-release-holds.json').read_text())
        for sha in held['sources']:
            with self.subTest(sha=sha), self.assertRaisesRegex(ValueError, 'withheld'):
                self.validate(run=dict(self.run, head_sha=sha))

    def test_missing_duplicate_expired_or_extra_artifact(self):
        for kind in ['missing', 'duplicate', 'expired', 'extra', 'count']:
            a = copy.deepcopy(self.artifacts)
            if kind == 'missing': a['artifacts'].pop(); a['total_count'] = 7
            if kind == 'duplicate': a['artifacts'][-1] = a['artifacts'][0]
            if kind == 'expired': a['artifacts'][0]['expired'] = True
            if kind == 'extra': a['artifacts'].append({'name': 'unexpected', 'expired': False}); a['total_count'] = 9
            if kind == 'count': a['total_count'] = 7
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(artifacts=a)

if __name__ == '__main__':
    unittest.main()
