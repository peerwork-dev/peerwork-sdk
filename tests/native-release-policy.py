"""Prevent reactivating retired binding publishers or silently expanding CI targets."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/release'))
import version


class NativeReleasePolicy(unittest.TestCase):
    def test_only_selected_native_qualification_and_checks_are_active(self):
        workflows = ROOT / '.github/workflows'
        self.assertEqual({p.name for p in workflows.glob('*.yml')},
                         {'checks.yml', 'native-participant-candidate.yml'})
        checks = (workflows / 'checks.yml').read_text()
        self.assertIn('tools/release/version.py check --native', checks)
        self.assertIn('cargo test --locked -p peerwork-core -p peerwork-runtime -p peerwork-cli', checks)
        self.assertNotIn('cargo test --workspace', checks)
        candidate = (workflows / 'native-participant-candidate.yml').read_text()
        self.assertNotIn('contents: write', candidate)
        self.assertNotIn('gh release', candidate)
        for obsolete in ('darwin-x64', 'linux-arm64', 'musl', 'maturin', 'npm publish', 'cargo build --workspace'):
            self.assertNotIn(obsolete, candidate)
        self.assertEqual(set(version.check_native(ROOT)['targets']),
                         {'linux-x64-gnu', 'darwin-arm64', 'win32-x64-msvc'})

    def test_native_version_cli_ignores_frozen_binding_versions_but_pins_tag(self):
        command = [sys.executable, str(ROOT / 'tools/release/version.py'), 'check', '--native']
        result = subprocess.run(command + ['--plain'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), version.authority(ROOT))
        result = subprocess.run(command + ['--tag', 'v999.0.0'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('tag does not match native Cargo release version', result.stderr)


if __name__ == '__main__':
    unittest.main()
