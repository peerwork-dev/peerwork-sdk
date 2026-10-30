#!/usr/bin/env python3
"""Three native candidate builds; no Node/Python SDK build or public publication.

Artifacts are temporary qualification inputs, not a signed/notarized release.
The installed executable is exercised in synthetic local state only. Service,
actual Agent delivery, throughput and public-release gates remain separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

TARGETS = {
    'linux-x64-gnu': 'x86_64-unknown-linux-gnu',
    'darwin-arm64': 'aarch64-apple-darwin',
    'win32-x64-msvc': 'x86_64-pc-windows-msvc',
}
GROUPS = ['communication_local_channel::tests', 'communication_runtime::tests',
          'communication_store::', 'participant_store::tests', 'participant_inbox::tests',
          'participant_transfer::tests', 'participant_presence::', 'agent_mcp::tests']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=TARGETS, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = root / '.participant-ci' / args.target
    assert not output.exists(), 'candidate output must be fresh'
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    assert re.fullmatch('[0-9a-f]{40}', source)
    assert not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=root), 'tracked source is dirty'
    rust = subprocess.check_output(['rustc', '-vV'], cwd=root, text=True)
    assert 'release: 1.89.0\n' in rust and 'host: ' + TARGETS[args.target] + '\n' in rust, 'wrong native toolchain'
    if args.target == 'linux-x64-gnu':
        assert subprocess.check_output(['getconf', 'GNU_LIBC_VERSION'], text=True).strip() == 'glibc 2.28'
    if args.target == 'darwin-arm64':
        assert os.environ.get('MACOSX_DEPLOYMENT_TARGET') == '11.0'
    output.mkdir(parents=True)
    env = dict(os.environ, CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', CARGO_PROFILE_RELEASE_DEBUG='0')

    def run(command, log):
        with (output / log).open('w', encoding='utf-8') as stream:
            subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)

    # Compile the shared test target once, then run only the native affected
    # groups. Explicitly ignored loopback tests are eligible on real CI hosts;
    # real service/Agent fixtures are outside these module prefixes.
    for index, group in enumerate(GROUPS):
        run(['cargo', 'test', '--release', '--locked', '-p', 'peerwork-runtime', '--lib',
             group, '--', '--include-ignored', '--test-threads=1'], f'tests-{index}.log')
        result = (output / f'tests-{index}.log').read_text(encoding='utf-8')
        assert re.search(r'test result: ok\. [1-9][0-9]* passed;', result), 'test selector matched no passing cases'
    run(['cargo', 'build', '--release', '--locked', '-p', 'peerwork-cli', '--bin', 'peerwork'], 'build.log')
    target_dir = Path(env.get('CARGO_TARGET_DIR', root / 'target'))
    if not target_dir.is_absolute():
        target_dir = root / target_dir
    built = target_dir / 'release' / ('peerwork.exe' if os.name == 'nt' else 'peerwork')
    installed = output / built.name
    shutil.copy2(built, installed)
    run([sys.executable, 'tests/installed-participant-smoke.py', '--cli', str(installed)], 'installed-smoke.json')
    assert json.loads((output / 'installed-smoke.json').read_text())['state'] == 'PASS'
    if args.target == 'linux-x64-gnu':
        symbols = subprocess.check_output(['readelf', '--version-info', installed], text=True)
        versions = [tuple(int(part or 0) for part in match) for match in re.findall(r'\bGLIBC_(\d+)\.(\d+)(?:\.(\d+))?\b', symbols)]
        assert versions and all(v <= (2,28,0) for v in versions), 'glibc floor exceeded'
        (output / 'dynamic-dependencies.txt').write_text(subprocess.check_output(['readelf', '-d', installed], text=True))
    elif args.target == 'darwin-arm64':
        (output / 'dynamic-dependencies.txt').write_text(subprocess.check_output(['otool', '-L', installed], text=True))
    version = subprocess.check_output([str(installed), 'version'], text=True).strip()
    (output / 'qualification.json').write_text(json.dumps({
        'format': 'peerwork.native-platform-qualification.v1', 'state': 'PASS',
        'source_commit': source, 'target': args.target, 'sdk_version': version,
        'binary_sha256': hashlib.sha256(installed.read_bytes()).hexdigest(),
        'binary_bytes': installed.stat().st_size, 'native_test_groups': GROUPS,
        'node_or_python_client_runtime': 'NOT_USED', 'public_release_qualified': False,
        'limits': ['CI native process/OS qualification only', 'Windows loader dependencies require release audit',
                   'No actual service/Agent performance, final packaging, signing or notarization claim'],
    }, indent=2) + '\n')
    print(json.dumps({'state': 'PASS', 'target': args.target, 'source_commit': source, 'public_release_qualified': False}))


if __name__ == '__main__':
    main()
