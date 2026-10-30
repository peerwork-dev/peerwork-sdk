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
          'participant_transfer::tests', 'participant_presence::', 'agent_mcp::tests',
          'transport::tests::send_phase_scope_excludes_interleaved_and_spawned_work_and_survives_cancellation']


def candidate_version(raw):
    """The CLI version command emits JSON, never an archive-name fragment."""
    document = json.loads(raw)
    assert isinstance(document, dict), 'invalid CLI version response'
    version = document.get('version')
    assert isinstance(version, str) and re.fullmatch(
        r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version
    ), 'invalid CLI version'
    return version


def loader_requirements(target, dependencies, symbols=''):
    """Audit emitted imports, not just build flags or a successful CI host."""
    if target == 'win32-x64-msvc':
        names = re.findall(r'^\s+([A-Za-z0-9_.-]+\.dll)\s*$', dependencies, re.I | re.M)
        assert names, 'Windows loader report contains no imports'
        external = re.compile(r'^(?:(?:msvcp|msvcr|vcruntime|concrt)\d.*|node|python\d*|icu.*)\.dll$', re.I)
        assert not any(external.fullmatch(name) for name in names), 'external Windows language/C++ runtime dependency'
        system = {'kernel32.dll','ws2_32.dll','bcryptprimitives.dll','advapi32.dll','crypt32.dll',
                  'ntdll.dll','bcrypt.dll','userenv.dll','secur32.dll','shell32.dll','ole32.dll',
                  'oleaut32.dll','iphlpapi.dll','psapi.dll','cfgmgr32.dll','version.dll','normaliz.dll',
                  'msvcrt.dll','msvcp_win.dll','ucrtbase.dll'}
        assert all(name.lower() in system or name.lower().startswith(('api-ms-win-', 'ext-ms-win-'))
                   for name in names), 'unqualified Windows loader import'
        return {'imports': sorted(set(name.lower() for name in names)), 'vc_runtime_dlls': 'NOT_IMPORTED', 'system_api_sets': 'Windows10+'}
    if target == 'darwin-arm64':
        names = re.findall(r'^\s+(\S+)\s+\(compatibility version', dependencies, re.M)
        assert names, 'macOS loader report contains no imports'
        assert all(name.startswith(('/usr/lib/', '/System/Library/Frameworks/')) for name in names), 'external macOS loader dependency'
        return {'imports': sorted(set(names)), 'deployment_target': '11.0'}
    assert target == 'linux-x64-gnu'
    names = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', dependencies)
    assert names, 'Linux loader report contains no imports'
    assert not any(re.match(r'lib(?:node|python|icu)', name) for name in names), 'external Linux language/ICU runtime dependency'
    required = {}
    for namespace, ceiling in [('GLIBC', (2, 28, 0)), ('GLIBCXX', (3, 4, 25)), ('CXXABI', (1, 3, 11))]:
        versions = [tuple(int(part or 0) for part in match) for match in
                    re.findall(r'\b' + namespace + r'_(\d+)\.(\d+)(?:\.(\d+))?\b', symbols)]
        assert versions or namespace != 'GLIBC', 'missing GNU ABI version requirements'
        if versions:
            actual = max(versions)
            assert actual <= ceiling, namespace + ' ABI floor exceeded'
            required[namespace] = '.'.join(map(str, actual))
    return {'imports': sorted(set(names)), 'required_symbol_versions': required,
            'cxx_runtime': 'SYSTEM_LIBSTDCXX' if 'libstdc++.so.6' in names else 'NOT_IMPORTED'}


def native_metadata(document):
    """Select the CLI's transitive source/build graph, never a binding wrapper."""
    packages = {p['id']: p for p in document['packages']}
    nodes = {n['id']: n for n in document['resolve']['nodes']}
    roots = [p['id'] for p in packages.values() if p['name'] == 'peerwork-cli' and p['source'] is None]
    assert len(roots) == 1, 'exactly one native CLI source root required'
    selected, pending = set(), roots.copy()
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        assert key in packages and key in nodes, 'incomplete native dependency graph'
        selected.add(key)
        pending.extend(nodes[key]['dependencies'])
    members = [key for key in document['workspace_members'] if key in selected]
    assert {packages[key]['name'] for key in members} == {'peerwork-cli','peerwork-runtime','peerwork-core'}, 'binding wrapper entered native source graph'
    return {**document, 'workspace_members': members,
            'packages': [p for p in document['packages'] if p['id'] in selected],
            'resolve': {**document['resolve'], 'nodes': [n for n in document['resolve']['nodes'] if n['id'] in selected]}}


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
    if args.target == 'win32-x64-msvc':
        assert os.environ.get('RUSTFLAGS') == '-C target-feature=+crt-static', 'native Windows candidate requires the selected static CRT flags'
        assert not os.environ.get('CARGO_ENCODED_RUSTFLAGS'), 'encoded flags override the selected CRT policy'
    output.mkdir(parents=True)
    env = dict(os.environ, CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', CARGO_PROFILE_RELEASE_DEBUG='0')

    def run(command, log):
        print(f'Native candidate stage: {log}', flush=True)
        with (output / log).open('w', encoding='utf-8') as stream:
            result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode:
            # Synthetic qualification only; make the failed stage visible in
            # job logs even if artifact upload subsequently fails.
            tail = '\n'.join((output / log).read_text(encoding='utf-8', errors='replace').splitlines()[-60:])
            print(tail[-16384:], flush=True)
            result.check_returncode()

    # Compile the shared test target once, then run only the native affected
    # groups. Explicitly ignored loopback tests are eligible on real CI hosts;
    # real service/Agent fixtures are outside these module prefixes.
    run(['cargo','test','--release','--locked','-p','peerwork-core','--lib',
         'js_locale::tests','--','--test-threads=1'], 'icu-conformance.log')
    assert re.search(r'test result: ok\. [1-9][0-9]* passed;', (output / 'icu-conformance.log').read_text(encoding='utf-8')), 'ICU selector matched no passing cases'
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
        (output / 'symbol-versions.txt').write_text(symbols)
        dependencies = subprocess.check_output(['readelf', '-d', installed], text=True)
    elif args.target == 'darwin-arm64':
        symbols = ''
        dependencies = subprocess.check_output(['otool', '-L', installed], text=True)
    else:
        symbols = ''
        vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        visual_studio = Path(subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.Component.MSBuild','-property','installationPath'],text=True).strip())
        dumpbins = sorted(visual_studio.glob('VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe'))
        assert dumpbins, 'Windows loader inspection tool missing'
        dependencies = subprocess.check_output([str(dumpbins[-1]),'/dependents',str(installed)],text=True)
    (output / 'dynamic-dependencies.txt').write_text(dependencies)
    loader = loader_requirements(args.target, dependencies, symbols)
    import sbom
    from assets import deterministic_tar
    metadata = native_metadata(json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--filter-platform',TARGETS[args.target]],cwd=root,env=env,text=True)))
    epoch = int(subprocess.check_output(['git','show','-s','--format=%ct','HEAD'],cwd=root,text=True))
    document,notices,files = sbom.generate(root,args.target,metadata,source,epoch)
    document['comment'] += ' This view is rooted at the native CLI, not the optional binding workspace members.'
    notices['source_inventory_scope'] = document['comment']
    (output / 'sbom.spdx.json').write_text(json.dumps(document,sort_keys=True) + '\n')
    (output / 'licenses.json').write_text(json.dumps(notices,sort_keys=True) + '\n')
    shutil.copy2(root / 'LICENSE',output / 'LICENSE')
    for name,data in files.items():
        path = output / 'third_party' / name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    version = candidate_version(subprocess.check_output([str(installed), 'version'], text=True))
    archive = output / f'peerwork-native-candidate-{version}-{args.target}.tar.gz'
    deterministic_tar(archive,{installed.name:(installed.read_bytes(),0o755),
        'LICENSE':((output / 'LICENSE').read_bytes(),0o644),
        'skills/peerwork/SKILL.md':((root / 'skills/peerwork/SKILL.md').read_bytes(),0o644),
        'third_party/sbom.spdx.json':((output / 'sbom.spdx.json').read_bytes(),0o644),
        'third_party/licenses.json':((output / 'licenses.json').read_bytes(),0o644),
        **{'third_party/'+name:(data,0o644) for name,data in files.items()}},epoch)
    (output / 'qualification.json').write_text(json.dumps({
        'format': 'peerwork.native-platform-qualification.v1', 'state': 'PASS',
        'source_commit': source, 'target': args.target, 'sdk_version': version,
        'binary_sha256': hashlib.sha256(installed.read_bytes()).hexdigest(),
        'binary_bytes': installed.stat().st_size, 'native_test_groups': GROUPS,
        'core_test_groups': ['js_locale::tests'],
        'os_loader_requirements': loader,
        'candidate_archive': archive.name, 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'node_or_python_client_runtime': 'NOT_USED', 'public_release_qualified': False,
        'limits': ['CI native process/OS qualification only', 'Linux GNU may require its declared system C++ runtime',
                   'No actual service/Agent performance, final packaging, signing or notarization claim'],
    }, indent=2) + '\n')
    print(json.dumps({'state': 'PASS', 'target': args.target, 'source_commit': source, 'public_release_qualified': False}))


if __name__ == '__main__':
    main()
