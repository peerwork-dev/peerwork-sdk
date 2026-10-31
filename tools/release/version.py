"""Offline release identity: Cargo authority, exact Node/platform/lock parity."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

TARGETS = ('linux-x64-gnu','linux-arm64-gnu','linux-x64-musl','linux-arm64-musl','darwin-x64','darwin-arm64','win32-x64-msvc')
NATIVE_TARGETS = ('linux-x64-gnu','darwin-arm64','win32-x64-msvc')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')

class ReleaseError(ValueError):
    pass

def read_toml(path: Path):
    return tomllib.loads(path.read_text(encoding='utf-8'))

def authority(root: Path) -> str:
    version = read_toml(root/'Cargo.toml')['workspace']['package']['version']
    if not isinstance(version,str) or not VERSION.fullmatch(version):
        raise ReleaseError('release version must be canonical stable MAJOR.MINOR.PATCH')
    return version

def check_native(root: Path, tag: str | None = None) -> dict:
    """The CLI/program cohort has its own finite graph, not binding parity."""
    version=authority(root)
    if tag is not None and tag!='v'+version:raise ReleaseError('tag does not match native Cargo release version')
    locked=read_toml(root/'Cargo.lock')['package'];names=[]
    for member,expected in [('crates/core','peerwork-core'),('crates/runtime','peerwork-runtime'),('crates/cli','peerwork-cli')]:
        package=read_toml(root/member/'Cargo.toml')['package']
        if package['name']!=expected or package.get('version')!={'workspace':True}:
            raise ReleaseError('native crate must inherit the exact Cargo release version')
        rows=[p for p in locked if p['name']==expected and 'source' not in p]
        if len(rows)!=1 or rows[0]['version']!=version:raise ReleaseError('native Cargo.lock release version drifted')
        names.append(expected)
    return dict(version=version,tag='v'+version,targets=list(NATIVE_TARGETS),workspace_packages=sorted(names))

def check(root: Path, tag: str | None = None) -> dict:
    version=authority(root)
    if tag is not None and tag != 'v'+version:
        raise ReleaseError('tag does not match the exact Cargo workspace release version')
    workspace=read_toml(root/'Cargo.toml')['workspace']
    names=[]
    for member in workspace['members']:
        package=read_toml(root/member/'Cargo.toml')['package']
        if package.get('version') != {'workspace':True}:
            raise ReleaseError('every workspace crate must inherit the release version')
        names.append(package['name'])
    if len(names)!=len(set(names)):
        raise ReleaseError('duplicate workspace package identity')
    python=read_toml(root/'bindings/python/pyproject.toml')['project']
    if 'version' in python or python.get('dynamic',[]).count('version')!=1:
        raise ReleaseError('Python version must derive from native Cargo metadata')
    if python['name']!='peerwork-sdk':
        raise ReleaseError('unexpected Python release package identity')
    node=json.loads((root/'bindings/node/package.json').read_text())
    expected={'@peerwork/agent-sdk-'+target:version for target in TARGETS}
    if node.get('name')!='@peerwork/agent-sdk' or node.get('version')!=version or node.get('optionalDependencies')!=expected:
        raise ReleaseError('Node root/platform release versions or finite target set drifted')
    locked=read_toml(root/'Cargo.lock')['package']
    for name in names:
        rows=[p for p in locked if p['name']==name and 'source' not in p]
        if len(rows)!=1 or rows[0]['version']!=version:
            raise ReleaseError('Cargo.lock workspace release version drifted')
    return dict(version=version,tag='v'+version,python_package=python['name'],node_package=node['name'],targets=list(TARGETS),workspace_packages=sorted(names))

def sync(root: Path, version: str | None = None) -> dict:
    """Explicit local update; never selects a release by querying a registry."""
    current=authority(root)
    if version is None:version=current
    if not VERSION.fullmatch(version):raise ReleaseError('release version must be canonical stable MAJOR.MINOR.PATCH')
    cargo=root/'Cargo.toml';content=cargo.read_text()
    section=re.search(r'(?ms)^\[workspace\.package\]\n(.*?)(?=^\[|\Z)',content)
    if section is None:raise ReleaseError('missing Cargo workspace package section')
    changed,n=re.subn(r'(?m)^version\s*=\s*"[^"]+"\s*$', 'version = '+json.dumps(version),section.group(1),count=1)
    if n!=1:raise ReleaseError('ambiguous Cargo release version')
    workspace=read_toml(cargo)['workspace']
    names={read_toml(root/member/'Cargo.toml')['package']['name'] for member in workspace['members']}
    node_path=root/'bindings/node/package.json';node=json.loads(node_path.read_text())
    expected_keys={'@peerwork/agent-sdk-'+target for target in TARGETS}
    if set(node.get('optionalDependencies',{}))!=expected_keys:raise ReleaseError('refuse to repair unknown/missing Node platform target')
    node['version']=version;node['optionalDependencies']={name:version for name in node['optionalDependencies']}
    lock=root/'Cargo.lock';text=lock.read_text();parts=re.split(r'(?m)(?=^\[\[package\]\])',text)
    seen=set()
    for i,part in enumerate(parts):
        if not part.startswith('[[package]]'):continue
        value=tomllib.loads(part)['package'][0]
        if value['name'] in names and 'source' not in value:
            if value['name'] in seen:raise ReleaseError('duplicate local Cargo lock package')
            seen.add(value['name'])
            parts[i],n=re.subn(r'(?m)^version = "[^"]+"$', 'version = '+json.dumps(version),part,count=1)
            if n!=1:raise ReleaseError('ambiguous Cargo lock version')
    if seen!=names:raise ReleaseError('missing local Cargo lock package')
    # Validate all candidate changes before replacing any source metadata.
    for member in workspace['members']:
        if read_toml(root/member/'Cargo.toml')['package'].get('version')!={'workspace':True}:raise ReleaseError('crate version must inherit before syncing')
    python=read_toml(root/'bindings/python/pyproject.toml')['project']
    if 'version' in python or python.get('dynamic',[]).count('version')!=1:raise ReleaseError('Python version must derive from Cargo')
    cargo.write_text(content[:section.start(1)]+changed+content[section.end(1):])
    node_path.write_text(json.dumps(node,indent=2)+'\n');lock.write_text(''.join(parts))
    return check(root)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    sub=parser.add_subparsers(dest='operation',required=True)
    check_parser=sub.add_parser('check');check_parser.add_argument('--tag');check_parser.add_argument('--plain',action='store_true')
    sync_parser=sub.add_parser('sync');sync_parser.add_argument('--version')
    args=parser.parse_args()
    try:
        result=check(args.root,args.tag) if args.operation=='check' else sync(args.root,args.version)
    except (ReleaseError,KeyError,ValueError) as error:
        parser.exit(2,'release version refused: '+str(error)+'\n')
    print(result['version'] if getattr(args,'plain',False) else json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
