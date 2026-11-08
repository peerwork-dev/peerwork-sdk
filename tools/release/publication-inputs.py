"""Verify final CI-produced bytes, then prepare finite trusted-publisher inputs.

This does not publish or inspect credentials. Registry commands remain in
protected workflow jobs, and incomplete/signed-source conflicts fail closed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import stage
from assets import inventory,sha
from assets import WHEEL_PLATFORM
from version import ReleaseError,check,TARGETS

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ci_verify',ROOT/'tools/release/ci-verify.py');ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(ci)

def prepare(root,directory,output,repository,tag):
    identity=check(root,tag);source,epoch=stage.source(root)
    manifest=json.loads((directory/'release.json').read_text())
    keys={'version','tag','source_commit','source_date_epoch','unsigned','targets','assets','unsigned_release_manifest_sha256','unsigned_assets','macos_signing'}
    if set(manifest)!=keys or manifest['source_commit']!=source or manifest['source_date_epoch']!=epoch or manifest['version']!=identity['version'] or manifest['tag']!=tag or manifest['unsigned'] is not False or set(manifest['targets'])!=set(TARGETS) or manifest['macos_signing']!={target:'macos-signing-'+target+'.json' for target in ['darwin-x64','darwin-arm64']}:raise ReleaseError('complete final signed release identity required')
    version=identity['version']
    wheels=['peerwork_sdk-'+version+'-cp311-abi3-'+WHEEL_PLATFORM[target]+'.whl' for target in TARGETS]
    platforms=['peerwork-agent-sdk-'+target+'-'+version+'.tgz' for target in TARGETS]
    wrapper='peerwork-agent-sdk-'+version+'.tgz'
    cli=['peerwork-'+version+'-'+target+'.tar.gz' for target in TARGETS]
    dependencies={'sbom-'+target+'.spdx.json' for target in TARGETS}|{'licenses-'+target+'.json' for target in TARGETS}
    expected=set(wheels+platforms+cli+[wrapper])|dependencies|set(manifest['macos_signing'].values())
    actual=inventory(directory)
    if set(manifest['assets'])!=expected or set(actual)!=expected|{'release.json','SHA256SUMS'} or {name:actual[name] for name in expected}!=manifest['assets']:raise ReleaseError('final release exact file/checksum closure required')
    sums=''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(actual.items()) if name!='SHA256SUMS')
    if (directory/'SHA256SUMS').read_text()!=sums:raise ReleaseError('final checksum manifest substitution')
    for path in sorted(directory.rglob('*')):
        if path.is_file():ci.verify_subject(path,repository,source,tag,'release.yml')
    if output.exists():raise ReleaseError('publication inputs must be fresh')
    (output/'pypi').mkdir(parents=True);(output/'npm').mkdir()
    for name in wheels:shutil.copyfile(directory/name,output/'pypi'/name)
    # Platform packages first; wrapper last. Registry failures remain partial
    # publication failures, not an atomic multi-registry operation.
    for name in platforms+[wrapper]:shutil.copyfile(directory/name,output/'npm'/name)
    result=dict(source_commit=source,version=version,python_wheels=wheels,node_packages=platforms+[wrapper],registry_atomicity=False)
    (output/'publication-inputs.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--repository',required=True);parser.add_argument('--tag',required=True);args=parser.parse_args()
    try:result=prepare(args.root,args.directory,args.output,args.repository,args.tag)
    except (ReleaseError,ValueError,KeyError) as error:parser.exit(2,'publication inputs refused: '+str(error)+'\n')
    print(json.dumps(dict(source_commit=result['source_commit'],python_wheels=len(result['python_wheels']),node_packages=len(result['node_packages']))))
