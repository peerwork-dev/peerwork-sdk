"""Bind exact unsigned inputs to provenance-verified macOS signed assets."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
from assets import sha,wire,inventory,tar_members,wheel_members,require_binary
import stage
from version import ReleaseError,check

ROOT=Path(__file__).resolve().parents[2]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tools/release'/(name.replace('_','-')+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
macos=module('macos_sign');ci=module('ci_verify')

def finalize(root,unsigned,signed,output,repository,tag):
    original=macos.validate_unsigned(root,unsigned,tag);source=original['source_commit']
    if signed.is_symlink() or not signed.is_dir() or {p.name for p in signed.iterdir()}!={'release-signed-darwin-x64','release-signed-darwin-arm64'}:raise ReleaseError('both signed macOS target bundles required')
    if output.exists():raise ReleaseError('final release output must be fresh')
    for path in sorted(unsigned.rglob('*')):
        if path.is_file():ci.verify_subject(path,repository,source,tag,'release.yml')
    receipts={}
    for target in ['darwin-x64','darwin-arm64']:
        directory=signed/('release-signed-'+target)
        receipt=json.loads((directory/'macos-signing.json').read_text())
        if set(receipt)!={'source_commit','tag','target','unsigned_release_manifest_sha256','notarization','binaries','assets','scope'} or receipt['source_commit']!=source or receipt['target']!=target or receipt['tag']!=tag or receipt['unsigned_release_manifest_sha256']!=sha(unsigned/'release.json'):raise ReleaseError('macOS signed source/input conflict')
        notary=receipt['notarization']
        if set(notary)!={'id','status','submission_sha256'} or notary['status']!='Accepted' or not re.fullmatch(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',notary['id']):raise ReleaseError('accepted macOS notarization receipt required')
        names=original['targets'][target]['package_assets'];expected=[names[0],names[1],names[3]]
        if len(receipt['assets'])!=3 or [row['name'] for row in receipt['assets']]!=expected or set(inventory(directory))!=set(expected)|{'macos-signing.json','SHA256SUMS'}:raise ReleaseError('macOS signed asset roster conflict')
        values=inventory(directory)
        sums=''.join(row['sha256']+'  '+name+'\n' for name,row in sorted(values.items()) if name!='SHA256SUMS')
        if (directory/'SHA256SUMS').read_text()!=sums:raise ReleaseError('macOS signed checksum substitution')
        for path in directory.iterdir():ci.verify_subject(path,repository,source,tag,'release.yml')
        bindings=[]
        for row in receipt['assets']:
            name=row['name'];path=directory/name
            if set(row)!={'name','unsigned_sha256','signed_sha256','signed_bytes'} or row['unsigned_sha256']!=sha(unsigned/name) or row['signed_sha256']!=sha(path) or row['signed_bytes']!=path.stat().st_size:raise ReleaseError('macOS signed asset/input byte conflict')
            before=wheel_members(unsigned/name) if name.endswith('.whl') else tar_members(unsigned/name)
            after=wheel_members(path) if name.endswith('.whl') else tar_members(path)
            if set(before)!=set(after):raise ReleaseError('macOS signing changed package closure')
            compiled=[member for member in before if member=='peerwork' or member=='package/index.node' or member.startswith('peerwork/') and member.endswith('.so')]
            if len(compiled)!=1:raise ReleaseError('one compiled macOS member per asset required')
            member=compiled[0];require_binary(after[member],target)
            import hashlib
            bindings.append(dict(asset=name,member=member,unsigned_sha256=hashlib.sha256(before[member]).hexdigest(),signed_sha256=hashlib.sha256(after[member]).hexdigest(),signature_verified=True))
            allowed={member}|({next(p for p in before if p.endswith('.dist-info/RECORD'))} if name.endswith('.whl') else set())
            if any(before[p]!=after[p] for p in before if p not in allowed):raise ReleaseError('macOS signing changed unsigned package data')
            if name.endswith('.whl'):stage.validate_record(after)
        if receipt['binaries']!=bindings:raise ReleaseError('macOS member signature binding conflict')
        receipts[target]=receipt
    shutil.copytree(unsigned,output)
    for target,receipt in receipts.items():
        for row in receipt['assets']:shutil.copyfile(signed/('release-signed-'+target)/row['name'],output/row['name'])
        (output/('macos-signing-'+target+'.json')).write_bytes(wire(receipt))
    manifest=dict(original,unsigned=False,unsigned_release_manifest_sha256=sha(unsigned/'release.json'),unsigned_assets=original['assets'],macos_signing={target:'macos-signing-'+target+'.json' for target in receipts})
    manifest['assets']={name:row for name,row in inventory(output).items() if name not in {'release.json','SHA256SUMS'}}
    (output/'release.json').write_bytes(wire(manifest))
    (output/'SHA256SUMS').write_text(''.join(row['sha256']+'  '+name+'\n' for name,row in sorted(inventory(output).items()) if name!='SHA256SUMS'))
    return manifest

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--unsigned',type=Path,required=True);parser.add_argument('--signed',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--repository',required=True);parser.add_argument('--tag',required=True);args=parser.parse_args()
    try:result=finalize(args.root,args.unsigned,args.signed,args.output,args.repository,args.tag)
    except (ReleaseError,ValueError,KeyError) as error:parser.exit(2,'final release refused: '+str(error)+'\n')
    print(json.dumps(dict(source_commit=result['source_commit'],targets=len(result['targets']),macos_signing_targets=len(result['macos_signing']))))
