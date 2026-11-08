"""Sign and notarize selected macOS assets after exact unsigned comparison.

Requires a preconfigured protected Developer ID keychain/notary profile. This
script neither discovers credentials nor publishes. All Apple commands must
actually succeed; timestamps are bound to final bytes, never normalized away.
"""
import argparse
import base64
import csv
from datetime import datetime,timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from assets import sha,wire,inventory,wheel_members,tar_members,deterministic_tar,require_binary
import stage
from version import ReleaseError,check

spec=importlib.util.spec_from_file_location('ci_verify',Path(__file__).with_name('ci-verify.py'));ci=importlib.util.module_from_spec(spec);spec.loader.exec_module(ci)

def validate_unsigned(root,directory,tag):
    identity=check(root,tag);revision,epoch=stage.source(root)
    manifest=json.loads((directory/'release.json').read_text())
    if manifest['source_commit']!=revision or manifest['source_date_epoch']!=epoch or manifest['version']!=identity['version'] or manifest['tag']!=tag or manifest['unsigned'] is not True or set(manifest['targets'])!=set(stage.TARGETS):raise ReleaseError('unsigned release source/tag/target conflict')
    actual=inventory(directory)
    if set(actual)!=set(manifest['assets'])|{'release.json','SHA256SUMS'} or {name:actual[name] for name in manifest['assets']}!=manifest['assets']:raise ReleaseError('unsigned release checksum/closure conflict')
    required=''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(actual.items()) if name!='SHA256SUMS')
    if (directory/'SHA256SUMS').read_text()!=required:raise ReleaseError('unsigned release checksum manifest conflict')
    return manifest

def write_wheel(path,files,epoch):
    record=next(name for name in files if name.endswith('.dist-info/RECORD'))
    rows=io.StringIO();writer=csv.writer(rows,lineterminator='\n')
    for name,data in sorted(files.items()):
        if name!=record:writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(),len(data)])
    writer.writerow([record,'','']);files[record]=rows.getvalue().encode()
    stamp=datetime.fromtimestamp(max(epoch,315532800),timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,stamp);info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16;archive.writestr(info,data)

def sign(root,directory,target,output,identity,profile,tag,repository,keychain):
    if target not in {'darwin-x64','darwin-arm64'}:raise ReleaseError('macOS signing target required')
    if not identity or not profile or not keychain.is_file():raise ReleaseError('configured Developer ID and protected notarization keychain required')
    manifest=validate_unsigned(root,directory,tag)
    for path in sorted(directory.rglob('*')):
        if path.is_file():ci.verify_subject(path,repository,manifest['source_commit'],tag,'release.yml')
    if output.exists():raise ReleaseError('signed output must be fresh')
    names=manifest['targets'][target]['package_assets'];selected=[names[0],names[1],names[3]]
    files_by_asset={names[0]:wheel_members(directory/names[0]),names[1]:tar_members(directory/names[1]),names[3]:tar_members(directory/names[3])}
    binaries={names[0]:[name for name in files_by_asset[names[0]] if name.startswith('peerwork/') and name.endswith('.so')],names[1]:['package/index.node'],names[3]:['peerwork']}
    if any(len(names)!=1 for names in binaries.values()):raise ReleaseError('exact three macOS compiled subjects required')
    bindings=[]
    with tempfile.TemporaryDirectory(prefix='peerwork-macos-sign-') as temporary:
        work=Path(temporary);work.chmod(0o700)
        signed_paths=[]
        for asset in selected:
            for name in binaries[asset]:
                data=files_by_asset[asset][name];require_binary(data,target)
                path=work/'signed'/asset/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o755)
                subprocess.run(['codesign','--force','--sign',identity,'--keychain',str(keychain),'--options','runtime','--timestamp',str(path)],check=True)
                subprocess.run(['codesign','--verify','--strict',str(path)],check=True)
                signed_paths.append(path)
                bindings.append(dict(asset=asset,member=name,unsigned_sha256=hashlib.sha256(data).hexdigest(),signed_sha256=sha(path),signature_verified=True))
                files_by_asset[asset][name]=path.read_bytes()
        submission=work/'notary-submission.zip'
        with zipfile.ZipFile(submission,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            for path in signed_paths:archive.write(path,path.relative_to(work/'signed').as_posix())
        result=subprocess.run(['xcrun','notarytool','submit',str(submission),'--keychain-profile',profile,'--keychain',str(keychain),'--wait','--output-format','json'],capture_output=True,text=True)
        if result.returncode!=0:raise ReleaseError('macOS notarization failed')
        notarization=json.loads(result.stdout)
        if notarization.get('status')!='Accepted' or not re.fullmatch(r'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',notarization.get('id','')):raise ReleaseError('macOS notarization not accepted')
        for path in signed_paths:subprocess.run(['codesign','--verify','--strict',str(path)],check=True)
        output.mkdir(parents=True)
        write_wheel(output/names[0],files_by_asset[names[0]],manifest['source_date_epoch'])
        stage.validate_record(wheel_members(output/names[0]))
        for asset in [names[1],names[3]]:
            deterministic_tar(output/asset,{name:(data,0o755 if name=='peerwork' else 0o644) for name,data in files_by_asset[asset].items()},manifest['source_date_epoch'])
        receipt=dict(source_commit=manifest['source_commit'],tag=tag,target=target,unsigned_release_manifest_sha256=sha(directory/'release.json'),notarization=dict(id=notarization['id'],status='Accepted',submission_sha256=sha(submission)),binaries=bindings,assets=[dict(name=name,unsigned_sha256=sha(directory/name),signed_sha256=sha(output/name),signed_bytes=(output/name).stat().st_size) for name in selected],scope='verified Developer ID signatures plus accepted ZIP notarization; standalone executables/extensions have no staplable app/pkg/dmg container')
        (output/'macos-signing.json').write_bytes(wire(receipt))
        (output/'SHA256SUMS').write_text(''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(inventory(output).items())))
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--unsigned',type=Path,required=True);parser.add_argument('--target',required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--identity',required=True);parser.add_argument('--notary-profile',required=True);parser.add_argument('--keychain',type=Path,required=True);parser.add_argument('--tag',required=True);parser.add_argument('--repository',required=True);args=parser.parse_args()
    try:result=sign(args.root,args.unsigned,args.target,args.output,args.identity,args.notary_profile,args.tag,args.repository,args.keychain)
    except (ReleaseError,subprocess.CalledProcessError,ValueError) as error:parser.exit(2,'macOS signing refused: '+str(error)+'\n')
    print(json.dumps(dict(target=result['target'],source_commit=result['source_commit'],notarization_status='Accepted')))
