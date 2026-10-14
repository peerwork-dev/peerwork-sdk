"""Fresh unsigned release bundles: exact source/target assets and dependencies.

A builder must supply the artifacts and target-filtered Cargo metadata. This
local association is later authenticated by CI provenance, not this collector.
"""
from __future__ import annotations
import argparse
import csv
from datetime import datetime,timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from assets import inspect,sha,wire,deterministic_tar,inventory,tar_members,wheel_members
from version import TARGETS,ReleaseError,check
import notices
import sbom


def source(root: Path):
    revision=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}',revision):raise ReleaseError('invalid selected Git source')
    if subprocess.check_output(['git','-C',str(root),'status','--porcelain','--untracked-files=no'],text=True).strip():raise ReleaseError('tracked source changes block release staging')
    epoch=int(subprocess.check_output(['git','-C',str(root),'show','-s','--format=%ct','HEAD'],text=True))
    return revision,epoch


def license_payload(document,license_inventory,files):
    return dict(files,**{'sbom.spdx.json':wire(document),'licenses.json':wire(license_inventory)})


def embed_wheel(path: Path,payload: dict[str,bytes],output: Path,epoch: int):
    """Copy untouched compiled bytes; add data and rebuild every RECORD hash."""
    import base64
    import zipfile
    files=wheel_members(path)
    record=next(name for name in files if name.endswith('.dist-info/RECORD'))
    files.pop(record)
    if any(name.startswith('peerwork/third_party/') for name in files):raise ReleaseError('wheel already has ambiguous third-party payload')
    files.update({'peerwork/third_party/'+name:data for name,data in payload.items()})
    rows=io.StringIO();writer=csv.writer(rows,lineterminator='\n')
    for name,data in sorted(files.items()):writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(),len(data)])
    writer.writerow([record,'','']);files[record]=rows.getvalue().encode()
    # ZIP has a 1980 lower bound; preserve a deterministic, valid timestamp.
    stamp=datetime.fromtimestamp(max(epoch,315532800),timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(files.items()):
            entry=zipfile.ZipInfo(name,stamp);entry.compress_type=zipfile.ZIP_DEFLATED;entry.external_attr=0o100644<<16;archive.writestr(entry,data)


def embed_platform(path: Path,payload: dict[str,bytes],output: Path,epoch: int):
    files=tar_members(path);metadata=json.loads(files['package/package.json'])
    if any(name.startswith('package/third_party/') for name in files):raise ReleaseError('npm platform already has ambiguous third-party payload')
    metadata['files']=[*metadata['files'],'third_party/']
    files['package/package.json']=wire(metadata)
    files.update({'package/third_party/'+name:data for name,data in payload.items()})
    deterministic_tar(output,{name:(data,0o644) for name,data in files.items()},epoch)


def validate_embedded(wheel: Path,platform: Path,payload: dict[str,bytes]):
    files=wheel_members(wheel);expected={'peerwork/third_party/'+name:data for name,data in payload.items()}
    if {name:data for name,data in files.items() if name.startswith('peerwork/third_party/')}!=expected:raise ReleaseError('wheel dependency/license payload substitution')
    files=tar_members(platform);expected={'package/third_party/'+name:data for name,data in payload.items()}
    if {name:data for name,data in files.items() if name.startswith('package/third_party/')}!=expected:raise ReleaseError('npm dependency/license payload substitution')
    metadata=json.loads(files['package/package.json'])
    if metadata['files'].count('third_party/')!=1:raise ReleaseError('npm embedded license closure mismatch')


def validate_record(files):
    import base64
    records=[name for name in files if name.endswith('.dist-info/RECORD')]
    if len(records)!=1:raise ReleaseError('staged wheel must have one RECORD')
    record=records[0];seen=set()
    for row in csv.reader(io.StringIO(files[record].decode())):
        if len(row)!=3 or row[0] not in files or row[0] in seen:raise ReleaseError('staged wheel RECORD coverage')
        name,digest,length=row;seen.add(name)
        if name==record:
            if digest or length:raise ReleaseError('staged RECORD must be unhashed')
        elif digest!='sha256='+base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b'=').decode() or length!=str(len(files[name])):raise ReleaseError('staged wheel RECORD hash/size substitution')
    if seen!=set(files):raise ReleaseError('staged wheel RECORD incomplete')


def validate_final(root,target,directory,payload,asset_names):
    """Inspect original package closure after exact payload and RECORD checks.

    Temporary core archives are validation inputs only. No release file is
    rewritten or installed, and no compiler/source authenticity is inferred.
    """
    version=check(root)['version']
    if asset_names[1:]!=['peerwork-agent-sdk-'+target+'-'+version+'.tgz','peerwork-agent-sdk-'+version+'.tgz','peerwork-'+version+'-'+target+'.tar.gz']:raise ReleaseError('release package filename identity mismatch')
    wheel,platform,wrapper,cli_archive=[directory/name for name in asset_names]
    validate_embedded(wheel,platform,payload)
    wheel_files=wheel_members(wheel);validate_record(wheel_files)
    platform_files=tar_members(platform);metadata=json.loads(platform_files['package/package.json'])
    expected_files=['index.node','index.cjs','lib/','LICENSE','README.md']+(['LLVM-LICENSE.txt'] if target.endswith('musl') else [])+['third_party/']
    if metadata['files']!=expected_files:raise ReleaseError('staged npm published file list mismatch')
    cli_files=tar_members(cli_archive);cli_name='peerwork.exe' if target.startswith('win32') else 'peerwork'
    if set(cli_files)!={cli_name,'LICENSE'}|{'third_party/'+name for name in payload}:raise ReleaseError('CLI release archive closure mismatch')
    if cli_files['LICENSE']!=(root/'LICENSE').read_bytes() or {name[len('third_party/'):]:data for name,data in cli_files.items() if name.startswith('third_party/')}!=payload:raise ReleaseError('CLI release notice substitution')
    with tempfile.TemporaryDirectory(prefix='peerwork-release-verify-') as temporary:
        temp=Path(temporary)
        cli=temp/cli_name;cli.write_bytes(cli_files[cli_name])
        # Exact embedded payload was checked above; remove it only in private
        # validation copies and rebuild their RECORD without changing tags.
        clean_wheel={name:data for name,data in wheel_files.items() if not name.startswith('peerwork/third_party/')}
        record=next(name for name in clean_wheel if name.endswith('.dist-info/RECORD'));clean_wheel.pop(record)
        import base64,zipfile
        rows=io.StringIO();writer=csv.writer(rows,lineterminator='\n')
        for name,data in sorted(clean_wheel.items()):writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(),len(data)])
        writer.writerow([record,'','']);clean_wheel[record]=rows.getvalue().encode()
        core_wheel=temp/wheel.name
        with zipfile.ZipFile(core_wheel,'w') as archive:
            for name,data in clean_wheel.items():archive.writestr(name,data)
        clean_platform={name:data for name,data in platform_files.items() if not name.startswith('package/third_party/')}
        metadata['files']=expected_files[:-1];clean_platform['package/package.json']=wire(metadata)
        core_platform=temp/platform.name;deterministic_tar(core_platform,{name:(data,0o644) for name,data in clean_platform.items()},0)
        inspect(root,target,cli,core_wheel,wrapper,core_platform)
        notices.wheel(root,core_wheel);notices.platform(root,target,core_platform)


def stage(root: Path,target: str,cli: Path,wheel: Path,node_root: Path,node_platform: Path,metadata: dict,output: Path,input_source_commit: str):
    identity=check(root);revision,epoch=source(root)
    if not re.fullmatch('[0-9a-f]{40}',input_source_commit):raise ReleaseError('exact compiled input source commit required')
    if output.exists():raise ReleaseError('release output must be fresh')
    original=inspect(root,target,cli,wheel,node_root,node_platform)
    notices.platform(root,target,node_platform);notices.wheel(root,wheel)
    document,license_inventory,files=sbom.generate(root,target,metadata,revision,epoch)
    payload=license_payload(document,license_inventory,files)
    names=[wheel.name,node_platform.name,node_root.name,'peerwork-'+identity['version']+'-'+target+'.tar.gz']
    if len(set(names))!=4 or set(names)&{'release.json','SHA256SUMS','sbom.spdx.json','licenses.json'}:raise ReleaseError('release asset basename collision')
    output.mkdir(parents=True)
    embed_wheel(wheel,payload,output/wheel.name,epoch)
    embed_platform(node_platform,payload,output/node_platform.name,epoch)
    shutil.copyfile(node_root,output/node_root.name)
    cli_name='peerwork.exe' if target.startswith('win32') else 'peerwork'
    archive_name='peerwork-'+identity['version']+'-'+target+'.tar.gz'
    deterministic_tar(output/archive_name,{cli_name:(cli.read_bytes(),0o755),'LICENSE':((root/'LICENSE').read_bytes(),0o644),**{'third_party/'+name:(data,0o644) for name,data in payload.items()}},epoch)
    (output/'sbom.spdx.json').write_bytes(wire(document));(output/'licenses.json').write_bytes(wire(license_inventory))
    validate_embedded(output/wheel.name,output/node_platform.name,payload)
    # Compiled inputs are never modified by metadata/license repacking.
    if next(data for name,data in wheel_members(output/wheel.name).items() if name.endswith(('.so','.pyd')) and name.startswith('peerwork/'))!=next(data for name,data in wheel_members(wheel).items() if name.endswith(('.so','.pyd')) and name.startswith('peerwork/')) or tar_members(output/node_platform.name)['package/index.node']!=tar_members(node_platform)['package/index.node']:raise ReleaseError('metadata repacking changed compiled bytes')
    validate_final(root,target,output,payload,names)
    manifest=dict(version=identity['version'],target=target,source_commit=revision,input_source_commit=input_source_commit,release_eligible=input_source_commit==revision,source_date_epoch=epoch,unsigned=True,scope='declared input source and packaging source association; source agreement is necessary, verified CI build provenance and platform execution are separate gates',original_inputs=original['files'],package_assets=names,assets=inventory(output))
    (output/'release.json').write_bytes(wire(manifest))
    rows=inventory(output);(output/'SHA256SUMS').write_text(''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(rows.items())))
    return manifest


def verify(directory: Path,root: Path):
    manifest=json.loads((directory/'release.json').read_text())
    revision,epoch=source(root)
    keys={'version','target','source_commit','input_source_commit','release_eligible','source_date_epoch','unsigned','scope','original_inputs','package_assets','assets'}
    if set(manifest)!=keys or manifest.get('target') not in TARGETS or manifest.get('source_commit')!=revision or manifest.get('source_date_epoch')!=epoch or manifest.get('version')!=check(root)['version'] or manifest.get('unsigned') is not True:raise ReleaseError('invalid release identity')
    if not isinstance(manifest['input_source_commit'],str) or not re.fullmatch('[0-9a-f]{40}',manifest['input_source_commit']) or manifest['release_eligible'] is not (manifest['input_source_commit']==revision):raise ReleaseError('invalid compiled source agreement')
    expected=manifest['assets']
    actual=inventory(directory)
    if set(actual)!=set(expected)|{'release.json','SHA256SUMS'}:raise ReleaseError('release file closure mismatch')
    if {name:actual[name] for name in expected}!=expected:raise ReleaseError('release asset checksum/size mismatch')
    required=''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(actual.items()) if name!='SHA256SUMS')
    if (directory/'SHA256SUMS').read_text()!=required:raise ReleaseError('release checksum manifest substitution')
    document=json.loads((directory/'sbom.spdx.json').read_text());licenses=json.loads((directory/'licenses.json').read_text())
    if licenses['source_commit']!=manifest['source_commit'] or licenses['target']!=manifest['target'] or licenses['version']!=manifest['version'] or licenses['unknown_bundled_licenses']!=[]:raise ReleaseError('release dependency identity/conflict')
    if len(manifest['package_assets'])!=4 or len(set(manifest['package_assets']))!=4 or set(expected)!=set(manifest['package_assets'])|{'sbom.spdx.json','licenses.json'}:raise ReleaseError('release package roster mismatch')
    from assets import safe_name
    for name in manifest['package_assets']:
        if safe_name(name)!=Path(name).name:raise ReleaseError('release package must use a basename')
    # Embedded license files must be exactly those bound by the separately
    # checksummed source inventory, not caller-added unbounded payloads.
    wheel_files=wheel_members(directory/manifest['package_assets'][0])
    license_files={name[len('peerwork/third_party/'):]:data for name,data in wheel_files.items() if name.startswith('peerwork/third_party/') and name not in {'peerwork/third_party/sbom.spdx.json','peerwork/third_party/licenses.json'}}
    expected_notices={}
    for component in licenses['components']:
        for notice in component['notices']:
            name=notice['file'];digest=notice['sha256']
            if name in expected_notices and expected_notices[name]!=digest:raise ReleaseError('conflicting dependency notice association')
            expected_notices[name]=digest
    if {name:hashlib.sha256(data).hexdigest() for name,data in license_files.items()}!=expected_notices:raise ReleaseError('embedded dependency notices do not match source inventory')
    validate_final(root,manifest['target'],directory,license_payload(document,licenses,license_files),manifest['package_assets'])
    return manifest


def assemble(root: Path,bundles: Path,output: Path,tag: str):
    identity=check(root,tag);revision,epoch=source(root)
    if bundles.is_symlink() or not bundles.is_dir() or {p.name for p in bundles.iterdir()}!=set(TARGETS):raise ReleaseError('complete exact seven-target release bundles required')
    if output.exists():raise ReleaseError('release assembly output must be fresh')
    manifests={}
    for target in TARGETS:
        manifest=verify(bundles/target,root)
        if manifest['target']!=target:raise ReleaseError('bundle directory/target disagreement')
        if not manifest['release_eligible']:raise ReleaseError('compiled input source differs from selected release source')
        manifests[target]=manifest
    wrappers={sha(bundles/target/manifest['package_assets'][2]) for target,manifest in manifests.items()}
    if len(wrappers)!=1:raise ReleaseError('root npm wrapper differs across target builders')
    output.mkdir(parents=True)
    selected={};targets={}
    for target,manifest in manifests.items():
        names=manifest['package_assets']
        for name in names:
            candidate=bundles/target/name
            if name in selected:
                if name!=names[2] or selected[name]!=sha(candidate):raise ReleaseError('release asset name collision')
                continue
            shutil.copyfile(candidate,output/name);selected[name]=sha(candidate)
        target_dir=output/'dependencies'/target;target_dir.mkdir(parents=True)
        for name in ['sbom.spdx.json','licenses.json']:shutil.copyfile(bundles/target/name,target_dir/name)
        targets[target]=dict(bundle_manifest_sha256=sha(bundles/target/'release.json'),package_assets=names)
    manifest=dict(version=identity['version'],tag=tag,source_commit=revision,source_date_epoch=epoch,unsigned=True,targets=targets,assets=inventory(output))
    (output/'release.json').write_bytes(wire(manifest))
    (output/'SHA256SUMS').write_text(''.join(value['sha256']+'  '+name+'\n' for name,value in sorted(inventory(output).items())))
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('stage');command.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);command.add_argument('--target',required=True)
    for name in ['cli','wheel','node-root','node-platform','metadata','output']:command.add_argument('--'+name,type=Path,required=True)
    command.add_argument('--input-source-commit',required=True)
    command=commands.add_parser('verify');command.add_argument('directory',type=Path);command.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    command=commands.add_parser('assemble');command.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);command.add_argument('--bundles',type=Path,required=True);command.add_argument('--output',type=Path,required=True);command.add_argument('--tag',required=True)
    args=parser.parse_args()
    try:
        result=assemble(args.root,args.bundles,args.output,args.tag) if args.command=='assemble' else verify(args.directory,args.root) if args.command=='verify' else stage(args.root,args.target,args.cli,args.wheel,args.node_root,args.node_platform,json.loads(args.metadata.read_text()),args.output,args.input_source_commit)
    except (ReleaseError,KeyError,ValueError) as error:parser.exit(2,'release stage refused: '+str(error)+'\n')
    print(json.dumps(dict(target=result.get('target'),source_commit=result['source_commit'],version=result['version'],assets=len(result['assets']),unsigned=result['unsigned']),sort_keys=True))
if __name__=='__main__':main()
