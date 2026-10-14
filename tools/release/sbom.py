"""Deterministic SPDX source dependency inventory and exact bundled notices.

Consumes locked Cargo metadata for a selected build target. This is a source
inventory, not a binary scanner or assertion that build-only packages are linked.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib
from urllib.parse import quote
from version import TARGETS,ReleaseError,check,read_toml
from assets import sha,wire,tar_members

MAX_NOTICE=8*1024*1024
LICENSE_IDS={'MIT','MIT-0','Apache-2.0','BSD-2-Clause','BSD-3-Clause','ISC','Zlib','Unicode-3.0','CC0-1.0','Unlicense'}
EXCEPTIONS={'LLVM-exception'}
ICU_FILES={'third_party/icu4c-78.3/icu4c-78.3-sources.tgz':'3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0','third_party/icu4c-78.3/icudt78l.dat':'790a1d07c4a9e4d7de4eab025cc97b54e0097de2ad94408d190ea55c37fcd7e5'}

def identifier(value):return 'SPDXRef-'+hashlib.sha256(value.encode()).hexdigest()[:32]

def license_expression(value: str):
    # Preserve the actual declaration in licenses.json; Cargo's historical
    # slash spelling has the same OR meaning but is not valid SPDX syntax.
    value={'MIT/Apache-2.0':'MIT OR Apache-2.0'}.get(value,value)
    tokens=re.findall(r'[A-Za-z0-9.+-]+|[()]',value)
    if ''.join(tokens)!=re.sub(r'\s+','',value):raise ReleaseError('unsupported bundled license expression')
    at=0
    def term():
        nonlocal at
        if at>=len(tokens):raise ReleaseError('incomplete bundled license expression')
        token=tokens[at];at+=1
        if token=='(':
            expression()
            if at>=len(tokens) or tokens[at]!=')':raise ReleaseError('unbalanced bundled license expression')
            at+=1
        elif token not in LICENSE_IDS:raise ReleaseError('unknown bundled license identifier: '+token)
        if at<len(tokens) and tokens[at]=='WITH':
            at+=1
            if at>=len(tokens) or tokens[at] not in EXCEPTIONS:raise ReleaseError('unknown bundled license exception')
            at+=1
    def expression():
        nonlocal at
        term()
        while at<len(tokens) and tokens[at] in ('AND','OR'):
            at+=1;term()
    expression()
    if at!=len(tokens):raise ReleaseError('invalid bundled license expression')
    return value

def notices(root: Path,package: dict,checksum: str | None):
    directory=Path(package['manifest_path']).resolve().parent
    manifest=read_toml(directory/'Cargo.toml')['package']
    if manifest['name']!=package['name'] or (manifest.get('version') if isinstance(manifest.get('version'),str) else check(root)['version'])!=package['version']:
        raise ReleaseError('dependency source manifest identity mismatch: '+package['name'])
    declared=manifest.get('license')
    if declared=={'workspace':True}:declared=read_toml(root/'Cargo.toml')['workspace']['package']['license']
    if declared!=package.get('license'):raise ReleaseError('dependency source license declaration mismatch: '+package['name'])
    archive=None
    if checksum:
        cache=directory.parent.parent.parent/'cache'/directory.parent.name/(package['name']+'-'+package['version']+'.crate')
        if not cache.is_file() or sha(cache)!=checksum:
            raise ReleaseError('locked dependency cache/source checksum mismatch: '+package['name'])
        archive=tar_members(cache)
        prefix=package['name']+'-'+package['version']+'/'
        if archive.get(prefix+'Cargo.toml')!=(directory/'Cargo.toml').read_bytes():raise ReleaseError('locked dependency manifest bytes changed: '+package['name'])
    if package.get('source') is None:
        if not directory.is_relative_to(root.resolve()):raise ReleaseError('workspace dependency escaped selected source')
        found=[root/'LICENSE']
    else:
        found=[p for p in sorted(directory.iterdir()) if p.is_file() and p.name.lower().startswith(('license','licence','copying','notice','unlicense'))]
        selected=package.get('license_file')
        if selected:
            chosen=Path(selected).resolve()
            if not chosen.is_relative_to(directory):raise ReleaseError('dependency notice escaped its source: '+package['name'])
            found.append(chosen)
        if not found:
            override= root/'third_party/release-licenses/napi-rs.json'
            if not override.exists():raise ReleaseError('missing bundled source notice: '+package['name'])
            data=json.loads(override.read_text())
            vcs=directory/'.cargo_vcs_info.json'
            selection=data['packages'].get(package['name'],{})
            if selection.get('version')!=package['version'] or package.get('license')!=data['license'] or package.get('repository')!=data['repository'] or not vcs.exists() or json.loads(vcs.read_text())['git']['sha1']!=selection.get('source_revision'):
                raise ReleaseError('missing exact-version bundled source notice: '+package['name'])
            if archive and archive.get(prefix+'.cargo_vcs_info.json')!=vcs.read_bytes():raise ReleaseError('locked dependency source revision changed: '+package['name'])
            chosen=override.parent/data['file']
            if not chosen.resolve().is_relative_to(override.parent.resolve()) or sha(chosen)!=data['sha256']:raise ReleaseError('pinned bundled notice changed')
            found=[chosen]
    result=[]
    for path in dict.fromkeys(found):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_NOTICE:raise ReleaseError('invalid dependency notice: '+package['name'])
        if archive and path.is_relative_to(directory) and archive.get(prefix+path.relative_to(directory).as_posix())!=path.read_bytes():
            raise ReleaseError('locked dependency notice checksum mismatch: '+package['name'])
        origin={'kind':'workspace_source','path':'LICENSE'} if package.get('source') is None else (
            {'kind':'locked_crate','path':path.relative_to(directory).as_posix(),'archive_sha256':checksum} if path.is_relative_to(directory) else
            {'kind':'exact_upstream_notice','url':data['repository'].replace('https://github.com/','https://raw.githubusercontent.com/')+'/'+selection['source_revision']+'/LICENSE','revision':selection['source_revision']})
        result.append((path.name,path.read_bytes(),origin))
    return result

def generate(root: Path,target: str,metadata: dict,source_sha: str,epoch: int):
    identity=check(root)
    if target not in TARGETS or not re.fullmatch('[0-9a-f]{40}',source_sha) or not 0<=epoch<=253402300799:
        raise ReleaseError('invalid selected release source/target/epoch')
    if metadata.get('version')!=1 or Path(metadata['workspace_root']).resolve()!=root.resolve() or not metadata.get('resolve'):
        raise ReleaseError('Cargo metadata does not bind the selected source/resolve graph')
    nodes=metadata['resolve']['nodes'];selected={p['id']:p for p in metadata['packages'] if p['id'] in {n['id'] for n in nodes}}
    if not selected or len(selected)>4096 or len(selected)!=len(nodes):raise ReleaseError('incomplete or duplicate Cargo resolve graph')
    locked=read_toml(root/'Cargo.lock')['package'];packages=[];license_rows=[];notice_files={};package_ids={}
    for package_id,p in sorted(selected.items(),key=lambda item:(item[1]['name'],item[1]['version'],item[1].get('source') or '')):
        source=p.get('source');expression=p.get('license')
        if not isinstance(expression,str) or not expression.strip() or expression.strip().upper() in ('UNKNOWN','NOASSERTION','NONE'):
            raise ReleaseError('unknown bundled dependency license: '+p['name'])
        spdx_expression=license_expression(expression)
        candidates=[x for x in locked if x['name']==p['name'] and x['version']==p['version'] and x.get('source')==source]
        if len(candidates)!=1:raise ReleaseError('dependency does not match locked source: '+p['name'])
        lock=candidates[0]
        if source is not None and (source!='registry+https://github.com/rust-lang/crates.io-index' or not re.fullmatch('[0-9a-f]{64}',lock.get('checksum',''))):raise ReleaseError('unsupported/unhashed dependency source: '+p['name'])
        stable=p['name']+'@'+p['version']+'#'+(source or 'workspace');spdx_id=identifier(stable);package_ids[package_id]=spdx_id
        declared=notices(root,p,lock.get('checksum'));refs=[]
        for filename,contents,origin in declared:
            digest=hashlib.sha256(contents).hexdigest();safe='licenses/'+digest+'-'+re.sub('[^A-Za-z0-9_.-]','_',filename)
            notice_files[safe]=contents;refs.append(dict(file=safe,sha256=digest,source=origin))
        license_rows.append(dict(component=p['name'],version=p['version'],license_declared=expression,source_registry=source,source_archive_sha256=lock.get('checksum'),notices=refs,scope='locked Cargo source dependency; resolve graph includes build/proc-macro dependencies'))
        value=dict(SPDXID=spdx_id,name=p['name'],versionInfo=p['version'],downloadLocation='NOASSERTION',filesAnalyzed=False,licenseConcluded='NOASSERTION',licenseDeclared=spdx_expression,copyrightText='NOASSERTION',externalRefs=[dict(referenceCategory='PACKAGE-MANAGER',referenceType='purl',referenceLocator='pkg:cargo/'+quote(p['name'],safe='')+'@'+quote(p['version'],safe=''))])
        if source:value['checksums']=[dict(algorithm='SHA256',checksumValue=lock['checksum'])]
        else:value['sourceInfo']='Selected workspace source commit '+source_sha
        packages.append(value)
    if set(metadata['workspace_members'])-{*package_ids}:raise ReleaseError('workspace member missing from selected Cargo graph')
    for path,expected in ICU_FILES.items():
        if sha(root/path)!=expected:raise ReleaseError('pinned bundled ICU input changed')
    for name,version,license_name,file in [('ICU4C','78.3','Unicode-3.0','third_party/icu4c-78.3/LICENSE')]+([('LLVM libc++ runtime','20.1.8','Apache-2.0 WITH LLVM-exception','third_party/llvm-20.1.8-LICENSE.txt')] if target.endswith('musl') else []):
        path=root/file
        if path.is_symlink() or not path.is_file():raise ReleaseError('missing actual bundled component license: '+name)
        data=path.read_bytes();digest=hashlib.sha256(data).hexdigest();notice='licenses/'+digest+'-'+path.name
        notice_files[notice]=data;spdx_id=identifier(name+'@'+version)
        packages.append(dict(SPDXID=spdx_id,name=name,versionInfo=version,downloadLocation='NOASSERTION',filesAnalyzed=False,licenseConcluded='NOASSERTION',licenseDeclared=license_name,copyrightText='NOASSERTION',sourceInfo='Pinned vendored native source/runtime; not an OS library inventory',**({'checksums':[dict(algorithm='SHA256',checksumValue=ICU_FILES['third_party/icu4c-78.3/icu4c-78.3-sources.tgz'])]} if name=='ICU4C' else {})))
        license_rows.append(dict(component=name,version=version,license_declared=license_name,notices=[dict(file=notice,sha256=digest)],scope='bundled native component'))
    relationships=[dict(spdxElementId='SPDXRef-DOCUMENT',relationshipType='DESCRIBES',relatedSpdxElement=p['SPDXID']) for p in packages]
    for node in nodes:
        for dependency in node['dependencies']:
            if dependency not in package_ids:raise ReleaseError('dependency edge absent from selected Cargo graph')
            relationships.append(dict(spdxElementId=package_ids[node['id']],relationshipType='DEPENDS_ON',relatedSpdxElement=package_ids[dependency]))
    created=datetime.fromtimestamp(epoch,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    document=dict(spdxVersion='SPDX-2.3',dataLicense='CC0-1.0',SPDXID='SPDXRef-DOCUMENT',name='Peerwork SDK '+identity['version']+' '+target,documentNamespace='https://github.com/peerwork-dev/peerwork-sdk/sbom/'+source_sha+'/'+target+'/'+sha(root/'Cargo.lock'),creationInfo=dict(created=created,creators=['Tool: peerwork-offline-release-sbom']),documentComment='Locked source/build dependency inventory plus pinned bundled ICU and optional LLVM runtime. Not a binary scanner, license opinion, vulnerability verdict or OS/toolchain dependency inventory.',packages=packages,relationships=relationships)
    inventory=dict(source_commit=source_sha,target=target,version=identity['version'],cargo_lock_sha256=sha(root/'Cargo.lock'),source_inventory_scope=document['documentComment'],unknown_bundled_licenses=[],components=license_rows,external_system_runtime='OS/linker/interpreter runtimes are external unless their exact files are separately packaged; no OS bundling inferred')
    return document,inventory,notice_files

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--target',required=True);parser.add_argument('--metadata',type=Path,required=True);parser.add_argument('--source-sha',required=True);parser.add_argument('--epoch',type=int,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        document,inventory,files=generate(args.root,args.target,json.loads(args.metadata.read_text()),args.source_sha,args.epoch)
        if args.output.exists():raise ReleaseError('SBOM output must be fresh')
        args.output.mkdir(parents=True)
        (args.output/'sbom.spdx.json').write_bytes(wire(document));(args.output/'licenses.json').write_bytes(wire(inventory))
        for name,data in files.items():
            path=args.output/name;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
    except (ReleaseError,KeyError,ValueError) as error:parser.exit(2,'release SBOM refused: '+str(error)+'\n')
    print(json.dumps(dict(target=args.target,packages=len(document['packages']),notices=len(files),scope='locked source and actual bundled native licenses'),sort_keys=True))
if __name__=='__main__':main()
