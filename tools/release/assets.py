"""Exact unsigned release artifact inspection, deterministic staging and comparison.

These guards associate explicit artifacts; they do not authenticate a compiler
or claim any unexecuted platform. Native version smoke remains a build gate.
"""
from __future__ import annotations
import argparse
import base64
import csv
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import itertools
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import zipfile
from version import TARGETS, ReleaseError, check

MAX_MEMBER=256*1024*1024
MAX_ARCHIVE=1024*1024*1024

def sha(path: Path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1024*1024):digest.update(chunk)
    return digest.hexdigest()

def wire(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def safe_name(name: str):
    path=PurePosixPath(name)
    if not name or '\\' in name or path.is_absolute() or any(p in ('..','.') for p in path.parts) or str(path)!=name:
        raise ReleaseError('unsafe archive member path')
    return name

def tar_members(path: Path):
    if path.stat().st_size>MAX_ARCHIVE:raise ReleaseError('archive exceeds size limit')
    result={};total=0
    with tarfile.open(path,'r:*') as archive:
        for member in archive:
            safe_name(member.name)
            if member.isdir():continue
            if not member.isfile() or member.name in result or member.size>MAX_MEMBER:raise ReleaseError('invalid or duplicate archive member')
            total+=member.size
            if total>MAX_ARCHIVE:raise ReleaseError('expanded archive exceeds size limit')
            result[member.name]=archive.extractfile(member).read()
    return result

def wheel_members(path: Path):
    if path.stat().st_size>MAX_ARCHIVE:raise ReleaseError('wheel exceeds size limit')
    with zipfile.ZipFile(path) as archive:
        result={};total=0
        for member in archive.infolist():
            safe_name(member.filename.rstrip('/'))
            if member.is_dir():continue
            if member.filename in result or member.file_size>MAX_MEMBER or (member.external_attr>>16)&0o170000==0o120000:
                raise ReleaseError('invalid or duplicate wheel member')
            total+=member.file_size
            if total>MAX_ARCHIVE:raise ReleaseError('expanded wheel exceeds size limit')
            result[member.filename]=archive.read(member)
    return result

def binary_target(data: bytes):
    if data.startswith(b'\x7fELF'):
        if len(data)<20 or data[4]!=2 or data[5] not in (1,2):raise ReleaseError('unsupported ELF binary')
        machine=struct.unpack_from('<H' if data[5]==1 else '>H',data,18)[0]
        return 'linux', {62:'x64',183:'arm64'}.get(machine)
    if data[:4] in (b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf'):
        if len(data)<8:raise ReleaseError('truncated Mach-O binary')
        machine=struct.unpack_from('<I' if data[0]==0xcf else '>I',data,4)[0]
        return 'darwin',{0x1000007:'x64',0x100000c:'arm64'}.get(machine)
    if data.startswith(b'MZ') and len(data)>=64:
        at=struct.unpack_from('<I',data,60)[0]
        if at+6>len(data) or data[at:at+4]!=b'PE\0\0':raise ReleaseError('invalid PE binary')
        return 'win32',{0x8664:'x64'}.get(struct.unpack_from('<H',data,at+4)[0])
    raise ReleaseError('not a supported native release binary')

def require_binary(data: bytes,target: str):
    expected=tuple(target.split('-')[:2])
    if binary_target(data)!=expected:raise ReleaseError('native binary OS/architecture does not match selected target')

# Release build profiles, not evidence of execution on these platforms. Builders
# must produce these exact floors; an arbitrary newer floor is not substituted.
WHEEL_PLATFORM={'linux-x64-gnu':'manylinux_2_28_x86_64','linux-arm64-gnu':'manylinux_2_28_aarch64','linux-x64-musl':'musllinux_1_2_x86_64','linux-arm64-musl':'musllinux_1_2_aarch64','darwin-x64':'macosx_11_0_x86_64','darwin-arm64':'macosx_11_0_arm64','win32-x64-msvc':'win_amd64'}

def wheel_tags(filename: str,tags: list[str],target: str,version: str):
    """Match the complete filename expansion to uncompressed WHEEL tags.

    This deliberately accepts only our release's cp311/abi3 build profile,
    rather than serving as a general Python installer tag parser.
    """
    if target not in WHEEL_PLATFORM:raise ReleaseError('unknown release target')
    if len(filename)>255 or not filename.endswith('.whl'):raise ReleaseError('invalid wheel filename')
    fields=filename[:-4].split('-')
    if len(fields) not in (5,6) or fields[:2]!=['peerwork_sdk',version]:raise ReleaseError('wheel filename identity/version mismatch')
    build=fields[2] if len(fields)==6 else None
    if build is not None and not re.fullmatch(r'[0-9][A-Za-z0-9_]*',build):raise ReleaseError('invalid wheel build tag')
    components=[field.split('.') for field in fields[-3:]]
    if any(not values or len(values)!=len(set(values)) or any(not re.fullmatch(r'[a-z0-9_]+',value) for value in values) for values in components):raise ReleaseError('invalid wheel filename tag grammar')
    expected={'cp311-abi3-'+WHEEL_PLATFORM[target]}
    expanded={'-'.join(values) for values in itertools.product(*components)}
    # Reject duplicate/compressed/malformed metadata tags and every extra tag,
    # including cross-arch alternatives and different compatibility floors.
    if not tags or len(tags)>64 or len(tags)!=len(set(tags)) or any(len(tag)>128 or not re.fullmatch(r'[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+',tag) for tag in tags):raise ReleaseError('invalid WHEEL tag grammar')
    if set(tags)!=expanded:raise ReleaseError('wheel filename and WHEEL tags disagree')
    if expanded!=expected:raise ReleaseError('wheel interpreter/ABI/platform release profile mismatch')

def inspect(root: Path,target: str,cli: Path,wheel: Path,node_root: Path,node_platform: Path):
    identity=check(root)
    if target not in TARGETS:raise ReleaseError('unknown release target')
    version=identity['version'];files=wheel_members(wheel)
    metas=[n for n in files if n.endswith('.dist-info/METADATA')]
    if len(metas)!=1:raise ReleaseError('wheel must have exactly one METADATA')
    prefix=metas[0].rsplit('/',1)[0]
    metadata=BytesParser().parsebytes(files[metas[0]])
    if metadata['Name']!='peerwork-sdk' or metadata['Version']!=version:raise ReleaseError('wheel release identity/version mismatch')
    wheel_data=BytesParser().parsebytes(files[prefix+'/WHEEL'])
    tags=wheel_data.get_all('Tag',[])
    wheel_tags(wheel.name,tags,target,version)
    native=[n for n in files if n.startswith('peerwork/') and n.endswith(('.so','.pyd'))]
    if len(native)!=1 or 'peerwork/py.typed' not in files:raise ReleaseError('wheel missing unique native module or py.typed')
    require_binary(files[native[0]],target)
    records=list(csv.reader(io.StringIO(files[prefix+'/RECORD'].decode())))
    seen=set()
    for row in records:
        if len(row)!=3 or row[0] in seen or row[0] not in files:raise ReleaseError('invalid wheel RECORD coverage')
        seen.add(row[0]);name,digest,size=row
        if name==prefix+'/RECORD':
            if digest or size:raise ReleaseError('RECORD must be unhashed')
        elif digest!='sha256='+base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b'=').decode() or size!=str(len(files[name])):
            raise ReleaseError('wheel RECORD hash/size mismatch')
    if seen!=set(files):raise ReleaseError('wheel RECORD does not cover exact contents')
    package=tar_members(node_root);root_meta=json.loads(package['package/package.json'])
    expected=json.loads((root/'bindings/node/package.json').read_text())
    if root_meta!=expected:raise ReleaseError('npm wrapper does not match exact checked source metadata')
    expected_wrapper={'package/package.json'}|{'package/'+name for name in expected['files']}
    if set(package)!=expected_wrapper:raise ReleaseError('npm wrapper file closure mismatch')
    for name in expected['files']:
        if package['package/'+name]!=(root/'bindings/node'/name).read_bytes():raise ReleaseError('npm wrapper source file mismatch')
    platform=tar_members(node_platform);platform_meta=json.loads(platform['package/package.json'])
    os,cpu,*libc=target.split('-')
    if platform_meta.get('name')!='@peerwork/agent-sdk-'+target or platform_meta.get('version')!=version or platform_meta.get('os')!=[os] or platform_meta.get('cpu')!=[cpu] or platform_meta.get('license')!=expected['license'] or platform_meta.get('repository')!=expected['repository']:
        raise ReleaseError('npm native package identity/target/version mismatch')
    if os=='linux' and platform_meta.get('libc')!=['glibc' if libc==['gnu'] else 'musl']:raise ReleaseError('npm libc selection mismatch')
    keys={'name','version','description','license','repository','os','cpu','files','main'}|({'libc'} if os=='linux' else set())
    if set(platform_meta)!=keys or platform_meta['main']!='index.cjs':raise ReleaseError('unexpected npm native metadata or install hooks')
    if platform.get('package/index.cjs')!=b"'use strict';\nmodule.exports = require('./index.node');\n":raise ReleaseError('unexpected npm native loader')
    allowed={'package/package.json','package/index.node','package/index.cjs','package/README.md','package/LICENSE'}
    if os=='linux' and libc==['musl']:allowed|={'package/lib/'+name for name in ['libc++.so.1','libc++abi.so.1','libunwind.so.1']}|{'package/LLVM-LICENSE.txt'}
    if set(platform)!=allowed:raise ReleaseError('npm native file closure mismatch')
    require_binary(platform['package/index.node'],target);require_binary(cli.read_bytes(),target)
    if os=='linux' and libc==['musl']:
        for filename in ['lib/libc++.so.1','lib/libc++abi.so.1','lib/libunwind.so.1','LLVM-LICENSE.txt']:
            if 'package/'+filename not in platform:raise ReleaseError('missing actual bundled musl runtime/license')
    for bundle in [package,platform]:
        if 'package/LICENSE' not in bundle or 'package/README.md' not in bundle:raise ReleaseError('npm package missing license/readme')
    return dict(version=version,target=target,files=[dict(name=p.name,bytes=p.stat().st_size,sha256=sha(p)) for p in [cli,wheel,node_root,node_platform]],scope='package identity, RECORD and native binary architecture; not execution/platform or source-compiler proof')

def deterministic_tar(path: Path,entries: dict[str,tuple[bytes,int]],epoch: int):
    with path.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as archive:
        for name,(data,mode) in sorted(entries.items()):
            safe_name(name);info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.mtime=epoch;info.uid=info.gid=0;info.uname=info.gname='';archive.addfile(info,io.BytesIO(data))

def inventory(directory: Path):
    if directory.is_symlink() or not directory.is_dir():raise ReleaseError('artifact inventory must be a real directory')
    result={}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():raise ReleaseError('symlink in artifact inventory')
        if path.is_file():result[path.relative_to(directory).as_posix()]=dict(bytes=path.stat().st_size,sha256=sha(path))
    if not result:raise ReleaseError('empty artifact inventory')
    return result

def compare(left: Path,right: Path):
    before=inventory(left);after=inventory(right)
    if before!=after:raise ReleaseError('unsigned artifact names/lengths/exact bytes are not reproducible')
    return dict(equal=True,files=len(before),scope='exact unsigned artifacts; signatures/notarization must be separately bound and verified')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('inspect');command.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);command.add_argument('--target',required=True)
    for name in ['cli','wheel','node-root','node-platform']:command.add_argument('--'+name,type=Path,required=True)
    command=commands.add_parser('compare');command.add_argument('left',type=Path);command.add_argument('right',type=Path)
    args=parser.parse_args()
    try:result=inspect(args.root,args.target,args.cli,args.wheel,args.node_root,args.node_platform) if args.command=='inspect' else compare(args.left,args.right)
    except (ReleaseError,KeyError,ValueError,tarfile.TarError,zipfile.BadZipFile) as error:parser.exit(2,'release asset refused: '+str(error)+'\n')
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
