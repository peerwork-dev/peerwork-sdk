"""Exact package notice/template binding; presence alone is not acceptance."""
from pathlib import Path
from assets import tar_members,wheel_members
from version import TARGETS,ReleaseError

def platform(root: Path,target: str,path: Path):
    if target not in TARGETS:raise ReleaseError('unknown notice target')
    files=tar_members(path)
    expected={'package/LICENSE':(root/'bindings/node/LICENSE').read_bytes(),
        'package/README.md':('# @peerwork/agent-sdk-'+target+'\n\nExperimental platform binary. See the root SDK package for scoped verified operations and limits.\n').encode()}
    if target.endswith('musl'):expected['package/LLVM-LICENSE.txt']=(root/'third_party/llvm-20.1.8-LICENSE.txt').read_bytes()
    for name,data in expected.items():
        if files.get(name)!=data:raise ReleaseError('platform source notice or generated README substitution')
    return {'exact_source_notices':len(expected),'target':target}

def wheel(root: Path,path: Path):
    files=wheel_members(path)
    own=[name for name in files if name.endswith('.dist-info/licenses/LICENSE')]
    if len(own)!=1 or files[own[0]]!=(root/'bindings/python/LICENSE').read_bytes():raise ReleaseError('wheel source license substitution')
    if files.get('peerwork/LLVM-LICENSE.txt')!=(root/'bindings/python/peerwork/LLVM-LICENSE.txt').read_bytes():raise ReleaseError('wheel distributed LLVM notice substitution')
    return {'exact_source_notices':2,'scope':'distributed license bytes; not inference that LLVM runtime is bundled on this target'}
