"""Verify exact reusable-builder subjects before native reproducibility/assembly.

Runs only in the release job with its read-only ephemeral GitHub token. This is
an actual provenance verification path, not a local credentials/status probe.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
from assets import compare,sha,wire
import stage
from version import TARGETS,ReleaseError,check

def verify_subject(path,repository,source,tag,workflow='release-build.yml'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository):raise ReleaseError('invalid selected repository')
    if workflow not in {'release-build.yml','release.yml'}:raise ReleaseError('unknown trusted release workflow')
    signer=repository+'/.github/workflows/'+workflow
    command=['gh','attestation','verify',str(path),'--repo',repository,'--signer-workflow',signer,'--signer-digest',source,'--source-digest',source,'--source-ref','refs/tags/'+tag,'--deny-self-hosted-runners','--format','json']
    completed=subprocess.run(command,capture_output=True,text=True)
    if completed.returncode!=0:raise ReleaseError('exact builder/source/subject provenance refused')
    if not isinstance(json.loads(completed.stdout),list) or not json.loads(completed.stdout):raise ReleaseError('missing verified attestation result')
    return dict(name=path.name,sha256=sha(path),repository=repository,source_commit=source,source_ref='refs/tags/'+tag,signer_workflow=signer,verified=True)

def prepare(root,artifacts,output,repository,tag):
    check(root,tag);source,epoch=stage.source(root)
    expected={'release-unsigned-'+replica+'-'+target for replica in ['1','2'] for target in TARGETS}
    if artifacts.is_symlink() or not artifacts.is_dir() or {p.name for p in artifacts.iterdir()}!=expected:raise ReleaseError('exact fourteen independently built bundles required')
    proof=[]
    for target in TARGETS:
        left=artifacts/('release-unsigned-1-'+target);right=artifacts/('release-unsigned-2-'+target)
        for directory in [left,right]:
            manifest=stage.verify(directory,root)
            if manifest['target']!=target or not manifest['release_eligible']:raise ReleaseError('native bundle target/source conflict')
            for path in sorted(directory.iterdir()):
                if not path.is_file() or path.is_symlink():raise ReleaseError('unexpected builder subject')
                proof.append(verify_subject(path,repository,source,tag))
        compare(left,right)
    selected=root/'.release-selected'
    if selected.exists() or output.exists():raise ReleaseError('release verification outputs must be fresh')
    selected.mkdir()
    for target in TARGETS:shutil.copytree(artifacts/('release-unsigned-1-'+target),selected/target)
    result=stage.assemble(root,selected,output,tag)
    # Proof remains separate from the unsigned reproducibility comparison.
    (root/'.release-provenance.json').write_bytes(wire(dict(source_commit=source,source_date_epoch=epoch,subjects=proof,independent_native_build_comparison='exact unsigned inventories')))
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--repository',required=True);parser.add_argument('--tag',required=True);args=parser.parse_args()
    try:result=prepare(args.root,args.artifacts,args.output,args.repository,args.tag)
    except (ReleaseError,ValueError) as error:parser.exit(2,'release provenance refused: '+str(error)+'\n')
    print(json.dumps(dict(source_commit=result['source_commit'],targets=len(result['targets']),unsigned=True)))
