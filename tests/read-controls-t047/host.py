"""Three installed creation-time coordination cases; no model."""
from pathlib import Path
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import sys
import time

COHORT=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/marker-sdk-t023-20261015')
ROOTFS=(COHORT/'rootfs').resolve()
REFERENCE=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006')
HERE=Path(__file__).resolve().parent
SDK=ROOTFS/'work/sdk-marker-t023-20261015'
NODE=ROOTFS/'opt/node24/bin/node'
PIN='7dd319713708c417e5bc6026be1cf32ca598cfde'
SOURCE_MANIFEST='9e2900b85d4097ab3e3b0e9f403f5a56ff22442a3e90df857e6f83f91d083e0e'
ARTIFACT_MANIFEST=os.environ['PEERWORK_MARKER_ARTIFACT_MANIFEST_SHA256']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify_cohort():
 assert sha(COHORT/'source-manifest-final.sha256')==SOURCE_MANIFEST
 assert sha(COHORT/'artifact-manifest.sha256')==ARTIFACT_MANIFEST
 subprocess.run(['sha256sum','-c','--status',str(COHORT/'source-manifest-final.sha256')],cwd=SDK,check=True)
 subprocess.run(['sha256sum','-c','--status',str(COHORT/'artifact-manifest.sha256')],cwd=COHORT,check=True)
verify_cohort()
assert subprocess.check_output(['git','-C',str(REFERENCE),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
subprocess.run(['git','-C',str(REFERENCE),'diff','--quiet','HEAD','--','src','tests','scripts','protocols','package.json','package-lock.json','tsconfig.workspace.json'],check=True)
compiled=REFERENCE/'dist-workspace/src';files=sorted(compiled.rglob('*.js'));digest=hashlib.sha256()
for file in files:digest.update(str(file.relative_to(compiled)).encode()+b'\0'+sha(file).encode()+b'\n')
assert len(files)==204 and digest.hexdigest()=='6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc'
# Existing fixture scripts add their source/module/compiler/dependency guards.
name=sys.argv[1] if len(sys.argv)>1 else 'coordination-genesis-d47-first'
assert name and len(name)<=64 and all(c.isalnum() or c=='-' for c in name)
state=ROOTFS/'work'/name;assert not state.exists();state.mkdir(mode=0o700)
overlay=ROOTFS/'work'/(name+'-overlay');assert not overlay.exists();overlay.mkdir(mode=0o700)
for file in ['consumer.py','request-observer.cjs','reference-kernel-server.mjs']:shutil.copyfile(HERE/file,overlay/file)
(STATE_META:=state/'overlay-files.json').write_text(json.dumps({file:sha(overlay/file) for file in ['consumer.py','request-observer.cjs','reference-kernel-server.mjs']},indent=2)+'\n');STATE_META.chmod(0o600)
services=[]
def start(case,kind):
 directory=case/kind;directory.mkdir(mode=0o700)
 if kind=='kernel':(case/'requests.jsonl').touch(mode=0o600)
 stderr_path=directory/'stderr.log';stderr_path.touch(mode=0o600);stderr=stderr_path.open('wb')
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(directory),PEERWORK_SDK_ROOT=str(SDK))
 script=overlay/'reference-kernel-server.mjs'
 if kind=='kernel':env.update(PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_PUBLIC_READ='1',PEERWORK_TEST_PUBLIC_INSTALL_PAGES='1',PEERWORK_TEST_REQUEST_OBSERVER=str(case/'requests.jsonl'))
 argv=[str(NODE)]+(['--require',str(overlay/'request-observer.cjs')] if kind=='kernel' else [])+[str(script)]
 process=subprocess.Popen(argv,env=env,stdout=subprocess.PIPE,stderr=stderr,text=True)
 services.append((process,stderr,stderr_path,directory))
 select=selectors.DefaultSelector();select.register(process.stdout,selectors.EVENT_READ)
 try:
  if not select.select(60):raise RuntimeError('fixture READY timeout; protected stderr '+str(stderr_path))
  line=process.stdout.readline()
  if not line:raise RuntimeError('fixture startup failed; protected stderr '+str(stderr_path))
  return json.loads(line)
 finally:select.close()
def stop():
 while services:
  process,stderr,stderr_path,directory=services.pop()
  process.terminate()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
  stderr.close()
  path=directory/'service-exit.json';path.write_text(json.dumps(dict(exit_code=process.returncode,stderr_sha256=sha(stderr_path)))+'\n');path.chmod(0o600)
results=[]
for interface in ['python','node','cli']:
 profile=interface;visibility='PUBLIC';version=None
 case=state/profile;case.mkdir(mode=0o700)
 try:
  kernel=start(case,'kernel');origin=kernel['origin'];public=kernel['public_read']
  import sqlite3
  with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:
   commits=db.execute('SELECT artifact FROM secure_commits ORDER BY sequence').fetchall();policies=db.execute('SELECT artifact FROM secure_policies ORDER BY version').fetchall()
   assert len(commits)==52 and policies
   bound=sum(len(row[0].encode()) for row in commits+policies)
  guest_case='/work/'+name+'/'+interface
  controls=os.environ.get('PEERWORK_READ_CONTROLS_STAGE','all');assert controls in ['all','timeout-only']
  fixture=dict(controls=controls,origin=origin,interface=interface,public=public,bound=bound,pem=guest_case+'/kernel/synthetic-public-read-owner.pem',request_log=guest_case+'/requests.jsonl')
  path=case/'host-fixture.json';path.write_text(json.dumps(fixture));path.chmod(0o600)
  program='''task_root="$1";guest_case="$2";guest_overlay="$3";profile="$4";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
 /bin/bash -euc '
 umask 077
 guest_case="$1";guest_overlay="$2";profile="$3"
 PEERWORK_TEST_SDK_ROOT=/work/sdk-marker-t023-20261015 PEERWORK_TEST_STATE="$guest_case" PEERWORK_TEST_HOST_FIXTURE_JSON="$guest_case/host-fixture.json" PEERWORK_TEST_CLI=/work/sdk-marker-t023-20261015/target/release/peerwork PEERWORK_TEST_NODE=/opt/node24/bin/node PEERWORK_TEST_NODE_PACKAGE=/work/sdk-marker-t023-20261015/dist/node-consumer/node_modules/@peerwork/agent-sdk PYTHONPATH=/work/sdk-marker-t023-20261015/dist/python-consumer \
 /opt/python/cp311-cp311/bin/python -B "$guest_overlay/consumer.py"
 ' runtime "$guest_case" "$guest_overlay" "$profile"
'''
  run=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'consumer',str(ROOTFS),guest_case,'/work/'+name+'-overlay',profile],capture_output=True,text=True,timeout=180)
  out=case/'consumer.stdout';out.write_text(run.stdout);out.chmod(0o600)
  err=case/'consumer.stderr';err.write_text(run.stderr);err.chmod(0o600)
  terminal=dict(profile=profile,interface=interface,visibility=visibility,version=version,exit_code=run.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err))
  if run.returncode==0:terminal['result']=json.loads(run.stdout.splitlines()[-1])
  results.append(terminal);print(json.dumps(terminal),flush=True)
 finally:
  stop()
  verify_cohort()
path=state/'summary.json';path.write_text(json.dumps(dict(source=PIN,classification='operator_synthetic',cases=results),indent=2)+'\n');path.chmod(0o600)
assert len(results)==3 and all(r['exit_code']==0 for r in results),'read-control cases failed; inspect protected logs'
