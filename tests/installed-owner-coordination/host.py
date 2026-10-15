"""Three independent installed dedicated coordination enable/recovery cases; no model."""
from pathlib import Path
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import sys
import time

COHORT=Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/coordination-sdk-d47bbd5-20261015')
ROOTFS=(COHORT/'rootfs').resolve()
REFERENCE=Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006')
HERE=Path(__file__).resolve().parent
SDK=ROOTFS/'work/sdk-coordination-d47bbd5'
NODE=ROOTFS/'opt/node24/bin/node'
PIN='d47bbd57f5a1e374d6e60cb8f8aa1c565f9c3559'
SOURCE_MANIFEST='8a86e069375614455106c56ed9506552d1254761ceb1e01af922eb66259cfde8'
ARTIFACT_MANIFEST=os.environ['PEERWORK_COORDINATION_ARTIFACT_MANIFEST_SHA256']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def verify_cohort():
 assert sha(COHORT/'source-manifest-d47bbd5.sha256')==SOURCE_MANIFEST
 assert sha(COHORT/'artifact-manifest.sha256')==ARTIFACT_MANIFEST
 subprocess.run(['sha256sum','-c','--status',str(COHORT/'source-manifest-d47bbd5.sha256')],cwd=SDK,check=True)
 subprocess.run(['sha256sum','-c','--status',str(COHORT/'artifact-manifest.sha256')],cwd=COHORT,check=True)
verify_cohort()
assert subprocess.check_output(['git','-C',str(REFERENCE),'rev-parse','HEAD'],text=True).strip()=='f828b6c50a0a58d1e718af90f653b214adcc3328'
subprocess.run(['git','-C',str(REFERENCE),'diff','--quiet','HEAD','--','src','tests','scripts','protocols','package.json','package-lock.json','tsconfig.workspace.json'],check=True)
compiled=REFERENCE/'dist-workspace/src';files=sorted(compiled.rglob('*.js'));digest=hashlib.sha256()
for file in files:digest.update(str(file.relative_to(compiled)).encode()+b'\0'+sha(file).encode()+b'\n')
assert len(files)==204 and digest.hexdigest()=='6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc'
# Existing fixture scripts add their source/module/compiler/dependency guards.
name=sys.argv[1] if len(sys.argv)>1 else 'coordination-d47-first'
assert name and len(name)<=64 and all(c.isalnum() or c=='-' for c in name)
state=ROOTFS/'work'/name;assert not state.exists();state.mkdir(mode=0o700)
overlay=ROOTFS/'work'/(name+'-overlay');assert not overlay.exists();overlay.mkdir(mode=0o700)
for file in ['consumer.py']:shutil.copyfile(HERE/file,overlay/file)
(STATE_META:=state/'overlay-files.json').write_text(json.dumps({file:sha(overlay/file) for file in ['consumer.py']},indent=2)+'\n');STATE_META.chmod(0o600)
services=[]
def start(case,kind):
 directory=case/kind;directory.mkdir(mode=0o700)
 if kind=='kernel':(case/'requests.jsonl').touch(mode=0o600)
 stderr_path=directory/'stderr.log';stderr_path.touch(mode=0o600);stderr=stderr_path.open('wb')
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(directory),PEERWORK_SDK_ROOT=str(SDK))
 script=SDK/'tests/reference-catalog-server.mjs' if kind=='catalog' else SDK/'tests/reference-kernel-server.mjs'
 if kind=='kernel':env.update(PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(case/'requests.jsonl'))
 argv=[str(NODE)]+(['--require',str(SDK/'tests/historical-direct-request-observer.cjs')] if kind=='kernel' else [])+[str(script)]
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
 case=state/interface;case.mkdir(mode=0o700)
 try:
  kernel=start(case,'kernel');origin=kernel['origin'];source_dir=case/'source'
  helper=SDK/'tests/owner-coordination-source.mjs'
  assert sha(helper)=='62414a441bcbc8ff17c1e8b7b201a97e574689f97a74aa73272d81ab8444709c'
  produced=subprocess.run([str(NODE),str(helper),origin,str(source_dir),str(REFERENCE),'PRIVATE'],capture_output=True,text=True,timeout=120)
  for suffix,content in [('stdout',produced.stdout),('stderr',produced.stderr)]:
   path=case/('source-'+suffix+'.log');path.write_text(content);path.chmod(0o600)
  terminal=case/'source-terminal.json';terminal.write_text(json.dumps({'exit_code':produced.returncode})+'\n');terminal.chmod(0o600)
  assert produced.returncode==0,'genuine coordination fixture failed; inspect protected source logs'
  item=json.loads(produced.stdout);assert item['visibility']=='PRIVATE' and item['policy_v']==3 and item['sequence']==3
  item['source_policy']=json.loads((source_dir/'source-policy.json').read_text())
  item['source_record']=json.loads((source_dir/'source-record.json').read_text())
  assert item['source_policy']['payload']['structure_mode']=='NONE' and 'coordination' not in item['source_policy']['payload'].get('structure',{})
  import sqlite3
  with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:
   assert db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(item['workspace_id'],)).fetchone()[0]==3
   assert [r[0] for r in db.execute('SELECT action_id FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(item['workspace_id'],))]==['secure.bootstrap','wiki.create','secure.invite.finalize']
  item['interface']=interface
  for key in ['state_path','pem_path','intent_db_path']:
   path=Path(item[key]);assert path.is_relative_to(source_dir) and path.is_file()
   item[key]='/work/'+name+'/'+interface+'/'+str(path.relative_to(case))
  guest_case='/work/'+name+'/'+interface;request_log=case/'requests.jsonl'
  fixture=dict(origin=origin,source=item,request_log=guest_case+'/requests.jsonl',fixture_request_lines=len(request_log.read_text().splitlines()))
  f=case/'host-fixture.json';f.write_text(json.dumps(fixture));f.chmod(0o600)
  guest_overlay='/work/'+name+'-overlay'
  guards={key:sha(SDK/path) for path,key in [('tests/owner-coordination-source.mjs','PEERWORK_TEST_COORDINATION_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256')]}
  program='''task_root="$1";guest_case="$2";guest_overlay="$3";interface="$4";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
 PYTHONPATH=/work/sdk-coordination-d47bbd5/dist/python-consumer PEERWORK_TEST_SDK_ROOT=/work/sdk-coordination-d47bbd5 \
 PEERWORK_TEST_STATE="$guest_case" PEERWORK_TEST_HOST_FIXTURE_JSON="$guest_case/host-fixture.json" PEERWORK_TEST_INTERFACE="$interface" \
 PEERWORK_TEST_NODE=/opt/node24/bin/node PEERWORK_TEST_NODE_PACKAGE=/work/sdk-coordination-d47bbd5/dist/node-consumer/node_modules/@peerwork/agent-sdk \
 PEERWORK_TEST_CLI=/work/sdk-coordination-d47bbd5/target/release/peerwork \
 PEERWORK_TEST_COORDINATION_HELPER_SHA256="$5" PEERWORK_TEST_REFERENCE_FIXTURE_SHA256="$6" \
 /opt/python/cp311-cp311/bin/python "$guest_overlay/consumer.py"
'''
  completed=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'consumer',str(ROOTFS),guest_case,guest_overlay,interface,*guards.values()],capture_output=True,text=True,timeout=480)
  out=case/'consumer.stdout';out.write_text(completed.stdout);out.chmod(0o600)
  err=case/'consumer.stderr';err.write_text(completed.stderr);err.chmod(0o600)
  terminal=dict(interface=interface,exit_code=completed.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err))
  if completed.returncode==0:terminal['result']=json.loads(completed.stdout.splitlines()[-1])
  results.append(terminal);print(json.dumps(terminal),flush=True)
 finally:
  stop()
  verify_cohort()
summary=state/'summary.json';summary.write_text(json.dumps(dict(source=PIN,classification='operator_synthetic',interfaces=results),indent=2)+'\n');summary.chmod(0o600)
assert len(results)==3 and all(r['exit_code']==0 for r in results),'installed coordination cases failed; inspect protected logs'
