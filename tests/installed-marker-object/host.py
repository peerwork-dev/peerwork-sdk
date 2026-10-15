"""Three installed selected final object-stage handoffs; reuse accepted composition host primitives."""
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
FIXTURE_SDK=ROOTFS/'work/sdk-coordination-d47bbd5'
NODE=ROOTFS/'opt/node24/bin/node'
PIN='7dd319713708c417e5bc6026be1cf32ca598cfde'
SOURCE_MANIFEST='9e2900b85d4097ab3e3b0e9f403f5a56ff22442a3e90df857e6f83f91d083e0e'
ARTIFACT_MANIFEST=os.environ['PEERWORK_MARKER_ARTIFACT_MANIFEST_SHA256']
assert len(ARTIFACT_MANIFEST)==64 and all(c in '0123456789abcdef' for c in ARTIFACT_MANIFEST)
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
name=sys.argv[1] if len(sys.argv)>1 else 'final-affected-object-first'
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
 argv=[str(NODE)]+(['--require',str(SDK/'tests/staged-install-request-observer.cjs')] if kind=='kernel' else [])+[str(script)]
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
cases=[('python','marker-before-command'),('node','command-before-pending'),('cli','cleanup-applied')]
if os.environ.get('PEERWORK_MARKER_ONLY_INTERFACE'):cases=[pair for pair in cases if pair[0]==os.environ['PEERWORK_MARKER_ONLY_INTERFACE']]
assert cases
for interface,mode in cases:
 case=state/interface;case.mkdir(mode=0o700)
 try:
  kernel=start(case,'kernel');origin=kernel['origin'];source_dir=case/'source'
  produced=subprocess.run([str(NODE),str(SDK/'tests/legacy-owner-marker-object-stage.mjs'),origin,str(source_dir),str(REFERENCE),mode],capture_output=True,text=True,timeout=120)
  for suffix,text in [('stdout',produced.stdout),('stderr',produced.stderr)]:p=case/('source-'+suffix+'.log');p.write_text(text);p.chmod(0o600)
  (case/'source-returncode.json').write_text(json.dumps({'exit_code':produced.returncode})+'\n')
  assert produced.returncode==0,'genuine marker fixture failed'
  item=json.loads(produced.stdout);assert item['part_count']==4 and item['compiler_equality']and item['cut_saved_before_throw']
  code="""import{readFileSync}from'node:fs';import{pathToFileURL}from'node:url';
const[path,root,workspace,instance]=process.argv.slice(1);const{secureHash}=await import(pathToFileURL(root+'/dist-workspace/src/workspace-secure-client.js').href);const{readProtocolObjectSource}=await import(pathToFileURL(root+'/dist-workspace/src/workspace-protocol-object-source.js').href);
const state=JSON.parse(readFileSync(path)),marker=state.protocol_object_stage_intents[workspace+'.'+instance];if(Object.keys(state.pending).length||Object.keys(state.protocol_install_intents??{}).length)throw Error('marker fixture has pending install');console.log(JSON.stringify({path:'/api/workspace/v1/secure/workspaces/'+workspace+'/commits',marker_hash:await secureHash(marker),logical_value:readProtocolObjectSource(marker.proof,marker.parts)}));"""
  oracle=json.loads(subprocess.check_output([str(NODE),'--input-type=module','-e',code,item['state_path'],str(REFERENCE),item['workspace_id'],item['instance_id']],text=True));assert oracle['marker_hash']==item['marker_hash'];item['compiler_oracle']=oracle
  import sqlite3
  with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True)as db:
   assert db.execute('SELECT count(*)FROM secure_commits WHERE workspace_id=?',(item['workspace_id'],)).fetchone()[0]==1+item['expected_accepted_parts']
  item['interface']=interface;item['fixture_dir']='source';guest_case='/work/'+name+'/'+interface
  for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:item[key]=guest_case+'/'+str(Path(item[key]).relative_to(case))
  fixture=dict(origin=origin,sources=[item],request_log=guest_case+'/requests.jsonl',fixture_request_lines=len((case/'requests.jsonl').read_text().splitlines()))
  f=case/'host-fixture.json';f.write_text(json.dumps(fixture));f.chmod(0o600);guest_overlay='/work/'+name+'-overlay'
  guards={key:sha(SDK/path)for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-marker-object-stage.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256'),('tests/legacy-owner-install-object-material.mjs','PEERWORK_TEST_OBJECT_HELPER_SHA256')]}
  program='''task_root="$1";guest_case="$2";guest_overlay="$3";interface="$4";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
 PYTHONPATH=/work/sdk-marker-t023-20261015/dist/python-consumer PEERWORK_TEST_SDK_ROOT=/work/sdk-marker-t023-20261015 \
 PEERWORK_TEST_STATE="$guest_case" PEERWORK_TEST_HOST_FIXTURE_JSON="$guest_case/host-fixture.json" PEERWORK_TEST_INTERFACE="$interface" \
 PEERWORK_TEST_NODE=/opt/node24/bin/node PEERWORK_TEST_NODE_PACKAGE=/work/sdk-marker-t023-20261015/dist/node-consumer/node_modules/@peerwork/agent-sdk \
 PEERWORK_TEST_CLI=/work/sdk-marker-t023-20261015/target/release/peerwork \
 PEERWORK_TEST_ATTACH_SOURCE_SHA256="$5" PEERWORK_TEST_LEGACY_HELPER_SHA256="$6" PEERWORK_TEST_REFERENCE_FIXTURE_SHA256="$7" PEERWORK_TEST_OBJECT_HELPER_SHA256="$8" \
 /opt/python/cp311-cp311/bin/python "$guest_overlay/consumer.py"
'''
  started=time.time();completed=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'consumer',str(ROOTFS),guest_case,guest_overlay,interface,*guards.values()],capture_output=True,text=True,timeout=480)
  for suffix,text in [('stdout',completed.stdout),('stderr',completed.stderr)]:p=case/('consumer.'+suffix);p.write_text(text);p.chmod(0o600)
  terminal=dict(interface=interface,mode=mode,exit_code=completed.returncode,duration_seconds=time.time()-started)
  if completed.returncode==0:terminal['result']=json.loads(completed.stdout.splitlines()[-1])
  results.append(terminal);print(json.dumps(terminal),flush=True)
 finally:stop();verify_cohort()
(state/'summary.json').write_text(json.dumps(dict(source=PIN,interfaces=results),indent=2)+'\n')
assert len(results)==len(cases) and all(r['exit_code']==0 for r in results),'installed marker cases failed'
