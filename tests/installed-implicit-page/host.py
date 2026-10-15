"""One installed implicit retained-PAGE source-gone case; no model."""
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
ARTIFACT_MANIFEST='15cb4a56a213cb497c114b3d61a73692bad82b0e1d4f1cf632b1c65ad233466f'
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
name=sys.argv[1] if len(sys.argv)>1 else 'implicit-page-d47-first'
assert name and len(name)<=64 and all(c.isalnum() or c=='-' for c in name)
state=ROOTFS/'work'/name;assert not state.exists();state.mkdir(mode=0o700)
overlay=ROOTFS/'work'/(name+'-overlay');assert not overlay.exists();overlay.mkdir(mode=0o700)
for file in ['consumer.py','producer.mjs']:shutil.copyfile(HERE/file,overlay/file)
(STATE_META:=state/'overlay-files.json').write_text(json.dumps({file:sha(overlay/file) for file in ['consumer.py','producer.mjs']},indent=2)+'\n');STATE_META.chmod(0o600)
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
for interface in ['python']:
 case=state/interface;case.mkdir(mode=0o700)
 try:
  kernel=start(case,'kernel');origin=kernel['origin']
  source_dir=case/'source';mode='direct-implicit-page-before-post'
  produced=subprocess.run([str(NODE),str(HERE/'producer.mjs'),origin,str(source_dir),str(REFERENCE),mode],capture_output=True,text=True,timeout=120,env=dict(os.environ,PEERWORK_TEST_SDK_ROOT=str(SDK)))
  diagnostic=case/'source-stderr.log';diagnostic.write_text(produced.stderr);diagnostic.chmod(0o600)
  raw=case/'source-stdout.json';raw.write_text(produced.stdout);raw.chmod(0o600)
  assert produced.returncode==0,'genuine fixture authoring failed; inspect protected source-stderr.log'
  item=json.loads(produced.stdout)
  assert item['mode']==mode and item['pending_count']==1 and item['pending_sequence']==item['latest_sequence']+1
  assert item['pending_action_id']=='secure.structure.page' and item['explicit_dependency_count']==0 and item['original_dependencies_omitted'] is True and item['authenticated_dependency_count']==1 and item['compiler_equality'] is True
  assert item['latest_structure_state']=='SEEDING' and item['latest_sequence']==item['initial_sequence']+1
  import sqlite3
  with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:
   rows=db.execute('SELECT sequence,command_id,action_id,commit_hash FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(item['workspace_id'],)).fetchall()
  assert len(rows)==item['latest_sequence'] and rows[-1][2]=='secure.structure.begin'
  item['original_begin_command_id']=rows[-1][1];item['original_begin_commit_hash']=rows[-1][3]
  code="""import {readFileSync} from 'node:fs';import {pathToFileURL} from 'node:url';
const [path,command,root,materialPath]=process.argv.slice(1);
const {secureHash}=await import(pathToFileURL(root+'/dist-workspace/src/workspace-secure-client.js').href);
const {compilePackageMaterial}=await import(pathToFileURL(root+'/dist-workspace/src/workspace-protocol-package-source.js').href);
const compiled=compilePackageMaterial(JSON.parse(readFileSync(materialPath,'utf8')));
const pending=JSON.parse(readFileSync(path,'utf8')).pending[command];
if(pending.body.commit.payload.command_id!==command||pending.body.commit.payload.action_id!=='secure.structure.page'||Object.keys(pending.body).join(',')!=='commit')throw new Error('selected BEGIN packet mismatch');
console.log(JSON.stringify({request:{method:'POST',path:pending.path,body_sha256:await secureHash(pending.body)},compiled_manifest:compiled.manifest,protocol_digest:compiled.protocolDigest,compiler_own_source_digest:compiled.sourceDigest}));"""
  oracle=json.loads(subprocess.check_output([str(NODE),'--input-type=module','-e',code,item['state_path'],item['pending_command_id'],str(REFERENCE),item['material_path']],text=True))
  assert oracle['protocol_digest']==item['protocol_digest'] 
  item['expected_native_request']=oracle.pop('request');item['compiler_oracle']=oracle
  item['interface']=interface;item['fixture_dir']='source'
  for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:
   path=Path(item[key]);assert path.is_relative_to(source_dir) and path.is_file()
   item[key]='/work/'+name+'/'+interface+'/'+str(path.relative_to(case))
  guest_case='/work/'+name+'/'+interface
  request_log=case/'requests.jsonl'
  fixture=dict(origin=origin,sources=[item],request_log=guest_case+'/requests.jsonl',fixture_request_lines=len(request_log.read_text().splitlines()))
  f=case/'host-fixture.json';f.write_text(json.dumps(fixture));f.chmod(0o600)
  guest_overlay='/work/'+name+'-overlay'
  guards={key:sha(SDK/path) for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-install-intent.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256'),('tests/legacy-owner-install-composition-material.mjs','PEERWORK_TEST_COMPOSITION_HELPER_SHA256')]}
  program='''task_root="$1";guest_case="$2";guest_overlay="$3";interface="$4";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/opt/python/cp311-cp311/bin:/opt/node24/bin:/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
 PYTHONPATH=/work/sdk-coordination-d47bbd5/dist/python-consumer PEERWORK_TEST_SDK_ROOT=/work/sdk-coordination-d47bbd5 \
 PEERWORK_TEST_STATE="$guest_case" PEERWORK_TEST_HOST_FIXTURE_JSON="$guest_case/host-fixture.json" PEERWORK_TEST_INTERFACE="$interface" \
 PEERWORK_TEST_NODE=/opt/node24/bin/node PEERWORK_TEST_NODE_PACKAGE=/work/sdk-coordination-d47bbd5/dist/node-consumer/node_modules/@peerwork/agent-sdk \
 PEERWORK_TEST_CLI=/work/sdk-coordination-d47bbd5/target/release/peerwork \
 PEERWORK_TEST_ATTACH_SOURCE_SHA256="$5" PEERWORK_TEST_LEGACY_HELPER_SHA256="$6" PEERWORK_TEST_REFERENCE_FIXTURE_SHA256="$7" PEERWORK_TEST_COMPOSITION_HELPER_SHA256="$8" \
 /opt/python/cp311-cp311/bin/python "$guest_overlay/consumer.py"
'''
  # One complete independent service/workspace per interface.
  completed=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'consumer',str(ROOTFS),guest_case,guest_overlay,interface,*guards.values()],capture_output=True,text=True,timeout=480)
  out=case/'consumer.stdout';out.write_text(completed.stdout);out.chmod(0o600)
  err=case/'consumer.stderr';err.write_text(completed.stderr);err.chmod(0o600)
  terminal=dict(interface=interface,mode=mode,exit_code=completed.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err))
  if completed.returncode==0:terminal['result']=json.loads(completed.stdout.splitlines()[-1])
  results.append(terminal);print(json.dumps(terminal),flush=True)
 finally:
  stop()
  verify_cohort()
summary=state/'summary.json';summary.write_text(json.dumps(dict(source=PIN,classification='operator_synthetic',interfaces=results),indent=2)+'\n');summary.chmod(0o600)
assert len(results)==1 and all(r['exit_code']==0 for r in results),'implicit PAGE case failed; inspect protected logs'
