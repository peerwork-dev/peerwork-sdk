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
def sha_bytes(value):return hashlib.sha256(value).hexdigest()
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
for file in ['node-consumer.cjs','request-observer.cjs']:shutil.copyfile(HERE/file,overlay/file)
(STATE_META:=state/'overlay-files.json').write_text(json.dumps({file:sha(overlay/file) for file in ['node-consumer.cjs','request-observer.cjs']},indent=2)+'\n');STATE_META.chmod(0o600)
services=[]
def start(case,kind):
 directory=case/kind;directory.mkdir(mode=0o700)
 if kind=='kernel':(case/'requests.jsonl').touch(mode=0o600)
 stderr_path=directory/'stderr.log';stderr_path.touch(mode=0o600);stderr=stderr_path.open('wb')
 env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(REFERENCE),PEERWORK_TEST_STATE=str(directory),PEERWORK_SDK_ROOT=str(SDK))
 script=SDK/'tests/reference-catalog-server.mjs' if kind=='catalog' else SDK/'tests/reference-kernel-server.mjs'
 if kind=='kernel':env.update(PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(case/'requests.jsonl'))
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
for profile in ['node22-gnu']:
 interface='node';visibility='PUBLIC';version=None
 case=state/profile;case.mkdir(mode=0o700)
 try:
  kernel=start(case,'kernel');origin=kernel['origin'];pem=case/'selected-owner.pem'
  code="""const{generateKeyPairSync,createPublicKey,createHash}=require('node:crypto');const{writeFileSync}=require('node:fs');const privateKey=generateKeyPairSync('ed25519').privateKey;writeFileSync(process.argv[1],privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});const publicKey=createPublicKey(privateKey).export({type:'spki',format:'der'}).subarray(-32);console.log(JSON.stringify({actor_id:createHash('sha256').update(Buffer.concat([Buffer.from('peerwork.identity.v1\\0'),publicKey])).digest('base64url'),key_id:publicKey.toString('base64url')}));"""
  generated=subprocess.run([str(NODE),'-e',code,str(pem)],capture_output=True,text=True,timeout=30)
  for suffix,content in [('stdout',generated.stdout),('stderr',generated.stderr)]:
   path=case/('keygen-'+suffix+'.log');path.write_text(content);path.chmod(0o600)
  assert generated.returncode==0
  identity=json.loads(generated.stdout);assert len(identity['actor_id'])==43 and len(identity['key_id'])==43
  guest_case='/work/'+name+'/'+profile
  fixture=dict(profile=profile,origin=origin,interface=interface,visibility=visibility,version=version,identity=identity,pem=guest_case+'/selected-owner.pem',request_log=guest_case+'/requests.jsonl')
  path=case/'host-fixture.json';path.write_text(json.dumps(fixture));path.chmod(0o600)
  program='''task_root="$1";guest_case="$2";guest_overlay="$3";profile="$4";
for device in null zero urandom;do mount --bind "/dev/$device" "$task_root/dev/$device";done
chroot "$task_root" /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
 /bin/bash -euc '
 umask 077
 guest_case="$1";guest_overlay="$2";profile="$3"
 runtime=/work/t038-node22-runtime
 mkdir -m700 "$guest_case/node-consumer"
 PATH="$runtime/bin:/usr/bin:/bin" "$runtime/bin/node" "$runtime/lib/node_modules/npm/bin/npm-cli.js" install --prefix "$guest_case/node-consumer" --offline --ignore-scripts --no-audit --no-fund --no-save /work/sdk-marker-t023-20261015/dist/npm/peerwork-agent-sdk-0.0.1.tgz /work/sdk-marker-t023-20261015/dist/npm/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz >"$guest_case/install.log" 2>&1
 PEERWORK_TEST_STATE="$guest_case" PEERWORK_TEST_NODE_CONSUMER="$guest_case/node-consumer" PEERWORK_TEST_CLI=/work/sdk-marker-t023-20261015/target/release/peerwork \
 "$runtime/bin/node" "$guest_overlay/node-consumer.cjs"
 ' runtime "$guest_case" "$guest_overlay" "$profile"
'''
  run=subprocess.run(['unshare','--user','--map-root-user','--mount','--pid','--fork','/bin/bash','-euc',program,'consumer',str(ROOTFS),guest_case,'/work/'+name+'-overlay',profile],capture_output=True,text=True,timeout=240)
  out=case/'consumer.stdout';out.write_text(run.stdout);out.chmod(0o600)
  err=case/'consumer.stderr';err.write_text(run.stderr);err.chmod(0o600)
  terminal=dict(profile=profile,interface=interface,visibility=visibility,version=version,exit_code=run.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err))
  if run.returncode==0:
   terminal['result']=json.loads(run.stdout.splitlines()[-1])
   import sqlite3
   with sqlite3.connect('file:'+str(case/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:
    assert db.execute('SELECT count(*) FROM secure_workspaces').fetchone()==(1,)
    rows=db.execute('SELECT command_id,sequence,action_id,commit_hash,policy_hash,artifact FROM secure_commits').fetchall();assert len(rows)==1
    row=rows[0];v=terminal['result'];assert row[:5]==(v['command_id'],1,'secure.bootstrap',v['head'],v['policy_hash']) and sha_bytes(row[5].encode())==v['head']
    policy=db.execute('SELECT artifact FROM secure_policies WHERE policy_hash=?',(v['policy_hash'],)).fetchone()[0];assert sha_bytes(policy.encode())==v['policy_hash']
    p=json.loads(policy)['payload'];assert p['visibility']=='PUBLIC' and p['owner_id']==identity['actor_id'] and p['signing_key']==identity['key_id']
    from urllib.parse import urlsplit
    layers=[json.loads(line) for line in (case/'requests.jsonl').read_text().splitlines()]
    requests=[r for r in layers if r['host']==urlsplit(origin).netloc];body='{"commit":'+row[5]+',"policy":'+policy+'}'
    assert len(requests)==1 and requests[0]['body_sha256']==sha_bytes(body.encode())
    assert len(layers)==2 and all(r['command_id']==v['command_id'] and r['body_sha256']==sha_bytes(body.encode()) for r in layers)

  results.append(terminal);print(json.dumps(terminal),flush=True)
 finally:
  stop()
  verify_cohort()
path=state/'summary.json';path.write_text(json.dumps(dict(source=PIN,classification='operator_synthetic',cases=results),indent=2)+'\n');path.chmod(0o600)
assert len(results)==1 and all(r['exit_code']==0 for r in results),'runtime cases failed; inspect protected logs'
