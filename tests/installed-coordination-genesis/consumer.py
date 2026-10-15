"""One genuine installed coordinated genesis, selected identity and replay."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from urllib.parse import urlsplit
import peerwork

SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE'])
f=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text());interface=f['interface'];visibility=f['visibility'];version=f['version'];origin=f['origin'];expected=f['identity']
assert (interface,visibility,version) in [('python','PRIVATE',1),('node','PUBLIC',2),('cli','PRIVATE',2)]
assert STATE.stat().st_mode&0o077==0 and origin.startswith('http://127.0.0.1:')
native=STATE/'native';assert not native.exists();config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
name='Native coordinated genesis '+interface
input_file=STATE/'create-input.json';input_file.write_text(json.dumps(dict(name=name,visibility=visibility,structured=True,coordination_version=version)));input_file.chmod(0o600)
log=STATE/'calls.jsonl';log.touch(mode=0o600)
def invoke(operation,command=None,workspace=None):
 if interface=='python':
  if operation=='import':value=peerwork.import_legacy_owner_identity(str(config_file),f['pem'])
  elif operation=='identity':value=peerwork.open_identity(str(native/'identity.state'))
  else:
   owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
   if operation=='create':value=owner.create(name,visibility,structured=True,coordination_version=version)
   elif operation=='resume':value=owner.resume(command)
   elif operation=='operations':value=owner.operations()
   elif operation=='read':value=owner.read(workspace)
   elif operation=='coordination_operations':value=owner.coordination_operations(workspace)
   else:raise AssertionError(operation)
 elif interface=='node':
  code=r'''
void(async()=>{const fs=require('node:fs'),x=JSON.parse(fs.readFileSync(0,'utf8')),sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE);let value;
if(x.operation==='import')value=await sdk.importLegacyOwnerIdentity(x.configFile,x.pem);
else if(x.operation==='identity')value=await sdk.openIdentity(x.identity);
else{const owner=sdk.openSecureOwnerWorkspaces(x.config);switch(x.operation){
case 'create':value=await owner.create({name:x.name,visibility:x.visibility,structured:true,coordinationVersion:x.version});break;
case 'resume':value=await owner.resume(x.command);break;
case 'operations':value=await owner.operations();break;
case 'read':value=await owner.read(x.workspace);break;
case 'coordination_operations':value=await owner.coordinationOperations(x.workspace);break;
default:throw Error('unknown operation');}}console.log(JSON.stringify(value));})().catch(error=>{console.error(JSON.stringify({code:error.code,message:error.message}));process.exitCode=1;});
'''
  payload=dict(operation=operation,config=dict(origin=origin,stateDir=str(native),allowLoopbackHttp=True),configFile=str(config_file),pem=f['pem'],identity=str(native/'identity.state'),name=name,visibility=visibility,version=version,command=command,workspace=workspace)
  run=subprocess.run([os.environ['PEERWORK_TEST_NODE'],'-e',code],input=json.dumps(payload),capture_output=True,text=True,timeout=120);assert run.returncode==0,run.stderr;value=json.loads(run.stdout)
 else:
  if operation=='import':args=['identity','import-legacy-owner-pem',str(config_file),f['pem']]
  elif operation=='identity':args=['identity','info',str(native/'identity.state')]
  elif operation=='create':args=['secure','owner-create',str(config_file),str(input_file)]
  elif operation=='resume':args=['secure','owner-resume',str(config_file),command]
  elif operation=='operations':args=['secure','owner-operations',str(config_file)]
  elif operation=='read':args=['secure','owner-read',str(config_file),workspace]
  elif operation=='coordination_operations':args=['secure','owner-coordination-operations',str(config_file),workspace]
  else:raise AssertionError(operation)
  run=subprocess.run([os.environ['PEERWORK_TEST_CLI'],*args],capture_output=True,text=True,timeout=120);assert run.returncode==0,run.stderr;value=json.loads(run.stdout)
 with log.open('a') as out:out.write(json.dumps(dict(operation=operation,command=command,workspace=workspace,value=value))+'\n')
 return value
def rows(sql,args=()):
 with sqlite3.connect('file:'+str(STATE/'kernel/control.sqlite')+'?mode=ro',uri=True) as db:return db.execute(sql,args).fetchall()
def observed():
 return [r for line in Path(f['request_log']).read_text().splitlines() if (r:=json.loads(line))['host']==urlsplit(origin).netloc]
assert rows('SELECT count(*) FROM secure_workspaces')==[(0,)] and rows('SELECT count(*) FROM secure_commits')==[(0,)] and observed()==[]
identity=invoke('import');assert identity==expected and all(identity[k] for k in ['actor_id','key_id'])
assert invoke('identity')==identity and invoke('operations')==[]
created=invoke('create');assert created['status']=='CREATED' and created['visibility']==visibility and created['sequence']==1 and len(created['head'])==64
workspace=created['workspace_id'];command=created['command_id'];assert len(workspace)==43 and len(command)==43
assert rows('SELECT count(*) FROM secure_workspaces')==[(1,)]
commits=rows('SELECT command_id,sequence,action_id,commit_hash,policy_hash,artifact FROM secure_commits WHERE workspace_id=?',(workspace,));assert len(commits)==1
commit=commits[0];assert commit[:4]==(command,1,'secure.bootstrap',created['head']) and hashlib.sha256(commit[5].encode()).hexdigest()==commit[3]
read=invoke('read',workspace=workspace);assert read['workspace_id']==workspace and read['sequence']==1 and read['head']==created['head'] and read['policy_hash']==commit[4] and read['structure_status']=='ACTIVE'
policy_rows=rows('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,read['policy_hash']));assert len(policy_rows)==1
policy_raw=policy_rows[0][0];assert hashlib.sha256(policy_raw.encode()).hexdigest()==read['policy_hash'];policy=json.loads(policy_raw);payload=policy['payload']
assert payload['visibility']==visibility and payload['owner_id']==identity['actor_id'] and payload['signing_key']==identity['key_id'] and payload['v']==3 and payload['structure_mode']=='STRUCTURED' and payload['effective_sequence']==1 and payload['previous_policy'] is None
assert payload['epoch']==(1 if visibility=='PRIVATE' else 0)
presets=json.loads((SOURCE/'conformance/coordination-presets.json').read_text());preset=[p for p in presets['entries'] if p['version']==version];assert len(preset)==1;preset=preset[0]
digest='644b0a3b04d972f10d4937ba866ac515841a3965231841ed7eb6b43736705291' if version==1 else '24cce0e02c45390f3ecb8efdca92509f6413da42656a7ce2445ad0bc7711ef76';assert preset['digest']==digest
contract=payload['structure'];coord=contract['coordination'];instance=coord['instance_id'];assert len(instance)==43
assert coord==dict(v=version,instance_id=instance,protocol_digest=digest,coordinator=identity['actor_id'],initial_delay_ms=60000,max_delay_ms=3600000,escalate_after=5,window_ms=60000,workspace_limit=60,sender_limit=10,recipient_limit=10)
protocol=[o for o in read['objects'] if o['kind']=='protocols' and o['id']==digest];assert len(protocol)==1
assert protocol[0]['value']['workspace_id']==workspace and protocol[0]['value']['digest']==digest and protocol[0]['value']['manifest']==preset['manifest'] and protocol[0]['value']['resolved_manifest']==preset['manifest']
instances=[o for o in read['objects'] if o['kind']=='instances' and o['id']==instance];assert len(instances)==1
assert instances[0]['value']['protocol_digest']==digest and instances[0]['value']['origin_entrypoint']=='coordination' and instances[0]['value']['state']==preset['manifest']['initial_state']
assert len([o for o in read['objects'] if o['kind']=='protocols'])==7 and len([o for o in read['objects'] if o['kind']=='instances'])==7
spaces=[o for o in read['objects'] if o['kind']=='workspaces'];assert len(spaces)==1 and spaces[0]['id']==workspace and spaces[0]['value']['visibility']==visibility and spaces[0]['value']['owner']==identity['actor_id'] and spaces[0]['value']['name']==name
assert len(payload['members'])==1 and payload['members'][0]['actor_id']==identity['actor_id'] and payload['members'][0]['role']=='OWNER'
scopes=payload['members'][0]['scopes'];assert len(scopes)==7
assert [s for s in scopes if s['instance_id']==instance]==[dict(instance_id=instance,actions=[a['id'] for a in preset['manifest']['actions']],protocol_roles=preset['manifest']['protocol_roles'],capabilities=preset['manifest']['capabilities'])]
assert [i for i in contract['instances'] if i['instance_id']==instance]==[dict(instance_id=instance,protocol_digest=digest)]
requests=observed();assert len(requests)==1
request=requests[0];body='{"commit":'+commit[5]+',"policy":'+policy_raw+'}'
assert request['method']=='POST' and request['path']=='/api/workspace/v1/secure/workspaces' and request['command_id']==command and request['body_sha256']==hashlib.sha256(body.encode()).hexdigest() and request['body_bytes']==len(body.encode())
assert invoke('identity')==identity and invoke('operations')==[dict(created,status='CREATED_LOCAL')] and invoke('coordination_operations',workspace=workspace)==[]
assert invoke('resume',command=command)==created and invoke('read',workspace=workspace)==read
assert rows('SELECT count(*) FROM secure_workspaces')==[(1,)] and rows('SELECT count(*) FROM secure_commits')==[(1,)] and observed()==requests
for name,value in [('verified-read',read),('hash-bound-policy',policy)]:
 path=STATE/(name+'.json');path.write_text(json.dumps(value));path.chmod(0o600)
result=dict(result='PASS',classification='operator_synthetic',interface=interface,visibility=visibility,coordination_version=version,protocol_digest=digest,selected_identity_matches=True,created_sequence=1,signed_structure='ACTIVE',coordination_instances=1,bootstrap_posts=1,service_workspaces=1,service_commits=1,original_command_resume_idempotent=True,separate_install_count=0,policy_artifact_hash_bound_to_verified_read=True)
path=STATE/'effects.json';path.write_text(json.dumps(result,indent=2)+'\n');path.chmod(0o600)
print(json.dumps(result),flush=True)
