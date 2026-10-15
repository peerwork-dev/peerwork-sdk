"""One installed-interface coordination flow. No hidden native state access."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
import peerwork

SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE'])
for path,key in [('tests/owner-coordination-source.mjs','PEERWORK_TEST_COORDINATION_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256')]:
 assert hashlib.sha256((SOURCE/path).read_bytes()).hexdigest()==os.environ[key]
fixture=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text());item=fixture['source'];interface=os.environ['PEERWORK_TEST_INTERFACE']
assert item['interface']==interface and interface in ['python','node','cli'] and item['sequence']==3 and item['visibility']=='PRIVATE'
origin=fixture['origin'];workspace=item['workspace_id'];actor=item['owner_actor_id'];member=item['member_actor_id']
assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
V1='644b0a3b04d972f10d4937ba866ac515841a3965231841ed7eb6b43736705291';V2='24cce0e02c45390f3ecb8efdca92509f6413da42656a7ce2445ad0bc7711ef76'
database=STATE/'kernel/control.sqlite';native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
source_input=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=actor,expected_owner_key_id=item['owner_key_id'])
source_file=STATE/'source-input.json';source_file.write_text(json.dumps(source_input));source_file.chmod(0o600)
log=STATE/'calls.jsonl';log.touch(mode=0o600)
def dbrows(sql,args=()):
 with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:return db.execute(sql,args).fetchall()
def count():return dbrows('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(workspace,))[0][0]
def observed():
 rows=[json.loads(line) for line in Path(fixture['request_log']).read_text().splitlines()[fixture['fixture_request_lines']:]]
 return [r for r in rows if r['host']==urlsplit(origin).netloc and r['path']==f'/api/workspace/v1/secure/workspaces/{workspace}/commits']
def invoke(operation,*,input=None,begin=None):
 if interface=='python':
  owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
  try:
   if operation=='attach':value=owner.attach(**source_input)
   elif operation=='operations':value=owner.coordination_operations(workspace)
   elif operation=='enable':value=owner.enable_coordination(workspace,**(input or {}))
   elif operation=='resume':value=owner.resume_coordination(workspace,begin)
   elif operation=='read':value=owner.read(workspace)
   else:raise AssertionError(operation)
   result=dict(ok=True,value=value)
  except peerwork.OwnerWorkspaceError as error:result=dict(ok=False,code=error.code)
 elif interface=='node':
  code=r'''
void(async()=>{
const fs=require('node:fs'),sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE),x=JSON.parse(fs.readFileSync(0,'utf8'));
const owner=sdk.openSecureOwnerWorkspaces(x.config);let value;
switch(x.operation){
case 'attach':value=await owner.attach(x.source);break;
case 'operations':value=await owner.coordinationOperations(x.workspace);break;
case 'enable':value=await owner.enableCoordination(x.workspace,x.input);break;
case 'resume':value=await owner.resumeCoordination(x.workspace,x.begin);break;
case 'read':value=await owner.read(x.workspace);break;
default:throw Error('unknown test operation');}
console.log(JSON.stringify({ok:true,value}));
})().catch(error=>console.log(JSON.stringify({ok:false,code:error.code})));
'''
  payload=dict(config=dict(origin=origin,stateDir=str(native),allowLoopbackHttp=True),workspace=workspace,operation=operation,input=input or {},begin=begin)
  if operation=='attach':payload['source']=dict(workspaceId=workspace,protectedTsStatePath=item['state_path'],protectedTsIntentDbPath=item['intent_db_path'],protectedOwnerPkcs8Path=item['pem_path'],expectedOwnerActorId=actor,expectedOwnerKeyId=item['owner_key_id'])
  run=subprocess.run([os.environ['PEERWORK_TEST_NODE'],'-e',code],input=json.dumps(payload),capture_output=True,text=True,timeout=120)
  assert run.returncode==0,'Node installed invocation failed';result=json.loads(run.stdout)
 else:
  if operation=='attach':args=['owner-attach',str(source_file)]
  elif operation=='operations':args=['owner-coordination-operations',workspace]
  elif operation=='enable':
   path=STATE/'enable-input.json';path.write_text(json.dumps(input or {}));path.chmod(0o600);args=['owner-coordination-enable',workspace,str(path)]
  elif operation=='resume':args=['owner-coordination-resume',workspace,begin]
  elif operation=='read':args=['owner-read',workspace]
  else:raise AssertionError(operation)
  run=subprocess.run([os.environ['PEERWORK_TEST_CLI'],'secure',args[0],str(config_file),*args[1:]],capture_output=True,text=True,timeout=120)
  raw=json.loads(run.stdout if run.returncode==0 else run.stderr);result=dict(ok=True,value=raw) if run.returncode==0 else dict(ok=False,code=raw['code'])
 with log.open('a') as output:output.write(json.dumps(dict(operation=operation,input=input,begin=begin,result=result))+'\n')
 return result
def success(operation,**kwargs):
 result=invoke(operation,**kwargs);assert result['ok'],dict(interface=interface,phase=operation,code=result.get('code'));return result['value']
def no_effects(before_count,before_requests):assert count()==before_count and observed()==before_requests

def verify_read(read,version,progress,old_policy):
 assert read['workspace_id']==workspace and read['sequence']==(7 if version==1 else 11) and read['head']==progress['head'] and read['policy_hash']==progress['policy_hash'] and read['structure_status']=='ACTIVE'
 assert [o for o in read['objects'] if o['kind']=='records' and o['id']==item['prior_record_id']]==[item['source_record']]
 wiki=[o for o in read['objects'] if o['kind']=='instances' and o['id']==item['wiki_instance_id']];assert wiki and sorted(o['revision'] for o in wiki)==[1,2]
 instances=[o for o in read['objects'] if o['kind']=='instances' and o['id']==progress['instance_id']];assert len(instances)==1 and instances[0]['value']['protocol_digest']==(V1 if version==1 else V2) and instances[0]['value']['origin_entrypoint']=='coordination'
 policies=dbrows('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,read['policy_hash']));assert len(policies)==1
 raw=policies[0][0];assert hashlib.sha256(raw.encode()).hexdigest()==read['policy_hash']
 policy=json.loads(raw);payload=policy['payload'];contract=payload['structure'];coord=contract['coordination'];assert payload['visibility']=='PRIVATE' and payload['owner_id']==actor and payload['signing_key']==item['owner_key_id']
 assert coord['v']==version and coord['instance_id']==progress['instance_id'] and coord['protocol_digest']==(V1 if version==1 else V2) and coord['coordinator']==actor
 for key,value in dict(initial_delay_ms=60000,max_delay_ms=3600000,escalate_after=5,window_ms=60000,workspace_limit=60,sender_limit=10,recipient_limit=10).items():assert coord[key]==value
 protocols=[o for o in read['objects'] if o['kind']=='protocols' and o['id']==coord['protocol_digest']];assert len(protocols)==1
 manifest=protocols[0]['value']['manifest'];actions=[a['id'] for a in manifest['actions']]
 for selected in [actor,member]:
  m=[m for m in payload['members'] if m['actor_id']==selected];assert len(m)==1
  scopes=[s for s in m[0]['scopes'] if s['instance_id']==coord['instance_id']];assert scopes==[dict(instance_id=coord['instance_id'],actions=actions,protocol_roles=['COLLABORATOR'],capabilities=['COORDINATE'])]
 for prior in old_policy['payload']['members']:
  current=[m for m in payload['members'] if m['actor_id']==prior['actor_id']];assert len(current)==1
  for key in prior:
   if key!='scopes':assert current[0][key]==prior[key]
  assert all(s in current[0]['scopes'] for s in prior['scopes'])
 if version==1:
  for p in contract['protocols']:
   if p['protocol_digest']!=V1:
    assert all(f['protection']=='e2ee' for schema in p['schemas'].values() for f in schema['fields'].values())
 else:
  previous=old_policy['payload']['structure']
  for p in previous['protocols']:assert p in contract['protocols']
  for key in previous['coordination']:
   if key not in ['v','instance_id','protocol_digest']:assert coord[key]==previous['coordination'][key]
 for kind in ['read','policy']:
  path=STATE/f'v{version}-{kind}.json';path.write_text(json.dumps(read if kind=='read' else policy));path.chmod(0o600)
 return policy

assert count()==3 and observed()==[]
attached=success('attach');assert attached['status']=='ATTACHED' and attached['sequence']==3
assert success('operations')==[];no_effects(3,[])
# The original TS producer is closed; subsequent calls use fresh installed handles.
shutil.move(str(STATE/'source'),str(STATE/'source-removed'))
for key in ['state_path','pem_path','intent_db_path']:assert not Path(item[key]).exists()
unknown='z'*43
assert invoke('enable',input=dict(participants=[unknown]))==dict(ok=False,code='PARTICIPANT_NOT_MEMBER')
assert success('operations')==[];no_effects(3,[])
with urlopen(Request(origin+'__test/drop-next-post',data=b'{}',method='POST'),timeout=30) as response:assert response.status==200
first=success('enable',input=dict(participants=[member]));begin=first['begin_command_id'];instance=first['instance_id']
assert len(begin)==43 and first['status']=='PENDING' and first['version']==1 and first['protocol_digest']==V1 and first['sequence']==3 and first['step_command_id']==begin and first['step_action_id']=='secure.structure.begin'
assert count()==4 and len(observed())==1 and observed()[0]['command_id']==begin
history=success('operations');assert history==[first]
# New omitted participants must retain/recover the original member choice.
progress=success('enable');assert progress['begin_command_id']==begin and progress['instance_id']==instance and progress['step_action_id']=='secure.structure.page' and count()==5
for _ in range(8):
 if progress['status']=='ACCEPTED':break
 before=count();progress=success('resume',begin=begin);assert count()-before in [0,1] and progress['begin_command_id']==begin and progress['instance_id']==instance
assert progress['status']=='ACCEPTED' and progress['sequence']==7 and count()==7 and len(observed())==4
read=success('read');v1=verify_read(read,1,progress,item['source_policy'])
before=observed();assert success('enable')['begin_command_id']==begin and success('resume',begin=begin)==progress and success('operations')==[progress];no_effects(7,before)
assert invoke('enable',input=dict(participants=[unknown]))==dict(ok=False,code='COORDINATION_CONFLICT');no_effects(7,before)
upgrade=success('enable',input=dict(version=2,participants=[member]));upgrade_begin=upgrade['begin_command_id'];upgrade_instance=upgrade['instance_id']
assert upgrade['status']=='PENDING' and upgrade['version']==2 and upgrade['protocol_digest']==V2 and upgrade_begin!=begin and upgrade_instance!=instance and count()==8
for _ in range(8):
 if upgrade['status']=='ACCEPTED':break
 before=count();upgrade=success('resume',begin=upgrade_begin);assert count()-before in [0,1] and upgrade['begin_command_id']==upgrade_begin and upgrade['instance_id']==upgrade_instance
assert upgrade['status']=='ACCEPTED' and upgrade['sequence']==11 and count()==11 and len(observed())==8
final=success('read');v2=verify_read(final,2,upgrade,v1)
before=observed();assert success('enable',input=dict(version=2))['begin_command_id']==upgrade_begin and success('resume',begin=upgrade_begin)==upgrade;no_effects(11,before)
assert invoke('enable',input=dict(version=1))==dict(ok=False,code='COORDINATION_CONFLICT');no_effects(11,before)
commits=dbrows('SELECT sequence,command_id,action_id,commit_hash,policy_hash,artifact FROM secure_commits WHERE workspace_id=? AND sequence>3 ORDER BY sequence',(workspace,))
assert [r[2] for r in commits]==['secure.structure.begin','secure.structure.page','secure.structure.page','secure.structure.end']*2
assert len({r[1] for r in commits})==8 and commits[0][1]==begin and commits[4][1]==upgrade_begin
for request,commit in zip(observed(),commits):
 sequence,command,action,commit_hash,policy_hash,artifact=commit
 assert hashlib.sha256(artifact.encode()).hexdigest()==commit_hash
 expected='{"commit":'+artifact
 if action=='secure.structure.begin':
  policy=dbrows('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,policy_hash));assert len(policy)==1;assert hashlib.sha256(policy[0][0].encode()).hexdigest()==policy_hash
  expected+=',"policy_update":'+policy[0][0]
 expected+='}'
 assert request['method']=='POST' and request['command_id']==command and request['body_sha256']==hashlib.sha256(expected.encode()).hexdigest() and request['body_bytes']==len(expected.encode())
assert sum(r['command_id']==begin for r in observed())==1 and sum(r['command_id']==upgrade_begin for r in observed())==1
result=dict(result='PASS',classification='operator_synthetic',interface=interface,source_cohort='d47bbd57f5a1e374d6e60cb8f8aa1c565f9c3559',source_removed=True,baseline=3,v1_sequence=7,v2_sequence=11,native_commit_posts=8,original_begin_count=1,upgrade_begin_count=1,prior_record_exact=True,prior_scopes_protection_preserved=True,omitted_pending_recovers_saved_member_choice=True,policy_artifact_hash_bound_to_verified_read=True)
path=STATE/'effects.json';path.write_text(json.dumps(result,indent=2)+'\n');path.chmod(0o600)
print(json.dumps(result),flush=True)
