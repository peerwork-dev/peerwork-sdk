"""One installed PRIVATE keep_encrypted genesis, signed declaration and data readback."""
import hashlib,json,os,sqlite3
from pathlib import Path
from urllib.parse import urlsplit
import peerwork
SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE']);f=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text())
assert (f['interface'],f['visibility'],f['version'])==('python','PRIVATE',None)
origin=f['origin'];identity=f['identity'];native=STATE/'native';assert not native.exists()
config=STATE/'config.json';config.write_text(json.dumps(dict(origin=origin,state_dir=str(native),allow_loopback_http=True)));config.chmod(0o600)
selector=[dict(schema='discussion.message',fields=['author'])];name='Installed encrypted genesis'
options=peerwork.SecureOwnerWorkspaceClient._input(name,'PRIVATE',structured=True,keep_encrypted=selector)
assert options==dict(name=name,name_utf16=None,visibility='PRIVATE',structured=True,keep_encrypted_json='[{"schema":"discussion.message","fields":["author"]}]',coordination_version=None)
p=STATE/'selected-options.json';p.write_text(json.dumps(options));p.chmod(0o600)
log=STATE/'calls.jsonl';log.touch(mode=0o600)
def save(op,value):
 with log.open('a')as out:out.write(json.dumps(dict(operation=op,value=value))+'\n')
 return value
def owner():return peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
def rows(sql,args=()):
 with sqlite3.connect('file:'+str(STATE/'kernel/control.sqlite')+'?mode=ro',uri=True)as db:return db.execute(sql,args).fetchall()
def observed():return [r for l in Path(f['request_log']).read_text().splitlines()if(r:=json.loads(l))['host']==urlsplit(origin).netloc]
assert rows('SELECT count(*) FROM secure_commits')==[(0,)] and observed()==[]
assert save('identity-import',peerwork.import_legacy_owner_identity(str(config),f['pem']))==identity
assert save('identity-info',peerwork.open_identity(str(native/'identity.state')))==identity
assert save('initial-operations',owner().operations())==[]
try:owner().create(name,'PRIVATE',structured=False,keep_encrypted=selector)
except peerwork.OwnerWorkspaceError as e:assert save('invalid-unstructured',dict(code=e.code))==dict(code='INPUT_INVALID')
else:raise AssertionError('keep_encrypted accepted without structured mode')
assert owner().operations()==[] and rows('SELECT count(*) FROM secure_commits')==[(0,)] and observed()==[]
created=save('create',owner().create(name,'PRIVATE',structured=True,keep_encrypted=selector));assert created['status']=='CREATED' and created['sequence']==1 and created['visibility']=='PRIVATE'
workspace=created['workspace_id'];command=created['command_id'];assert len(command)==43 and len(workspace)==43
read=save('signed-genesis-read',owner().read(workspace));assert read['workspace_id']==workspace and read['sequence']==1 and read['head']==created['head'] and read['structure_status']=='ACTIVE'
commits=rows('SELECT sequence,command_id,action_id,commit_hash,policy_hash,artifact FROM secure_commits WHERE workspace_id=?',(workspace,));assert len(commits)==1;c=commits[0]
assert c[:4]==(1,command,'secure.bootstrap',created['head']) and hashlib.sha256(c[5].encode()).hexdigest()==c[3] and read['policy_hash']==c[4]
policy_raw=rows('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,c[4]))[0][0];assert hashlib.sha256(policy_raw.encode()).hexdigest()==read['policy_hash'];policy=json.loads(policy_raw)['payload'];structure=policy['structure']
assert policy['v']==3 and policy['visibility']=='PRIVATE' and policy['structure_mode']=='STRUCTURED' and policy['epoch']==1 and policy['owner_id']==identity['actor_id'] and policy['signing_key']==identity['key_id'] and policy['effective_sequence']==1
assert structure.get('coordination') is None
presets=json.loads((SOURCE/'conformance/bootstrap-presets.json').read_text())['entries'];assert len(presets)==6
protocols=[o for o in read['objects']if o['kind']=='protocols'];instances=[o for o in read['objects']if o['kind']=='instances'];assert len(protocols)==len(instances)==6
assert {o['id']for o in protocols}=={p['digest']for p in presets}
def owner_roles(manifest):
 roles=[]
 for role in manifest['protocol_roles']:
  conflicts=manifest['role_conflicts']+manifest['historical_role_conflicts']
  if not any(role in pair and any(other!=role and other in roles for other in pair)for pair in conflicts):roles.append(role)
 return roles
for preset in presets:
 proto=[o for o in protocols if o['id']==preset['digest']];assert len(proto)==1 and proto[0]['value']['manifest']==preset['manifest'] and proto[0]['value']['resolved_manifest']==preset['manifest']
 ins=[o for o in instances if o['value']['protocol_digest']==preset['digest']];assert len(ins)==1 and ins[0]['value']['origin_entrypoint']==preset['entrypoint'] and ins[0]['value']['state']==preset['manifest']['initial_state']
 assert [s for s in policy['members'][0]['scopes']if s['instance_id']==ins[0]['id']]==[dict(instance_id=ins[0]['id'],actions=[a['id']for a in preset['manifest']['actions']],protocol_roles=owner_roles(preset['manifest']),capabilities=preset['manifest']['capabilities'])]
discussion=[p for p in presets if p['entrypoint']=='discussion'][0];digest=discussion['digest'];instance=[o['id']for o in instances if o['value']['protocol_digest']==digest][0]
declared=[p for p in structure['protocols']if p['protocol_digest']==digest];assert len(declared)==1
assert declared[0]['schemas']['discussion.message']['fields']['author']==dict(protection='e2ee',type='string')
disclosure=[d for d in structure['disclosure']if d['protocol_digest']==digest and d['schema']=='discussion.message'];assert len(disclosure)==1 and disclosure[0]['fields']==['reply_to']
spaces=[o for o in read['objects']if o['kind']=='workspaces'];assert len(spaces)==1 and spaces[0]['id']==workspace and spaces[0]['value']['owner']==identity['actor_id'] and spaces[0]['value']['visibility']=='PRIVATE' and spaces[0]['value']['name']==name
requests=observed();assert len(requests)==1 and requests[0]['command_id']==command and requests[0]['path']=='/api/workspace/v1/secure/workspaces'
assert requests[0]['body_sha256']==hashlib.sha256(('{"commit":'+c[5]+',"policy":'+policy_raw+'}').encode()).hexdigest()
assert save('operations-created',owner().operations())==[dict(created,status='CREATED_LOCAL')]
assert save('fresh-resume',owner().resume(command))==created and save('fresh-read',owner().read(workspace))==read and observed()==requests
# A normal public facade action on the selected default instance checks usable
# protected data and decrypted readback; no field-ciphertext claim from policy alone.
message='T037 protected author readback';actions=owner().private_actions(workspace)
submitted=save('discussion-submit',actions.submit('discussion.post',instance,dict(message=message)))
accepted=save('discussion-status',owner().private_actions(workspace).reconcile(submitted['command_id']));assert accepted['status']=='ACCEPTED' and accepted['sequence']==2 and accepted['workspace_id']==workspace and accepted['action_id']=='discussion.post'
receipt=accepted['receipt'];assert receipt['actor_id']==identity['actor_id'] and receipt['instance_id']==instance and receipt['command_id']==accepted['command_id'] and receipt['commit_hash']==accepted['commit_hash'] and receipt['sequence']==2 and len(receipt['effects'])==1
after=save('signed-data-read',owner().read(workspace));assert after['workspace_id']==workspace and after['sequence']==2 and after['head']==accepted['commit_hash'] and after['structure_status']=='ACTIVE' and after['policy_hash']==read['policy_hash']
records=[o for o in after['objects']if o['kind']=='records'and o['value'].get('schema_ref')=='discussion.message'];assert len(records)==1;r=records[0];assert r['id']==receipt['effects'][0]['record_id'] and receipt['effects'][0]['schema_ref']=='discussion.message' and r['value']['instance_id']==instance and r['value']['protocol_digest']==digest and r['value']['payload']==dict(message=message,reply_to=None,author=identity['actor_id'])
requests=observed();assert len(requests)==2 and requests[1]['command_id']==accepted['command_id']
assert save('retry-action',owner().private_actions(workspace).retry_saved(accepted['command_id']))==accepted
assert save('final-resume-create',owner().resume(command))==created and owner().read(workspace)==after and observed()==requests and rows('SELECT count(*)FROM secure_commits')==[(2,)] and rows('SELECT count(*)FROM secure_workspaces')==[(1,)]
assert save('identity-after',peerwork.open_identity(str(native/'identity.state')))==identity
for name,value in [('verified-read',read),('hash-bound-policy',json.loads(policy_raw)),('verified-data-read',after)]:
 p=STATE/(name+'.json');p.write_text(json.dumps(value));p.chmod(0o600)
result=dict(result='PASS',interface='python',visibility='PRIVATE',keep_encrypted=selector,coordination=None,default_protocol_instances=6,created_sequence=1,signed_active=True,author_e2ee_declaration=True,author_not_disclosed=True,protected_action_decrypted_readback=True,service_workspaces=1,service_commits=2,bootstrap_posts=1,action_posts=1,fresh_resume_idempotent=True)
p=STATE/'effects.json';p.write_text(json.dumps(result,indent=2)+'\n');p.chmod(0o600);print(json.dumps(result),flush=True)
