"""One genuine installed PUBLIC genesis, selected identity and replay."""
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
assert interface=='python' and visibility=='PUBLIC' and version is None
assert STATE.stat().st_mode&0o077==0 and origin.startswith('http://127.0.0.1:')
native=STATE/'native';assert not native.exists();config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
name='Native runtime genesis '+interface
input_file=STATE/'create-input.json';input_file.write_text(json.dumps(dict(name=name,visibility=visibility,structured=True)));input_file.chmod(0o600)
log=STATE/'calls.jsonl';log.touch(mode=0o600)
def invoke(operation,command=None,workspace=None):
 if interface=='python':
  if operation=='import':value=peerwork.import_legacy_owner_identity(str(config_file),f['pem'])
  elif operation=='identity':value=peerwork.open_identity(str(native/'identity.state'))
  else:
   owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
   if operation=='create':value=owner.create(name,visibility,structured=True)
   elif operation=='resume':value=owner.resume(command)
   elif operation=='operations':value=owner.operations()
   elif operation=='read':value=owner.read(workspace)
   else:raise AssertionError(operation)
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

spaces=[o for o in read['objects'] if o['kind']=='workspaces'];assert len(spaces)==1 and spaces[0]['value']['visibility']=='PUBLIC' and spaces[0]['value']['owner']==identity['actor_id']
assert payload['members'][0]['actor_id']==identity['actor_id'] and payload['members'][0]['role']=='OWNER'
requests=observed();assert len(requests)==1
request=requests[0];body='{"commit":'+commit[5]+',"policy":'+policy_raw+'}'
assert request['method']=='POST' and request['path']=='/api/workspace/v1/secure/workspaces' and request['command_id']==command and request['body_sha256']==hashlib.sha256(body.encode()).hexdigest()
assert invoke('identity')==identity and invoke('operations')==[dict(created,status='CREATED_LOCAL')]
cli=subprocess.run([os.environ['PEERWORK_TEST_CLI'],'identity','info',str(native/'identity.state')],capture_output=True,text=True,timeout=30)
assert cli.returncode==0 and json.loads(cli.stdout)==identity
(STATE/'cli-identity.json').write_text(cli.stdout)
assert invoke('resume',command=command)==created and invoke('read',workspace=workspace)==read
assert rows('SELECT count(*) FROM secure_workspaces')==[(1,)] and rows('SELECT count(*) FROM secure_commits')==[(1,)] and observed()==requests
import sys,platform,peerwork._peerwork_native as extension
wrapper=Path(peerwork.__file__);binary=Path(extension.__file__);venv=STATE/'venv'
assert wrapper.is_relative_to(venv) and binary.is_relative_to(venv) and Path(sys.prefix)==venv
assert platform.machine()=='x86_64' and sys.version_info[:2]=={'cp312-cp312':(3,12),'cp313-cp313':(3,13),'cp314-cp314':(3,14)}[f['profile']]
assert hashlib.sha256(wrapper.read_bytes()).hexdigest()=='ed062183121ab295b33532c9150a5d07c3b8123770612b3ede9bad982c772685'
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='e5fdf5d8ddb39d0b1ea5b08d8ff239ad2875b00617f6a66abe0f349e1a01a232'
assert not hasattr(sys,'_is_gil_enabled') or sys._is_gil_enabled()
module=dict(version=sys.version,executable=sys.executable,prefix=sys.prefix,wrapper=str(wrapper),wrapper_sha256=hashlib.sha256(wrapper.read_bytes()).hexdigest(),native=str(binary),native_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),machine=platform.machine())
(STATE/'import.json').write_text(json.dumps(module,indent=2)+'\n')
(STATE/'verified-read.json').write_text(json.dumps(read)+'\n')
result=dict(result='PASS',profile=f['profile'],classification='operator_synthetic',interface='python',visibility='PUBLIC',selected_identity_matches=True,created_sequence=1,signed_structure='ACTIVE',bootstrap_posts=1,service_workspaces=1,service_commits=1,original_command_resume_idempotent=True,python_cli_identity_reopen=True,policy_artifact_hash_bound_to_verified_read=True)
(STATE/'effects.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
