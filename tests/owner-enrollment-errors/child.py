"""No-model sandbox child; never print proxy URLs or protected file contents."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
cli,task_arg=sys.argv[1:];task=Path(task_arg);config=task/'owner-config.json';request=task/'workspace-input.json'
identity=task/'native/identity.state';identity_before=hashlib.sha256(identity.read_bytes()).hexdigest()
base=dict(os.environ);base.pop('PEERWORK_HTTP_PROXY',None)
assert base.get('CODEX_NETWORK_PROXY_ACTIVE') and base.get('HTTP_PROXY'),'runtime proxy not supplied'
proxy=base['HTTP_PROXY'];secret='OWNER_ENROLLMENT_PROXY_PRIVATE_MARKER'
requests=task/'requests.jsonl';before=requests.read_bytes()
def call(label,verb,*args,env=base):
 r=subprocess.run([cli,'secure',verb,str(config),*args],env=env,capture_output=True,text=True,timeout=90)
 for suffix,value in [('stdout',r.stdout),('stderr',r.stderr)]:
  p=task/(label+'.'+suffix);p.write_text(value);p.chmod(0o600)
 return r,json.loads(r.stdout if r.returncode==0 else r.stderr)
failed,value=call('generic-only','owner-create',str(request))
assert failed.returncode!=0 and value['code']=='TRANSPORT_FAILED'
assert 'owner enrollment:' in value['message'] and 'PEERWORK_HTTP_PROXY' in value['message'] and 'ignored' in value['message']
for private in [proxy,secret,str(task),json.loads(config.read_text())['origin']]:assert private not in failed.stderr
assert requests.read_bytes()==before and hashlib.sha256(identity.read_bytes()).hexdigest()==identity_before
operations,rows=call('after-failure-history','owner-operations');assert operations.returncode==0 and rows==[]
invalid_env=dict(base,PEERWORK_HTTP_PROXY='http://fixture-user:'+secret+'@/private-path')
invalid,refusal=call('invalid-explicit','owner-create',str(request),env=invalid_env)
assert invalid.returncode!=0 and refusal['code']=='TRANSPORT_CONFIGURATION_INVALID'
assert secret not in invalid.stderr and 'fixture-user' not in invalid.stderr and '/private-path' not in invalid.stderr
assert requests.read_bytes()==before and hashlib.sha256(identity.read_bytes()).hexdigest()==identity_before
explicit=dict(base,PEERWORK_HTTP_PROXY=proxy)
created,result=call('explicit-route','owner-create',str(request),env=explicit);assert created.returncode==0
for _ in range(4):
 if result['status']=='CREATED':break
 assert result['status']=='PENDING'
 resumed,result=call('explicit-resume','owner-resume',result['command_id'],env=explicit);assert resumed.returncode==0
assert result['status']=='CREATED' and result['sequence']==1
read,verified=call('signed-read','owner-read',result['workspace_id'],env=explicit);assert read.returncode==0
assert verified['workspace_id']==result['workspace_id'] and verified['sequence']==1 and verified['head']==result['head'] and verified['structure_status']=='ACTIVE'
owner=json.loads((task/'identity-import.stdout').read_text())
assert any(row['kind']=='workspaces' and row['id']==result['workspace_id'] and row['value']['visibility']=='PRIVATE' and row['value']['owner']==owner['actor_id'] for row in verified['objects'])
resumed,again=call('same-command-resume','owner-resume',result['command_id'],env=explicit);assert resumed.returncode==0 and again==result
assert hashlib.sha256(identity.read_bytes()).hexdigest()==identity_before
p=task/'child-summary.json';p.write_text(json.dumps(dict(result='PASS',generic_only_code=value['code'],invalid_explicit_code=refusal['code'],explicit_route_status=result['status'],signed_sequence=1,identity_unchanged=True,failed_workspace_history_empty=True,same_command_resume_identical=True))+'\n');p.chmod(0o600)
print(p.read_text(),end='')
