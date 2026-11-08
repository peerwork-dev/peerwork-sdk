"""Installed facades only; the old protected profile stays at its bound path."""
from pathlib import Path
import os,sys,json,subprocess,hashlib,platform
from urllib.request import urlopen
import peerwork,peerwork._peerwork_native as native
STATE=Path(os.environ['T083_STATE']);OUT=Path(os.environ['T083_REPORT']);HERE=Path(__file__).parent
f=json.loads((STATE/'fixture.json').read_text());reference=json.loads((STATE/'reference-objects.json').read_text());profile=STATE/'native'
assert peerwork.__file__==os.environ['PYTHONPATH']+'/peerwork/__init__.py'
assert native.__file__==os.environ['PYTHONPATH']+'/peerwork/_peerwork_native.abi3.so'
def save(name,value):
 p=OUT/name;p.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');p.chmod(0o600)
def owner(limit):
 args=dict(allow_loopback_http=True)
 if limit is not None:args['max_replay_commits']=limit
 return peerwork.SecureOwnerWorkspaceClient(f['origin'],str(profile),**args)
calls=[]
def call(interface,operation,limit=None):
 if interface=='python':
  try:
   o=owner(limit)
   value=o.read(f['workspace_id']) if operation=='read' else o.attachments() if operation=='attachments' else peerwork.open_identity(str(profile/'identity.state'))
   result=dict(ok=True,value=value)
  except peerwork.OwnerWorkspaceError as error:result=dict(ok=False,code=error.code,message=str(error))
 elif interface=='node':
  request=dict(operation=operation,origin=f['origin'],profile=str(profile),workspace=f['workspace_id'],limit=limit)
  child=subprocess.run([os.environ['T083_NODE'],str(HERE/'node.cjs')],input=json.dumps(request),capture_output=True,text=True,timeout=60)
  assert child.returncode==0,dict(interface=interface,operation=operation,stderr=child.stderr)
  result=json.loads(child.stdout)
  if result['ok']:
   assert result['wrapper']==os.environ['T083_NODE_PACKAGE']+'/index.cjs'
   assert result['native']==os.environ['T083_NODE_MODULES']+'/@peerwork/agent-sdk-linux-x64-gnu/index.node'
 else:
  config=dict(origin=f['origin'],state_dir=str(profile),allow_loopback_http=True)
  if limit is not None:config['max_replay_commits']=limit
  path=OUT/('config-'+('default' if limit is None else str(limit))+'.json');save(path.name,config)
  argv=[os.environ['T083_CLI']]
  if operation=='identity':argv+=['identity','info',str(profile/'identity.state')]
  else:argv+=['secure','owner-read' if operation=='read' else 'owner-attachments',str(path)]+([f['workspace_id']] if operation=='read' else [])
  child=subprocess.run(argv,capture_output=True,text=True,timeout=60)
  raw=json.loads(child.stdout if child.returncode==0 else child.stderr)
  result=dict(ok=True,value=raw) if child.returncode==0 else dict(ok=False,code=raw['code'],message=raw.get('message'))
  save(f'cli-{len(calls):02d}-terminal.json',dict(argv=argv,exit_code=child.returncode,stdout=child.stdout,stderr=child.stderr))
 calls.append(dict(interface=interface,operation=operation,limit=limit,result=result if not result['ok'] else dict(ok=True)))
 save('calls.json',calls)
 return result

def success(interface,operation,limit=None):
 r=call(interface,operation,limit);assert r['ok'],dict(interface=interface,operation=operation,limit=limit,code=r.get('code'));return r['value']
def check(v):
 assert v['workspace_id']==f['workspace_id'] and v['sequence']==27 and v['head']==f['head'] and v['policy_hash']==f['policy_hash']
 order=lambda xs:sorted(json.dumps(x,sort_keys=True,separators=(',',':')) for x in xs)
 assert len(v['objects'])==25 and order(v['objects'])==order(reference)
results=[];baseline=success('python','attachments');assert len(baseline)==1 and baseline[0]['status']=='ATTACHED'
identity=success('python','identity');assert identity['actor_id']==f['owner_actor_id'] and identity['key_id']==f['owner_key_id']
save('identity-before.json',identity);save('attachments-before.json',baseline)
for interface in ['python','node','cli']:
 assert success(interface,'attachments')==baseline and success(interface,'identity')==identity
 low=call(interface,'read',26);assert not low['ok'] and low['code']=='RESOURCE_LIMIT',dict(interface=interface,low=low)
 assert success(interface,'attachments')==baseline
 valid=success(interface,'read',27);check(valid);save(interface+'-limit27.json',valid)
 assert success(interface,'read',27)==valid and success(interface,'read')==valid
 assert success(interface,'attachments')==baseline and success(interface,'identity')==identity
 results.append(dict(interface=interface,limit26=low['code'],limit27=dict(sequence=27,objects=25,head=valid['head'],policy_hash=valid['policy_hash']),fresh_repeat=True,default_equal=True,identity_unchanged=True,attachment_unchanged=True))
with urlopen(f['origin']+'/__test/missing') as r:assert json.load(r)['missing']
try:
 negative=call('python','read',27);assert not negative['ok'] and negative['code']=='VERIFICATION_FAILED'
finally:
 with urlopen(f['origin']+'/__test/normal') as r:assert not json.load(r)['missing']
check(success('python','read',27));assert success('python','attachments')==baseline and success('python','identity')==identity
assert all(not (STATE/p).exists() for p in ['exported-ts-state.json','intents.sqlite','selected-owner.pem'])
result=dict(result='PASS',interfaces=results,shared_omission_negative=negative['code'],incoming_commits=14,restored_commits=27,source_exports_absent=True,python=dict(version=sys.version,libc=platform.libc_ver(),wrapper=peerwork.__file__,native=native.__file__),node_runtime=os.environ['T083_NODE'],cli=os.environ['T083_CLI'])
save('result.json',result);print(json.dumps(result),flush=True)
