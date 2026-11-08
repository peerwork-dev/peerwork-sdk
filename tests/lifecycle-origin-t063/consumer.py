import hashlib,json,os,shutil,urllib.request
from pathlib import Path
import peerwork,peerwork._peerwork_native as extension
state=Path('/work/t059-archive-service-env-fixed');data=Path('/work/t063-local');f=json.loads((state/'fixture.json').read_text());expected=json.loads((data/'binary-pins.json').read_text())
assert Path(peerwork.__file__)==data/'peerwork/__init__.py' and Path(extension.__file__)==data/'peerwork/_peerwork_native.so'
assert hashlib.sha256(Path(extension.__file__).read_bytes()).hexdigest()==expected['python_native']
def owner():return peerwork.SecureOwnerWorkspaceClient(f['origin'],str(state/'native'),allow_loopback_http=True)
def save(name,value):
 p=data/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');p.chmod(0o600)
def call(name,fn):
 try:value=fn();save(name+'.json',dict(ok=True,value=value));return value
 except peerwork.OwnerWorkspaceError as error:save(name+'.json',dict(ok=False,code=error.code,message=str(error)));raise
history=call('inventory-before',lambda:owner().attachments());assert len(history)==1 and history[0]['status']=='PREPARED';id=history[0]['attach_id'];assert id=='NGchyCgRWkgC4zk5J4KKok6jbjRMbdLQbQYhf7oVu5k'
progress=call('resume',lambda:owner().resume_attachment(id));assert progress['attach_id']==id and progress['status']=='ATTACHED' and progress['sequence']==27 and progress['head']==f['head']
reference=json.loads((state/'reference-objects.json').read_text());ordered=lambda x:sorted(json.dumps(o,sort_keys=True,separators=(',',':'))for o in x)
def check(v):
 assert v['workspace_id']==f['workspace_id'] and v['sequence']==27 and v['head']==f['head'] and v['policy_hash']==f['policy_hash'] and v['structure_status']=='UNSTRUCTURED'
 assert ordered(v['objects'])==ordered(reference)
first=call('first-read',lambda:owner().read(f['workspace_id']));check(first)
gone=data/'source-removed';gone.mkdir(mode=0o700)
for name in ['exported-ts-state.json','intents.sqlite','selected-owner.pem']:
 p=state/name;shutil.move(str(p),str(gone/name));assert not p.exists()
second=call('source-gone-read',lambda:owner().read(f['workspace_id']));check(second);assert second==first
def route(name):
 with urllib.request.urlopen(f['origin']+'/__test/'+name,timeout=10)as response:return json.load(response)
route('missing')
try:
 value=owner().read(f['workspace_id']);save('negative-unexpected.json',value);raise AssertionError('missing archive returned verified result')
except peerwork.OwnerWorkspaceError as error:
 negative=dict(code=error.code,no_verified_result=True);save('negative.json',negative);assert error.code=='VERIFICATION_FAILED'
finally:route('normal')
again=call('recovered-read',lambda:owner().read(f['workspace_id']));check(again);assert again==first
assert call('inventory-after',lambda:owner().attachments())==[progress]
result=dict(result='PASS',classification='task-owned compiled local Python; not installed release cohort',original_attach_id=id,same_operation=True,raw_origin=f['origin'],source_removed=True,source_sequence=27,incoming_private_commits=14,restored_public_commits=13,full_objects=len(reference),idempotent=True,negative=negative,loaded_python_native=str(extension.__file__))
save('effects.json',result);print(json.dumps(result),flush=True)
