import os,json,sys,urllib.request
from pathlib import Path
import peerwork
state=Path(os.environ['T079_STATE']);out=Path(os.environ['T079_REPORT']);f=json.loads((state/'fixture.json').read_text());reference=json.loads((state/'reference-objects.json').read_text());profile=state/'native'
def owner(limit=None):
 args=dict(allow_loopback_http=True)
 if limit is not None:args['max_replay_commits']=limit
 return peerwork.SecureOwnerWorkspaceClient(f['origin'],str(profile),**args)
def save(n,v):p=out/n;p.write_text(json.dumps(v,sort_keys=True)+'\n');p.chmod(0o600)
def check(v):
 assert v['workspace_id']==f['workspace_id'] and v['sequence']==27 and v['head']==f['head'] and v['policy_hash']==f['policy_hash']
 order=lambda xs:sorted(json.dumps(x,sort_keys=True,separators=(',',':')) for x in xs)
 assert order(v['objects'])==order(reference) and len(v['objects'])==25
before=owner().attachments();assert len(before)==1 and before[0]['status']=='ATTACHED';save('before.json',before)
try:owner(26).read(f['workspace_id'])
except peerwork.OwnerWorkspaceError as error:low=dict(code=error.code,message=str(error));assert error.code=='RESOURCE_LIMIT'
else:raise AssertionError('26 accepted 27 restored commits')
save('limit26.json',low);assert owner().attachments()==before
valid=owner(27).read(f['workspace_id']);check(valid);save('limit27.json',valid)
assert owner(27).read(f['workspace_id'])==valid;assert owner().read(f['workspace_id'])==valid
with urllib.request.urlopen(f['origin']+'/__test/missing') as r:assert json.load(r)['missing']
try:
 try:owner(27).read(f['workspace_id'])
 except peerwork.OwnerWorkspaceError as error:negative=dict(code=error.code);assert error.code=='VERIFICATION_FAILED'
 else:raise AssertionError('missing authenticated archive accepted')
finally:
 with urllib.request.urlopen(f['origin']+'/__test/normal') as r:assert not json.load(r)['missing']
assert owner(27).read(f['workspace_id'])==valid and owner().attachments()==before
for invalid in [0,-1,True,2**64]:
 try:owner(invalid)
 except (ValueError,TypeError):pass
 else:raise AssertionError('invalid count accepted by facade')
result=dict(result='PASS',incoming_commits=14,restored_commits=27,limit26=low,limit27_full_objects=25,default_unchanged=True,negative=negative,public_attachment_unchanged=True,source_exports_absent=all(not (state/x).exists() for x in ['exported-ts-state.json','selected-owner.pem','intents.sqlite']),wrapper=peerwork.__file__)
save('result.json',result);print(json.dumps(result),flush=True)
