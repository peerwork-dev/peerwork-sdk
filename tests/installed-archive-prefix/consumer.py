import hashlib,json,os,shutil,urllib.request
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
state=Path(os.environ['T059_STATE']);sdk=Path('/work/sdk-marker-t023-20261015');fixture=json.loads((state/'fixture.json').read_text())
assert Path(peerwork.__file__)==sdk/'dist/python-consumer/peerwork/__init__.py'
assert hashlib.sha256(Path(peerwork.__file__).read_bytes()).hexdigest()=='ed062183121ab295b33532c9150a5d07c3b8123770612b3ede9bad982c772685'
assert hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest()=='e5fdf5d8ddb39d0b1ea5b08d8ff239ad2875b00617f6a66abe0f349e1a01a232'
assert fixture['sequence']==27 and fixture['archived_public_commits']==13 and fixture['incoming_private_commits']==14
reference=json.loads((state/'reference-objects.json').read_text());profile=state/'native';origin=fixture['origin'];workspace=fixture['workspace_id'];calls=[]
def owner():return peerwork.SecureOwnerWorkspaceClient(origin,str(profile),allow_loopback_http=True)
def save(name,value):
 path=state/name;path.write_text(json.dumps(value,sort_keys=True)+'\n');path.chmod(0o600)
source=dict(workspace_id=workspace,protected_ts_state_path=str(state/'exported-ts-state.json'),protected_ts_intent_db_path=str(state/'intents.sqlite'),protected_owner_pkcs8_path=str(state/'selected-owner.pem'),expected_owner_actor_id=fixture['owner_actor_id'],expected_owner_key_id=fixture['owner_key_id'])
try:attached=owner().attach(**source)
except peerwork.OwnerWorkspaceError as error:
 save('native-attach-error.json',dict(code=error.code,message=str(error)));raise
save('native-attach.json',attached)
assert attached['status']=='ATTACHED' and attached['sequence']==27 and attached['head']==fixture['head']
def ordered(objects):return sorted((json.dumps(o,sort_keys=True,separators=(',',':')) for o in objects))
def check(value):
 assert value['workspace_id']==workspace and value['sequence']==27 and value['head']==fixture['head'] and value['policy_hash']==fixture['policy_hash'] and value['structure_status']=='UNSTRUCTURED'
 assert ordered(value['objects'])==ordered(reference)
 assert not any(k in value for k in ['keyring','private_key','jws'])
first=owner().read(workspace);check(first);save('native-first-read.json',first)
removed=state/'source-removed';removed.mkdir(mode=0o700)
for key in ['protected_ts_state_path','protected_ts_intent_db_path','protected_owner_pkcs8_path']:
 path=Path(source[key]);shutil.move(str(path),str(removed/path.name));assert not path.exists()
second=owner().read(workspace);check(second);assert second==first;save('native-fresh-read.json',second)
def route(name):
 with urllib.request.urlopen(origin+'/__test/'+name,timeout=10) as response:return json.load(response)
route('missing')
try:
 unexpected=owner().read(workspace);save('negative-unexpected.json',unexpected);raise AssertionError('missing archived original input returned a verified value')
except peerwork.OwnerWorkspaceError as error:
 negative=dict(code=error.code,no_verified_result=True);save('negative.json',negative);assert error.code=='VERIFICATION_FAILED'
finally:route('normal')
recovered=owner().read(workspace);check(recovered);assert recovered==first
assert owner().attachments()==[attached]
result=dict(result='PASS',interface='installed Python',source='7dd319713708c417e5bc6026be1cf32ca598cfde',incoming_private_commits=14,archived_public_commits=13,restored_signed_sequence=27,full_objects=len(reference),source_export='fresh fixture in-memory material through explicit supported attach',source_removed=True,fresh_handles=True,idempotent=True,negative=negative,negative_domain='transport omits one genuine PRIVATE single-item archive packet, therefore one original PUBLIC commit is unavailable; no service DB mutation')
save('effects.json',result);print(json.dumps(result),flush=True)
