import json,os,hashlib
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
s=Path('/work/t068-nested');f=json.loads((s/'fixture.json').read_text());assert hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest()=='46db204843cb30961ef846e74f8155ad87a17e0f05bba4d9db2200ea5583f11b'
o=peerwork.SecureOwnerWorkspaceClient(f['origin'],str(s/'native'),allow_loopback_http=True)
r={'installed_source':'52a1f100ef735d25f237d2df2db796f0fd718ad0','native_path':str(native.__file__)}
try:
 a=o.attach(workspace_id=f['workspace_id'],protected_ts_state_path=str(s/'exported-ts-state.json'),protected_ts_intent_db_path=str(s/'intents.sqlite'),protected_owner_pkcs8_path=str(s/'selected-owner.pem'),expected_owner_actor_id=f['owner_actor_id'],expected_owner_key_id=f['owner_key_id']);r['attach']=a
 r['read']=o.read(f['workspace_id']);r['result']='NATIVE_ACCEPTED'
except peerwork.OwnerWorkspaceError as e:r.update(result='NATIVE_REFUSAL',code=e.code,message=str(e))
p=s/'native-result.json';p.write_text(json.dumps(r,sort_keys=True)+'\n');p.chmod(0o600);print(json.dumps(r))
