import json,os,sys,hashlib
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
s=Path('/work/t073-ts-continuation');f=json.loads((s/'fixture.json').read_text());phase=sys.argv[1]
assert Path(peerwork.__file__)==Path('/work/sdk-config-t062-20261015/dist/python-consumer/peerwork/__init__.py')
assert hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest()=='46db204843cb30961ef846e74f8155ad87a17e0f05bba4d9db2200ea5583f11b'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=s/'legacy.sqlite';backup=s/'checked-backup.sqlite';identity=s/'native-identity.state';journal=s/'native-journal.sqlite'
def client():return peerwork.KernelClient(f['origin'],str(journal),str(identity),allow_loopback_http=True)
def save(name,value):p=s/name;p.write_text(json.dumps(value,sort_keys=True)+'\n');p.chmod(0o600)
if phase=='import':
 public=peerwork.import_legacy_identity_pem(str(identity),str(s/'selected-owner.pem'));assert public['key_id']==f['key_id'] and public['actor_id']==f['actor_id']
 before=sha(source);c=client();report=c.migrate_ts_store(str(source),str(backup),[f['key_id']]);assert report=={'pending_count':1,'accepted_count':1};assert sha(source)==before
 assert c.status(f['accepted_id'])['state']=='ACCEPTED' and c.status(f['pending_id'])['state']=='PENDING'
 pending=c.pending();assert len(pending)==1 and pending[0]['command_id']==f['pending_id'] and pending[0]['intent_digest']==f['pending_digest']
 result=dict(result='PASS',phase=phase,report=report,source_sha256=before,backup_sha256=sha(backup),public_identity=public,pending=pending,wrapper=str(peerwork.__file__),native=str(native.__file__))
 save('import-result.json',result)
elif phase=='reconcile':
 old=json.loads((s/'import-result.json').read_text());changed=sha(source);assert changed!=old['source_sha256'];assert sha(backup)==old['backup_sha256']
 c=client();accepted=c.submit_saved(f['pending_id']);ts=json.loads((s/'ts-continuation.json').read_text());assert accepted['command_id']==f['pending_id'] and accepted['workspace_id']==ts['pending_workspace_id'];assert accepted['event_sequence']==ts['event_sequence']
 assert client().status(f['pending_id'])['state']=='ACCEPTED' and client().pending()==[]
 before_status=client().status(f['pending_id']);before_accepted=client().status(f['accepted_id'])
 try:client().migrate_ts_store(str(source),str(backup),[f['key_id']])
 except RuntimeError as error:refusal=dict(type=type(error).__name__,message=str(error))
 else:raise AssertionError('changed source accepted against original backup')
 assert client().status(f['pending_id'])==before_status and client().status(f['accepted_id'])==before_accepted and client().pending()==[]
 assert sha(source)==changed and sha(backup)==old['backup_sha256'];assert client().submit_saved(f['pending_id'])==accepted
 result=dict(result='PASS',phase=phase,accepted=accepted,changed_source_sha256=changed,backup_sha256=sha(backup),changed_source_refusal=refusal,source_preserved_by_import=True,fresh_clients=True)
 save('reconcile-result.json',result)
else:raise AssertionError('unknown phase')
print(json.dumps(result),flush=True)
