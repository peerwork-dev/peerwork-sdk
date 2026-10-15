import os,sys,json,hashlib
from pathlib import Path
import peerwork,peerwork._peerwork_native as native
S=Path('/work/t077-migration-crash');F=json.loads((S/'fixture.json').read_text())
assert Path(peerwork.__file__)==Path('/work/sdk-config-t062-20261015/dist/python-consumer/peerwork/__init__.py')
assert hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest()=='46db204843cb30961ef846e74f8155ad87a17e0f05bba4d9db2200ea5583f11b'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
identity_metadata=lambda p:(p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns)
source=S/'legacy.sqlite';backup=S/'checked-backup.sqlite';identity=S/'native-identity.state';journal=S/'native-journal.sqlite'
def client():return peerwork.KernelClient(F['origin'],str(journal),str(identity),allow_loopback_http=True)
def save(n,v):p=S/n;p.write_text(json.dumps(v,sort_keys=True)+'\n');p.chmod(0o600)
if '--writer' in sys.argv:
 report=client().migrate_ts_store(str(source),str(backup),[F['key_id']]);save('writer-unexpected-return.json',report);raise SystemExit(0)
public=peerwork.import_legacy_identity_pem(str(identity),str(S/'selected-owner.pem'));assert public['actor_id']==F['actor_id'] and public['key_id']==F['key_id']
assert client().pending()==[];assert client().status(F['accepted_id'])=={'state':'NOT_FOUND'} and client().status(F['pending_id'])=={'state':'NOT_FOUND'}
pre=dict(source_sha256=sha(source),identity_metadata=identity_metadata(identity),backup_absent=not backup.exists());assert pre['backup_absent'];save('prewarm.json',pre)
from trace import run_child
trace=run_child([sys.executable,__file__,'--writer'],dict(os.environ),str(backup),str(journal)+'-wal',True,timeout=45);save('trace-result.json',trace)
assert not any(e.get('phase')=='entry' and e.get('syscall')=='pwrite64' and e.get('exact_wal') and not e.get('armed') for e in trace['events']),'unexpected destination WAL write before checked-backup arm; phase unproven'
assert trace['exit_code']==-9 and trace['boundary_reached'] and trace['armed_by_backup_fsync'],'barrier missed: preserve original fixture; no retry'
assert backup.exists() and backup.stat().st_mode&0o077==0 and sha(source)==pre['source_sha256'] and identity_metadata(identity)==tuple(pre['identity_metadata']) and peerwork.open_identity(str(identity))==public
statuses={'accepted':client().status(F['accepted_id']),'pending':client().status(F['pending_id'])};pending=client().pending();absent=statuses=={'accepted':{'state':'NOT_FOUND'},'pending':{'state':'NOT_FOUND'}}
complete=statuses['accepted']['state']=='ACCEPTED' and statuses['pending']['state']=='PENDING' and len(pending)==1 and pending[0]['command_id']==F['pending_id'] and pending[0]['intent_digest']==F['pending_digest']
assert absent or complete,'partially imported public rows after kill';save('after-kill.json',dict(statuses=statuses,pending=pending,classification='NONE' if absent else 'COMPLETE_1_1',source_sha256=sha(source),backup_sha256=sha(backup),identity_unchanged=True))
before_backup=sha(backup);report=client().migrate_ts_store(str(source),str(backup),[F['key_id']]);assert report=={'pending_count':1,'accepted_count':1}
final={'accepted':client().status(F['accepted_id']),'pending':client().status(F['pending_id'])};rows=client().pending();assert final['accepted']['state']=='ACCEPTED' and final['accepted']['result']['command_id']==F['accepted_id'] and final['accepted']['result']['workspace_id']==F['accepted_workspace_id'];assert final['pending']=={'state':'PENDING'};assert len(rows)==1 and rows[0]['command_id']==F['pending_id'] and rows[0]['intent_digest']==F['pending_digest']
assert client().migrate_ts_store(str(source),str(backup),[F['key_id']])==report;assert client().status(F['accepted_id'])==final['accepted'] and client().pending()==rows
assert sha(source)==pre['source_sha256'] and sha(backup)==before_backup and identity_metadata(identity)==tuple(pre['identity_metadata']) and peerwork.open_identity(str(identity))==public
result=dict(result='PASS',source='52a1f100ef735d25f237d2df2db796f0fd718ad0',killed_child_waited=True,trace=trace,after_kill='NONE' if absent else 'COMPLETE_1_1',retry_report=report,final_statuses=final,pending=rows,source_sha256=sha(source),backup_sha256=sha(backup),identity_unchanged=True,fresh_clients=True,no_submit_calls=True)
save('consumer-result.json',result);print(json.dumps(result),flush=True)
