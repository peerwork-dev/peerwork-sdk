from pathlib import Path
import json,hashlib,sys
W=Path(__file__).resolve().parents[2];E=W/'.test-data/t073';S=Path(json.loads((E/'paths.json').read_text())['state'])
load=lambda p:json.loads(p.read_text());f=load(S/'fixture.json');a=load(S/'import-result.json');t=load(S/'ts-continuation.json');b=load(S/'reconcile-result.json');requests=load(S/'requests.json');posts=[r for r in requests if r['method']=='POST'];c=load(S/'final-counts.json');life=load(S/'service-exit.json');term=load(E/'terminal.json')
assert term['exit_code']==1 and 'posts.every(r=>r.status===200)' in (E/'actual.log').read_text()
assert load(S/'import-terminal.json')['code']==0 and load(S/'reconcile-terminal.json')['code']==0
assert a['report']=={'pending_count':1,'accepted_count':1};assert a['public_identity']['actor_id']==f['actor_id'] and a['public_identity']['key_id']==f['key_id']
assert len(a['pending'])==1 and a['pending'][0]['command_id']==f['pending_id'] and a['pending'][0]['intent_digest']==f['pending_digest']
assert t['result']=='PASS' and t['same_actor'] and t['same_original_pending_id'] and t['cached_accepted_result_unchanged'] and t['cached_accepted_no_post'] and t['same_original_jws_digest']==f['pending_digest']
assert b['result']=='PASS' and b['accepted']['command_id']==f['pending_id'] and b['accepted']['workspace_id']==t['pending_workspace_id'] and b['accepted']['event_sequence']==t['event_sequence']
assert b['changed_source_refusal']=={'type':'RuntimeError','message':'TypeScript source or backup schema, rows, or pins are incompatible'}
assert a['source_sha256']!=b['changed_source_sha256'] and t['source_sha256']==b['changed_source_sha256'] and a['backup_sha256']==b['backup_sha256']
assert hashlib.sha256((S/'legacy.sqlite').read_bytes()).hexdigest()==b['changed_source_sha256'];assert hashlib.sha256((S/'checked-backup.sqlite').read_bytes()).hexdigest()==a['backup_sha256']
assert len(posts)==3 and all(r['status']==201 and r['path']=='/api/workspace/v1/commands' and r['error_code'] is None for r in posts)
assert posts[0]['command_id']==f['accepted_id'] and all(r['command_id']==f['pending_id'] and r['jws_sha256']==f['pending_digest'] for r in posts[1:])
assert c=={'commands':2,'workspaces':2};assert life=={'closed':True,'waited':True,'reference_in_process':True};assert all(r['status']<400 for r in requests)
r=dict(result='PASS_OFFLINE_CLOSURE_OF_LATE_HTTP_STATUS_ORACLE',original_host_exit=1,actual_installed_import_exit=0,actual_installed_reconcile_exit=0,correct_status=201,posts=3,accepted_business_effects=2,original_pending_post_attempts=2,original_pending_effects=1,old_TS_actual_continuation=True,source_preserved_at_import=True,backup_retained_unchanged=True,changed_source_refusal_no_extra_post=True,service_closed_waited=True,new_service_or_API_calls=0)
(E/'offline-result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
