"""One real installed PRIVATE options async cancellation/recovery case."""
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import urllib.request
from urllib.parse import urlsplit
import peerwork

SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE'])
for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-install-intent.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256')]:
    assert hashlib.sha256((SOURCE/path).read_bytes()).hexdigest()==os.environ[key]
fixture=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text())
assert len(fixture['sources'])==1 and os.environ['PEERWORK_TEST_INTERFACE']=='python-async'
item=fixture['sources'][0];assert item['interface']=='python-async' and item['mode']=='direct-disclosure-begin-before-post'
origin=fixture['origin'];assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
workspace=item['workspace_id'];command=item['pending_command_id'];database=STATE/'kernel/control.sqlite'
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def hook(path,post=False):
    request=urllib.request.Request(origin.rstrip('/')+path,data=b'{}' if post else None,method='POST' if post else 'GET')
    with opener.open(request,timeout=5) as response:return json.load(response)

def count(selected=None):
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        if selected is None:return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(workspace,)).fetchone()[0]
        return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?',(workspace,selected)).fetchone()[0]

def observed():
    rows=[json.loads(line) for line in Path(fixture['request_log']).read_text().splitlines()[fixture['fixture_request_lines']:]]
    return [row for row in rows if row['host']==urlsplit(origin).netloc and row['path']==f'/api/workspace/v1/secure/workspaces/{workspace}/commits']

def end_commit():
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        rows=db.execute("SELECT command_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? AND action_id='secure.structure.end' AND sequence=4",(workspace,)).fetchall()
    assert len(rows)==1
    return rows[0]

async def cancel_end(owner,attach_id):
    assert await asyncio.to_thread(hook,'/__test/delay-next-post',True)=={'enabled':True}
    task=asyncio.create_task(owner.recover_pending_direct_install_packet_async(attach_id,command))
    try:
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            status=await asyncio.to_thread(hook,'/__test/post-delay-status')
            if status['started']:
                assert count()==4 and count(command)==1
                end_id,_,_=end_commit();assert count(end_id)==1
                assert len(observed())==2 and observed()[-1]['command_id']==end_id
                assert not task.done(),'applied END response was not held before cancellation'
                break
            assert not task.done(),'recovery returned before the after-apply END barrier'
            await asyncio.sleep(0.025)
        else:raise AssertionError('signed END did not reach the after-apply barrier')
        task.cancel();await asyncio.sleep(0);task.cancel()
        try:await asyncio.wait_for(task,timeout=30)
        except asyncio.CancelledError:pass
        else:raise AssertionError('cancelled caller received successful recovery')
        assert task.cancelled()
        print(json.dumps(dict(phase='after-applied-END',caller='CancelledError',service_commits=4,begin_command_count=1,end_command_count=1)),flush=True)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):await asyncio.wait_for(task,timeout=30)

async def main():
    native=STATE/'native-async'
    def reopen():return peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
    options=Path(item['options_path']).read_text();material=Path(item['material_path']).read_text();parsed=json.loads(options)
    assert parsed['expected_checkpoint']==item['expected_checkpoint'] and item['expected_checkpoint']['sequence']==2
    assert parsed['disclose']==[dict(schema='item',fields=['title','label'])]
    assert len(parsed['grants'])==1 and parsed['grants'][0]['actor_id']==item['owner_actor_id'] and parsed['grants'][0]['actions']==['set']
    assert item['canonical_options_hash']!=item['intent_hash']
    selected=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=item['owner_actor_id'],expected_owner_key_id=item['owner_key_id'])
    owner=reopen();assert await owner.attachments_async()==[] and count()==2 and count(command)==0 and observed()==[]
    inventory=await owner.inspect_pending_direct_install_packet_async(**selected,selected_command_id=command,options_json=options,material_json=material)
    assert inventory['status']=='PENDING_UNRESOLVED' and inventory['command_id']==command and inventory['instance_id']==item['instance_id'] and inventory['intent_hash']==item['intent_hash'] and inventory['original_commit_hash']==item['pending_commit_hash'] and len(inventory['ts_state_digest'])==64
    progress=await owner.attach_pending_direct_install_packet_async(**selected,selected_command_id=command,expected_ts_state_digest=inventory['ts_state_digest'],options_json=options,material_json=material)
    assert progress['status']=='ATTACHED_RESTRICTED' and progress['sequence']==2 and progress['pending_direct_install_status']=='PENDING_UNRESOLVED'
    assert progress['pending_direct_install_command_id']==command and progress['pending_direct_install_instance_id']==item['instance_id'] and count()==2 and observed()==[]
    attach_id=progress['attach_id'];shutil.move(str(STATE/item['fixture_dir']),str(STATE/'source-removed'))
    for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(item[key]).exists()
    fresh=reopen();assert await fresh.attachments_async()==[progress] and await fresh.resume_attachment_async(attach_id)==progress
    # One step posts original BEGIN; the next step is native END and can use
    # the unchanged fixture's next-POST after-apply delay without a new hook.
    progress=await fresh.recover_pending_direct_install_packet_async(attach_id,command)
    assert progress['status']=='ATTACHED_RESTRICTED' and progress['sequence']==2 and progress['pending_direct_install_status']=='PENDING_UNRESOLVED' and count()==3 and count(command)==1
    assert len(observed())==1 and {key:observed()[0][key] for key in ['method','path','body_sha256']}==item['expected_native_request'] and observed()[0]['command_id']==command
    saved=await reopen().attachments_async();assert saved==[progress]
    await cancel_end(reopen(),attach_id)
    # SubmittedUncertain is a saved PENDING continuation: the already signed
    # BEGIN may become known while restriction/sequence/head stay unchanged.
    history=await reopen().attachments_async()
    assert history==[{**saved[0],'pending_direct_install_status':'BEGIN_ACCEPTED_CONTINUATION_PENDING'}]
    assert await reopen().resume_attachment_async(attach_id)==history[0] and history[0]['status']=='ATTACHED_RESTRICTED' and history[0]['sequence']==2
    before=observed();progress=await reopen().recover_pending_direct_install_packet_async(attach_id,command)
    assert progress['status']=='ATTACHED' and progress['pending_direct_install_status']=='ACCEPTED' and progress['sequence']==4
    assert count()==4 and count(command)==1 and observed()==before
    end_id,end_hash,end_artifact=end_commit();assert count(end_id)==1
    assert hashlib.sha256(end_artifact.encode()).hexdigest()==end_hash
    assert before[1]['method']=='POST' and before[1]['path']==item['expected_native_request']['path'] and before[1]['command_id']==end_id
    assert before[1]['body_sha256']==hashlib.sha256(('{"commit":'+end_artifact+'}').encode()).hexdigest()
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        assert db.execute('SELECT commit_hash FROM secure_commits WHERE workspace_id=? AND command_id=?',(workspace,command)).fetchone()[0]==item['pending_commit_hash']
    assert await reopen().recover_pending_direct_install_packet_async(attach_id,command)==progress and await reopen().resume_attachment_async(attach_id)==progress
    assert await reopen().private_package_installer(workspace).installs_async()==[] and await reopen().attachments_async()==[progress]
    read=await reopen().read_async(workspace);assert read['sequence']==4 and read['head']==end_hash and read['structure_status']=='ACTIVE'
    assert any(row['kind']=='instances' and row['id']==item['instance_id'] and row['value']['protocol_digest']==item['protocol_digest'] and row['value']['origin_entrypoint']==item['entrypoint'] for row in read['objects'])
    assert any(row['kind']=='protocols' and row['id']==item['protocol_digest'] for row in read['objects'])
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:policies=db.execute('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,read['policy_hash'])).fetchall()
    assert len(policies)==1 and hashlib.sha256(policies[0][0].encode()).hexdigest()==read['policy_hash']
    policy=json.loads(policies[0][0])['payload'];protocol=next(p for p in policy['structure']['protocols'] if p['protocol_digest']==item['protocol_digest'])
    for field in ['title','label']:assert protocol['schemas']['item']['fields'][field]==dict(protection='server_readable',type='opaque')
    assert protocol['schemas']['item']['fields']['secret']==dict(protection='e2ee',type='string')
    disclosure=[row for row in policy['structure']['disclosure'] if row['protocol_digest']==item['protocol_digest']]
    assert len(disclosure)==1 and disclosure[0]['fields']==['label','title'] and disclosure[0]['schema']=='item'
    action=reopen().private_actions(workspace);await action.submit_async('set',item['instance_id'],{},command_id='r'*43)
    accepted=await reopen().private_actions(workspace).reconcile_async('r'*43);receipt=accepted['receipt']
    assert accepted['status']=='ACCEPTED' and accepted['command_id']=='r'*43 and accepted['sequence']==5 and accepted['workspace_id']==workspace and accepted['action_id']=='set'
    assert receipt['command_id']==accepted['command_id'] and receipt['sequence']==5 and receipt['commit_hash']==accepted['commit_hash'] and receipt['actor_id']==item['owner_actor_id'] and receipt['effects']==[]
    assert receipt['instance_id']==item['instance_id'] and receipt['action_id']=='set'
    final=await reopen().read_async(workspace);assert final['sequence']==5 and final['head']==accepted['commit_hash'] and final['workspace_id']==workspace and final['structure_status']=='ACTIVE'
    latest=max((row for row in final['objects'] if row['kind']=='instances' and row['id']==item['instance_id']),key=lambda row:row['revision'])
    assert latest['revision']==2 and latest['value']['state']['count']==1
    assert latest['value']['protocol_digest']==item['protocol_digest'] and latest['value']['origin_entrypoint']==item['entrypoint']
    before=observed();assert count()==5 and len(before)==3
    assert await reopen().private_actions(workspace).retry_saved_async('r'*43)==accepted and observed()==before and count()==5
    # A later granted task advances the current verified workspace head; an
    # idempotent completed recovery reports that head without another POST.
    assert await reopen().recover_pending_direct_install_packet_async(attach_id,command)=={**progress,'sequence':5,'head':accepted['commit_hash']} and observed()==before and count()==5
    print(json.dumps(dict(result='PASS',classification='operator_synthetic',interface='python-async',mode=item['mode'],source='c5e7a3d8e59ff913da545db2c82e6969646fbe1a',source_removed=True,caller='CancelledError after applied END',sequence=5,native_commit_posts=3,original_begin_count=1,end_count=1,granted_task_count=1,ordinary_installs=[])),flush=True)

asyncio.run(main())
