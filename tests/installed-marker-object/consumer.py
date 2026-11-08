import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from urllib.parse import urlsplit
import peerwork

SOURCE=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);STATE=Path(os.environ['PEERWORK_TEST_STATE'])
for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-marker-object-stage.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256'),('tests/legacy-owner-install-object-material.mjs','PEERWORK_TEST_OBJECT_HELPER_SHA256')]:
    assert hashlib.sha256((SOURCE/path).read_bytes()).hexdigest()==os.environ[key]
fixture=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text())
assert len(fixture['sources'])==1
item=fixture['sources'][0];interface=os.environ['PEERWORK_TEST_INTERFACE']
assert item['interface']==interface and interface in ['python','node','cli'] and item['mode'] in ['marker-before-command','command-before-pending','cleanup-applied']
origin=fixture['origin'];workspace=item['workspace_id'];command=item['marker_hash'];instance=item['instance_id']
assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
database=STATE/'kernel/control.sqlite';native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
source_input=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=item['owner_actor_id'],expected_owner_key_id=item['owner_key_id'])
source_file=STATE/'source-input.json';source_file.write_text(json.dumps(source_input));source_file.chmod(0o600)
options_path=Path(item['options_path']);material_path=Path(item['material_path']);options=options_path.read_text();material=material_path.read_text()
parsed=json.loads(options);oracle=item['compiler_oracle']
assert item['part_count']==4 and item['compiler_equality'] and item['cut_saved_before_throw']
assert parsed['instance_id']==instance

def count(selected=None):
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        if selected is None:return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(workspace,)).fetchone()[0]
        return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?',(workspace,selected)).fetchone()[0]

def observed():
    rows=[json.loads(line) for line in Path(fixture['request_log']).read_text().splitlines()[fixture['fixture_request_lines']:]]
    return [row for row in rows if row['host']==urlsplit(origin).netloc and row['path']==oracle['path']]

def invoke(operation,*,selected_command=command,digest=None,selected_options=options,selected_material=material,attachment=None):
    if interface=='python':
        # Reopen on every operation; source paths are used only by inspect/attach.
        owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
        try:
            if operation=='candidates':value=owner.object_stage_intent_candidates(**source_input)
            elif operation=='inspect':value=owner.inspect_object_stage_intent(**source_input,marker_hash=selected_command,options_json=selected_options,material_json=selected_material)
            elif operation=='attach':value=owner.attach_object_stage_intent(**source_input,marker_hash=selected_command,expected_ts_state_digest=digest,options_json=selected_options,material_json=selected_material)
            elif operation=='attachments':value=owner.attachments()
            elif operation=='resume':value=owner.resume_attachment(attachment)
            elif operation=='recover':value=owner.recover_object_stage_intent(attachment,selected_command)
            elif operation=='read':value=owner.read(workspace)
            elif operation=='installs':value=owner.private_package_installer(workspace).installs()
            else:raise AssertionError(operation)
            return dict(ok=True,value=value)
        except peerwork.OwnerWorkspaceError as error:return dict(ok=False,code=error.code)
    if interface=='node':
        code=r'''
void(async()=>{
 const fs=require('node:fs'),sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE),x=JSON.parse(fs.readFileSync(0,'utf8'));
 const owner=sdk.openSecureOwnerWorkspaces(x.config);let value;
 switch(x.operation){
 case 'candidates':value=await owner.objectStageIntentCandidates(x.input);break;
 case 'inspect':value=await owner.inspectObjectStageIntent(x.input,x.command,x.options,x.material);break;
 case 'attach':value=await owner.attachObjectStageIntent(x.input,x.command,x.digest,x.options,x.material);break;
 case 'attachments':value=await owner.attachments();break;
 case 'resume':value=await owner.resumeAttachment(x.attachment);break;
 case 'recover':value=await owner.recoverObjectStageIntent(x.attachment,x.command);break;
 case 'read':value=await owner.read(x.workspace);break;
 case 'installs':value=await owner.privatePackageInstaller(x.workspace).installs();break;
 default:throw new Error('unknown test operation');
 }console.log(JSON.stringify({ok:true,value}));
})().catch(error=>console.log(JSON.stringify({ok:false,code:error.code})));
'''
        value=dict(config=dict(origin=origin,stateDir=str(native),allowLoopbackHttp=True),operation=operation)
        if operation in ['candidates','inspect','attach']:
            value.update(input=dict(workspaceId=workspace,protectedTsStatePath=item['state_path'],protectedTsIntentDbPath=item['intent_db_path'],protectedOwnerPkcs8Path=item['pem_path'],expectedOwnerActorId=item['owner_actor_id'],expectedOwnerKeyId=item['owner_key_id']),command=selected_command,digest=digest,options=selected_options,material=selected_material)
        elif operation in ['resume','recover']:
            value['attachment']=attachment
            if operation=='recover':value['command']=selected_command
        elif operation in ['read','installs']:
            value['workspace']=workspace
        result=subprocess.run([os.environ['PEERWORK_TEST_NODE'],'-e',code],input=json.dumps(value),capture_output=True,text=True,timeout=120)
        assert result.returncode==0,'Node consumer invocation failed'
        return json.loads(result.stdout)
    assert interface=='cli'
    if operation=='candidates':args=['owner-object-intent-candidates',str(source_file)]
    elif operation in ['inspect','attach']:
        opath=options_path;mpath=material_path
        if selected_options!=options:
            opath=STATE/'wrong-options.json';opath.write_text(selected_options);opath.chmod(0o600)
        if selected_material!=material:
            mpath=STATE/'wrong-material.json';mpath.write_text(selected_material);mpath.chmod(0o600)
        args=['owner-object-intent-'+operation,str(source_file),selected_command]+([digest] if operation=='attach' else [])+[str(opath),str(mpath)]
    elif operation=='attachments':args=['owner-attachments']
    elif operation=='resume':args=['owner-attach-resume',attachment]
    elif operation=='recover':args=['owner-object-intent-recover',attachment,selected_command]
    elif operation=='read':args=['owner-read',workspace]
    elif operation=='installs':args=['owner-private-install-list',workspace]
    else:raise AssertionError(operation)
    result=subprocess.run([os.environ['PEERWORK_TEST_CLI'],'secure',args[0],str(config_file),*args[1:]],capture_output=True,text=True,timeout=120)
    value=json.loads(result.stdout if result.returncode==0 else result.stderr)
    return dict(ok=True,value=value) if result.returncode==0 else dict(ok=False,code=value['code'])

def success(operation,**kwargs):
    result=invoke(operation,**kwargs);assert result['ok'],dict(interface=interface,phase=operation,code=result.get('code'));return result['value']

initial=1+item['expected_accepted_parts'];final=7
assert count()==initial and observed()==[] and success('attachments')==[]
candidates=success('candidates');assert len(candidates)==1
candidate=candidates[0];assert candidate['workspace_id']==workspace and candidate['instance_id']==instance and candidate['marker_hash']==command
assert candidate['original_command_id']==item['orphan_command_id'] and candidate['part_count']==4
assert set(candidate)=={'workspace_id','instance_id','marker_hash','original_command_id','original_options_hash','protocol_digest','part_count'}
inventory=success('inspect');assert inventory['marker_hash']==command and inventory['instance_id']==instance and inventory['protocol_digest']==item['protocol_digest']
assert inventory['accepted_parts']==item['expected_accepted_parts'] and inventory['part_count']==4
assert invoke('inspect',selected_material='{}')==dict(ok=False,code='SOURCE_UNRESOLVED')
assert invoke('attach',digest='0'*64)==dict(ok=False,code='SOURCE_CHANGED')
assert success('attachments')==[] and count()==initial and observed()==[]
progress=success('attach',digest=inventory['ts_state_digest']);attach_id=progress['attach_id']
assert progress['status']=='ATTACHED_RESTRICTED' and progress['object_stage_intent_marker_hash']==command and progress['pending_object_stage_command_id'] is None
assert progress['pending_object_stage_instance_id']==instance and progress['pending_object_stage_native_begin_command_id'] is None
assert progress['pending_object_stage_status']==('PENDING_UNRESOLVED' if initial==1 else 'STAGE_ACCEPTED_INSTALL_PENDING')
assert count()==initial and observed()==[]
shutil.move(str(STATE/item['fixture_dir']),str(STATE/'source-removed'))
for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(item[key]).exists()
assert success('resume',attachment=attach_id)==progress
assert invoke('recover',attachment=attach_id,selected_command='f'*64)==dict(ok=False,code='ATTACH_CONFLICT')
assert count()==initial and observed()==[]
async_handoff=False
if interface=='python':
 import asyncio,contextlib,time,urllib.request
 def hook(path,post=False):
  request=urllib.request.Request(origin.rstrip('/')+path,data=b'{}' if post else None,headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=10)as response:return json.load(response)
 async def cancel_after_part():
  owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
  assert await asyncio.to_thread(hook,'/__test/delay-next-post',True)=={'enabled':True}
  task=asyncio.create_task(owner.recover_object_stage_intent_async(attach_id,command))
  try:
   deadline=time.monotonic()+120
   while time.monotonic()<deadline:
    status=await asyncio.to_thread(hook,'/__test/post-delay-status')
    if status['started']:
     assert count()==2 and len(observed())==1 and not task.done();break
    assert not task.done();await asyncio.sleep(.025)
   else:raise AssertionError('native marker part did not reach after-apply barrier')
   task.cancel();await asyncio.sleep(0);task.cancel()
   try:await asyncio.wait_for(task,timeout=30)
   except asyncio.CancelledError:pass
   else:raise AssertionError('cancelled caller returned success')
   assert task.cancelled()
  finally:
   if not task.done():
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):await asyncio.wait_for(task,timeout=30)
 asyncio.run(cancel_after_part())
 cancelled_id=observed()[0]['command_id'];assert count(cancelled_id)==1
 history_after_cancel=success('attachments');assert len(history_after_cancel)==1 and history_after_cancel[0]['status']=='ATTACHED_RESTRICTED'
 assert history_after_cancel[0]['object_stage_intent_marker_hash']==command and history_after_cancel[0]['pending_object_stage_command_id'] is None
 interface='node'
 before_handoff=observed();progress=success('resume',attachment=attach_id)
 assert progress['status']=='ATTACHED_RESTRICTED' and observed()==before_handoff and count()==2
 progress=success('recover',attachment=attach_id)
 assert progress['status']=='ATTACHED_RESTRICTED' and count()==3 and len(observed())==2 and count(cancelled_id)==1
 interface='python';async_handoff=True
 event=dict(caller='CancelledError',after_apply_stage=True,live_task_at_barrier=True,double_cancel_drained=True,accepted_cancelled_command=cancelled_id,history_after_cancel=history_after_cancel[0],node_resume_no_post=True,node_recover_next_native_part=True)
 (STATE/'async-handoff.json').write_text(json.dumps(event,indent=2)+'\n');(STATE/'async-handoff.json').chmod(0o600)
for _ in range(12):
 if progress['status']=='ATTACHED':break
 progress=success('recover',attachment=attach_id)
 assert progress['status'] in ['ATTACHED_RESTRICTED','ATTACHED']
assert progress['status']=='ATTACHED' and progress['sequence']==final and progress['pending_object_stage_status']=='ACCEPTED'
assert progress['object_stage_intent_marker_hash']==command and progress['pending_object_stage_command_id'] is None
begin=progress['pending_object_stage_native_begin_command_id'];assert isinstance(begin,str) and len(begin)==43 and begin!=item['orphan_command_id']
assert count()==final and len(observed())==final-initial
with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True)as db:
 commits=db.execute('SELECT sequence,command_id,action_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(workspace,)).fetchall()
 policy_hash=json.loads(commits[5][4])['payload']['policy_hash'];policy=db.execute('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,policy_hash)).fetchone()[0]
assert [r[2]for r in commits]==['secure.bootstrap']+['secure.protocol-object.stage']*4+['secure.structure.begin','secure.structure.end']
assert len({r[1]for r in commits})==7 and commits[5][1]==begin and hashlib.sha256(policy.encode()).hexdigest()==policy_hash
if item['orphan_command_id']:assert count(item['orphan_command_id'])==int(initial==2)
for row,post in zip(commits[initial:],observed()):
 body='{"commit":'+row[4]+(',"policy_update":'+policy if row[2]=='secure.structure.begin'else'')+'}'
 assert post['method']=='POST' and post['path']==oracle['path'] and post['command_id']==row[1] and post['action_id']==row[2]
 assert post['body_sha256']==hashlib.sha256(body.encode()).hexdigest()
before=observed();assert success('recover',attachment=attach_id)==progress and success('resume',attachment=attach_id)==progress
assert count()==final and observed()==before and success('installs')==[]
read=success('read');assert read['workspace_id']==workspace and read['sequence']==final and read['head']==commits[-1][3] and read['structure_status']=='ACTIVE'
protocols=[r for r in read['objects']if r['kind']=='protocols'and r['id']==item['protocol_digest']];assert len(protocols)==1 and protocols[0]['value']==oracle['logical_value']
instances=[r for r in read['objects']if r['kind']=='instances'and r['id']==instance];assert instances and all(r['value']['protocol_digest']==item['protocol_digest']and r['value']['origin_entrypoint']==parsed['entrypoint']for r in instances)
assert any(r['kind']=='workspaces'and r['id']==workspace and r['value']['owner']==item['owner_actor_id']and r['value']['visibility']=='PRIVATE'for r in read['objects'])
print(json.dumps(dict(result='PASS',interface=interface,mode=item['mode'],source_cohort='7dd319713708c417e5bc6026be1cf32ca598cfde',source_removed=True,redacted_candidates=True,truthful_zero_prefix=(initial==1),full_compiler_readback=True,service_commits=7,native_commit_posts=len(observed()),orphan_applied=(initial==2),distinct_native_begin=True,idempotent=True,async_cancel_and_node_handoff=async_handoff)),flush=True)
