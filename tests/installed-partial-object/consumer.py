"""One installed-interface selected final object-stage source-gone recovery."""
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
for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-partial-object-stage.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256'),('tests/legacy-owner-install-object-material.mjs','PEERWORK_TEST_OBJECT_HELPER_SHA256')]:
    assert hashlib.sha256((SOURCE/path).read_bytes()).hexdigest()==os.environ[key]
fixture=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text())
assert len(fixture['sources'])==1
item=fixture['sources'][0];interface=os.environ['PEERWORK_TEST_INTERFACE']
assert item['interface']==interface and interface in ['python','node','cli'] and item['mode']=='part1-applied-loss'
origin=fixture['origin'];workspace=item['workspace_id'];command=item['pending_command_id'];instance=item['instance_id']
assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
database=STATE/'kernel/control.sqlite';native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
source_input=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=item['owner_actor_id'],expected_owner_key_id=item['owner_key_id'])
source_file=STATE/'source-input.json';source_file.write_text(json.dumps(source_input));source_file.chmod(0o600)
options_path=Path(item['options_path']);material_path=Path(item['material_path']);options=options_path.read_text();material=material_path.read_text()
parsed=json.loads(options);oracle=item['compiler_oracle']
assert item['part_index']==1 and item['part_count']==2 and item['accepted_part_count']==2 and item['install_intent_count']==0
assert item['compiler_equality'] is True and item['exact_operation_verified'] is True
assert parsed['instance_id']==instance and item['request_hash']==item['intent_hash']
assert parsed['grants']==[dict(actor_id=item['owner_actor_id'],actions=['discussion.post'],protocol_roles=['CONTRIBUTOR'],capabilities=['POST'])]

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
            if operation=='inspect':value=owner.inspect_pending_object_stage(**source_input,selected_command_id=selected_command,options_json=selected_options,material_json=selected_material)
            elif operation=='attach':value=owner.attach_pending_object_stage(**source_input,selected_command_id=selected_command,expected_ts_state_digest=digest,options_json=selected_options,material_json=selected_material)
            elif operation=='attachments':value=owner.attachments()
            elif operation=='resume':value=owner.resume_attachment(attachment)
            elif operation=='recover':value=owner.recover_pending_object_stage(attachment,selected_command)
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
 case 'inspect':value=await owner.inspectPendingObjectStage(x.input,x.command,x.options,x.material);break;
 case 'attach':value=await owner.attachPendingObjectStage(x.input,x.command,x.digest,x.options,x.material);break;
 case 'attachments':value=await owner.attachments();break;
 case 'resume':value=await owner.resumeAttachment(x.attachment);break;
 case 'recover':value=await owner.recoverPendingObjectStage(x.attachment,x.command);break;
 case 'read':value=await owner.read(x.workspace);break;
 case 'installs':value=await owner.privatePackageInstaller(x.workspace).installs();break;
 default:throw new Error('unknown test operation');
 }console.log(JSON.stringify({ok:true,value}));
})().catch(error=>console.log(JSON.stringify({ok:false,code:error.code})));
'''
        value=dict(config=dict(origin=origin,stateDir=str(native),allowLoopbackHttp=True),operation=operation)
        if operation in ['inspect','attach']:
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
    if operation in ['inspect','attach']:
        opath=options_path;mpath=material_path
        if selected_options!=options:
            opath=STATE/'wrong-options.json';opath.write_text(selected_options);opath.chmod(0o600)
        if selected_material!=material:
            mpath=STATE/'wrong-material.json';mpath.write_text(selected_material);mpath.chmod(0o600)
        args=['owner-object-stage-'+operation,str(source_file),selected_command]+([digest] if operation=='attach' else [])+[str(opath),str(mpath)]
    elif operation=='attachments':args=['owner-attachments']
    elif operation=='resume':args=['owner-attach-resume',attachment]
    elif operation=='recover':args=['owner-object-stage-recover',attachment,selected_command]
    elif operation=='read':args=['owner-read',workspace]
    elif operation=='installs':args=['owner-private-install-list',workspace]
    else:raise AssertionError(operation)
    result=subprocess.run([os.environ['PEERWORK_TEST_CLI'],'secure',args[0],str(config_file),*args[1:]],capture_output=True,text=True,timeout=120)
    value=json.loads(result.stdout if result.returncode==0 else result.stderr)
    return dict(ok=True,value=value) if result.returncode==0 else dict(ok=False,code=value['code'])

def success(operation,**kwargs):
    result=invoke(operation,**kwargs);assert result['ok'],dict(interface=interface,phase=operation,code=result.get('code'));return result['value']

assert count()==3 and count(command)==1 and observed()==[] and success('attachments')==[]
inventory=success('inspect')
assert inventory['status']=='APPLIED_IN_SIGNED_REPLAY' and inventory['instance_id']==instance and inventory['command_id']==command
assert inventory['part_index']==1 and inventory['part_count']==2 and inventory['protocol_digest']==item['protocol_digest']
assert inventory['original_options_hash']==item['request_hash'] and inventory['original_commit_hash']==item['pending_commit_hash']
assert len(inventory['ts_state_digest'])==64
assert invoke('inspect',selected_material='{}')==dict(ok=False,code='SOURCE_UNRESOLVED')
assert success('attachments')==[] and count()==3 and observed()==[]
assert invoke('attach',digest='0'*64)==dict(ok=False,code='SOURCE_CHANGED')
assert success('attachments')==[] and count()==3 and observed()==[]
progress=success('attach',digest=inventory['ts_state_digest']);attach_id=progress['attach_id']
assert progress['status']=='ATTACHED_RESTRICTED' and progress['sequence']==3
assert progress['workspace_id']==workspace and progress['owner_actor_id']==item['owner_actor_id'] and progress['owner_key_id']==item['owner_key_id']
assert progress['pending_object_stage_status']=='STAGE_ACCEPTED_INSTALL_PENDING' and progress['pending_object_stage_command_id']==command
assert progress['pending_object_stage_instance_id']==instance and progress['pending_object_stage_native_begin_command_id'] is None
assert count()==3 and observed()==[]
shutil.move(str(STATE/item['fixture_dir']),str(STATE/'source-removed'))
for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(item[key]).exists()
assert success('attachments')==[progress] and success('resume',attachment=attach_id)==progress
assert invoke('recover',attachment=attach_id,selected_command='z'*43)==dict(ok=False,code='ATTACH_CONFLICT')
assert count()==3 and observed()==[]
for _ in range(8):
    if progress['status']=='ATTACHED':break
    progress=success('recover',attachment=attach_id)
    assert progress['status'] in ['ATTACHED_RESTRICTED','ATTACHED']
assert progress['status']=='ATTACHED' and progress['pending_object_stage_status']=='ACCEPTED' and progress['sequence']==5
assert progress['pending_object_stage_command_id']==command and progress['pending_object_stage_instance_id']==instance
native_begin=progress['pending_object_stage_native_begin_command_id'];assert isinstance(native_begin,str) and native_begin!=command
assert count()==5 and count(command)==1 and len(observed())==2
with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
    commits=db.execute('SELECT sequence,command_id,action_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(workspace,)).fetchall()
    begin_policy_hash=json.loads(commits[3][4])['payload']['policy_hash']
    policy=db.execute('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,begin_policy_hash)).fetchone()[0]
assert [r[2] for r in commits]==['secure.bootstrap','secure.protocol-object.stage','secure.protocol-object.stage','secure.structure.begin','secure.structure.end']
assert commits[2][1]==command and commits[2][3]==item['pending_commit_hash'] and commits[3][1]==native_begin
assert hashlib.sha256(policy.encode()).hexdigest()==begin_policy_hash
begin,end=commits[3:]
for row,post,body in [(begin,observed()[0],'{"commit":'+begin[4]+',"policy_update":'+policy+'}'),(end,observed()[1],'{"commit":'+end[4]+'}')]:
    assert hashlib.sha256(row[4].encode()).hexdigest()==row[3]
    payload=json.loads(row[4])['payload'];assert payload['actor_id']==item['owner_actor_id'] and payload['signing_key']==item['owner_key_id'] and payload['workspace_id']==workspace
    assert post['method']=='POST' and post['path']==oracle['path'] and post['command_id']==row[1] and post['action_id']==row[2]
    assert post['body_sha256']==hashlib.sha256(body.encode()).hexdigest()
assert all(post['command_id']!=command and post['action_id'] not in ['secure.protocol-object.stage','secure.protocol-package.stage'] for post in observed())
before=observed();assert success('recover',attachment=attach_id)==progress and success('resume',attachment=attach_id)==progress
assert success('attachments')==[progress] and success('installs')==[] and observed()==before and count()==5
read=success('read');assert read['workspace_id']==workspace and read['sequence']==5 and read['head']==end[3] and read['structure_status']=='ACTIVE'
instances=[r for r in read['objects'] if r['kind']=='instances' and r['id']==instance]
assert instances and len({r['id'] for r in instances})==1 and all(r['value']['protocol_digest']==item['protocol_digest'] and r['value']['origin_entrypoint']==item['entrypoint'] for r in instances)
protocols=[r for r in read['objects'] if r['kind']=='protocols' and r['id']==item['protocol_digest']]
assert len(protocols)==1 and protocols[0]['value']==oracle['logical_value']
assert any(r['kind']=='workspaces' and r['id']==workspace and r['value']['visibility']=='PRIVATE' and r['value']['owner']==item['owner_actor_id'] for r in read['objects'])
assert observed()==before and count()==5
print(json.dumps(dict(result='PASS',classification='operator_synthetic',interface=interface,mode=item['mode'],source_cohort='8900e8066ef8d07117a3b85771e831e4f84ffba8',source_removed=True,protocol_digest=item['protocol_digest'],service_commits=5,native_commit_posts=2,original_stage_count=1,distinct_native_begin=True,stage_reposts=0,signed_active_sequence=5)),flush=True)
