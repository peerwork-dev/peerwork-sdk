"""One installed-interface explicit composition recovery/action scenario."""
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
for path,key in [('crates/runtime/src/secure_owner_attach.rs','PEERWORK_TEST_ATTACH_SOURCE_SHA256'),('tests/legacy-owner-install-intent.mjs','PEERWORK_TEST_LEGACY_HELPER_SHA256'),('tests/reference-kernel-server.mjs','PEERWORK_TEST_REFERENCE_FIXTURE_SHA256'),('tests/legacy-owner-install-composition-material.mjs','PEERWORK_TEST_COMPOSITION_HELPER_SHA256')]:
    assert hashlib.sha256((SOURCE/path).read_bytes()).hexdigest()==os.environ[key]
fixture=json.loads(Path(os.environ['PEERWORK_TEST_HOST_FIXTURE_JSON']).read_text())
assert len(fixture['sources'])==1
item=fixture['sources'][0];interface=os.environ['PEERWORK_TEST_INTERFACE']
assert item['interface']==interface and interface in ['python','node','cli'] and item['mode']=='direct-composition-begin-before-post'
origin=fixture['origin'];workspace=item['workspace_id'];command=item['pending_command_id'];instance=item['instance_id']
assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
database=STATE/'kernel/control.sqlite';native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
source_input=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=item['owner_actor_id'],expected_owner_key_id=item['owner_key_id'])
source_file=STATE/'source-input.json';source_file.write_text(json.dumps(source_input));source_file.chmod(0o600)
options_path=Path(item['options_path']);material_path=Path(item['material_path']);options=options_path.read_text();material=material_path.read_text()
parsed=json.loads(options);oracle=item['compiler_oracle'];composition=item['composition']
assert len(parsed['dependencies'])==1 and parsed['dependencies']==composition['dependencies']
assert parsed['manifest']==composition['source_manifest'] and composition['source_digest']==item['source_digest']
assert item['canonical_options_hash']!=item['intent_hash'] and oracle['compiler_own_source_digest']!=item['source_digest']
assert json.loads(material)['bindings']=={} and item['explicit_dependency_count']==1 and item['compiler_equality'] is True
assert parsed['grants']==[dict(actor_id=item['owner_actor_id'],actions=['discussion.post'],protocol_roles=['CONTRIBUTOR'],capabilities=['POST'])]
task_command='r'*43;message='Installed explicit composition / '+interface

def count(selected=None):
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        if selected is None:return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?',(workspace,)).fetchone()[0]
        return db.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?',(workspace,selected)).fetchone()[0]

def observed():
    rows=[json.loads(line) for line in Path(fixture['request_log']).read_text().splitlines()[fixture['fixture_request_lines']:]]
    return [row for row in rows if row['host']==urlsplit(origin).netloc and row['path']==item['expected_native_request']['path']]

def invoke(operation,*,selected_command=command,digest=None,selected_options=options,selected_material=material,attachment=None):
    if interface=='python':
        # Reopen on every operation; source paths are used only by inspect/attach.
        owner=peerwork.SecureOwnerWorkspaceClient(origin,str(native),allow_loopback_http=True)
        try:
            if operation=='inspect':value=owner.inspect_pending_direct_install_packet(**source_input,selected_command_id=selected_command,options_json=selected_options,material_json=selected_material)
            elif operation=='attach':value=owner.attach_pending_direct_install_packet(**source_input,selected_command_id=selected_command,expected_ts_state_digest=digest,options_json=selected_options,material_json=selected_material)
            elif operation=='attachments':value=owner.attachments()
            elif operation=='resume':value=owner.resume_attachment(attachment)
            elif operation=='recover':value=owner.recover_pending_direct_install_packet(attachment,selected_command)
            elif operation=='read':value=owner.read(workspace)
            elif operation=='installs':value=owner.private_package_installer(workspace).installs()
            elif operation=='submit':value=owner.private_actions(workspace).submit('discussion.post',instance,{'message':message},command_id=task_command)
            elif operation=='status':value=owner.private_actions(workspace).reconcile(task_command)
            elif operation=='retry':value=owner.private_actions(workspace).retry_saved(task_command)
            else:raise AssertionError(operation)
            return dict(ok=True,value=value)
        except peerwork.OwnerWorkspaceError as error:return dict(ok=False,code=error.code)
    if interface=='node':
        code=r'''
void(async()=>{
 const fs=require('node:fs'),sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE),x=JSON.parse(fs.readFileSync(0,'utf8'));
 const owner=sdk.openSecureOwnerWorkspaces(x.config);let value;
 switch(x.operation){
 case 'inspect':value=await owner.inspectPendingDirectInstallPacket(x.input,x.command,x.options,x.material);break;
 case 'attach':value=await owner.attachPendingDirectInstallPacket(x.input,x.command,x.digest,x.options,x.material);break;
 case 'attachments':value=await owner.attachments();break;
 case 'resume':value=await owner.resumeAttachment(x.attachment);break;
 case 'recover':value=await owner.recoverPendingDirectInstallPacket(x.attachment,x.command);break;
 case 'read':value=await owner.read(x.workspace);break;
 case 'installs':value=await owner.privatePackageInstaller(x.workspace).installs();break;
 case 'submit':value=await owner.privateActions(x.workspace).submit('discussion.post',x.instance,{message:x.message},{commandId:x.taskCommand});break;
 case 'status':value=await owner.privateActions(x.workspace).reconcile(x.taskCommand);break;
 case 'retry':value=await owner.privateActions(x.workspace).retrySaved(x.taskCommand);break;
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
        elif operation in ['read','installs','submit','status','retry']:
            value['workspace']=workspace
            if operation in ['submit','status','retry']:value.update(instance=instance,message=message,taskCommand=task_command)
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
        args=['owner-direct-packet-'+operation,str(source_file),selected_command]+([digest] if operation=='attach' else [])+[str(opath),str(mpath)]
    elif operation=='attachments':args=['owner-attachments']
    elif operation=='resume':args=['owner-attach-resume',attachment]
    elif operation=='recover':args=['owner-direct-packet-recover',attachment,selected_command]
    elif operation=='read':args=['owner-read',workspace]
    elif operation=='installs':args=['owner-private-install-list',workspace]
    elif operation=='submit':
        p=STATE/'action-input.json';p.write_text(json.dumps(dict(action_id='discussion.post',instance_id=instance,body_json=json.dumps({'message':message}),command_id=task_command)));p.chmod(0o600)
        args=['owner-private-action-submit',workspace,str(p)]
    elif operation in ['status','retry']:args=['owner-private-action-'+('status' if operation=='status' else 'retry'),workspace,task_command]
    else:raise AssertionError(operation)
    result=subprocess.run([os.environ['PEERWORK_TEST_CLI'],'secure',args[0],str(config_file),*args[1:]],capture_output=True,text=True,timeout=120)
    value=json.loads(result.stdout if result.returncode==0 else result.stderr)
    return dict(ok=True,value=value) if result.returncode==0 else dict(ok=False,code=value['code'])

def success(operation,**kwargs):
    result=invoke(operation,**kwargs);assert result['ok'],dict(interface=interface,phase=operation,code=result.get('code'));return result['value']

assert count()==1 and count(command)==0 and observed()==[] and success('attachments')==[]
inventory=success('inspect')
assert inventory['status']=='PENDING_UNRESOLVED' and inventory['instance_id']==instance and inventory['command_id']==command and inventory['intent_hash']==item['intent_hash'] and inventory['original_commit_hash']==item['pending_commit_hash'] and len(inventory['ts_state_digest'])==64
changed=json.loads(options);changed['dependencies'][0]['digest']='0'*64
for args,code in [(dict(selected_options=json.dumps(changed)),'SOURCE_UNRESOLVED'),(dict(selected_material='{}'),'SOURCE_UNRESOLVED')]:
    refusal=invoke('inspect',**args);assert refusal==dict(ok=False,code=code)
    assert success('attachments')==[] and count()==1 and observed()==[]
assert invoke('attach',digest='0'*64)==dict(ok=False,code='SOURCE_CHANGED')
assert success('attachments')==[] and count()==1 and observed()==[]
progress=success('attach',digest=inventory['ts_state_digest']);attach_id=progress['attach_id']
assert progress['status']=='ATTACHED_RESTRICTED' and progress['sequence']==1 and progress['pending_direct_install_status']=='PENDING_UNRESOLVED' and progress['pending_direct_install_command_id']==command and progress['pending_direct_install_instance_id']==instance
assert count()==1 and observed()==[]
shutil.move(str(STATE/item['fixture_dir']),str(STATE/'source-removed'))
for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(item[key]).exists()
assert success('attachments')==[progress] and success('resume',attachment=attach_id)==progress
assert invoke('recover',attachment=attach_id,selected_command='z'*43)==dict(ok=False,code='ATTACH_CONFLICT')
assert count()==1 and observed()==[]
for _ in range(8):
    if progress['status']=='ATTACHED':break
    progress=success('recover',attachment=attach_id)
    assert progress['status'] in ['ATTACHED_RESTRICTED','ATTACHED']
assert progress['status']=='ATTACHED' and progress['pending_direct_install_status']=='ACCEPTED' and progress['sequence']==3
assert count()==3 and count(command)==1 and len(observed())==2
first=observed()[0];assert {k:first[k] for k in ['method','path','body_sha256']}==item['expected_native_request'] and first['command_id']==command
with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
    commits=db.execute('SELECT sequence,command_id,action_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(workspace,)).fetchall()
assert [r[2] for r in commits]==['secure.bootstrap','secure.structure.begin','secure.structure.end'] and commits[1][1]==command and commits[1][3]==item['pending_commit_hash']
end=commits[2];assert hashlib.sha256(end[4].encode()).hexdigest()==end[3]
assert observed()[1]['method']=='POST' and observed()[1]['path']==first['path'] and observed()[1]['command_id']==end[1] and observed()[1]['body_sha256']==hashlib.sha256(('{"commit":'+end[4]+'}').encode()).hexdigest()
before=observed();assert success('recover',attachment=attach_id)==progress and success('resume',attachment=attach_id)==progress and success('attachments')==[progress] and success('installs')==[] and observed()==before and count()==3
read=success('read');assert read['workspace_id']==workspace and read['sequence']==3 and read['head']==end[3] and read['structure_status']=='ACTIVE'
instances=[r for r in read['objects'] if r['kind']=='instances' and r['id']==instance]
assert instances and all(r['value']['protocol_digest']==item['protocol_digest'] and r['value']['origin_entrypoint']==item['entrypoint'] for r in instances)
protocols=[r for r in read['objects'] if r['kind']=='protocols' and r['id']==item['protocol_digest']];assert len(protocols)==1
protocol=protocols[0]['value'];assert protocol['workspace_id']==workspace and protocol['digest']==item['protocol_digest'] and protocol['manifest']==oracle['compiled_manifest'] and protocol['resolved_manifest']==oracle['compiled_manifest'] and protocol['composition']==composition
assert protocol['composition']['source_manifest']==parsed['manifest'] and protocol['composition']['dependencies']==parsed['dependencies'] and protocol['composition']['source_digest']==item['source_digest']
assert any(r['kind']=='workspaces' and r['id']==workspace and r['value']['visibility']=='PRIVATE' and r['value']['owner']==item['owner_actor_id'] for r in read['objects'])
success('submit');accepted=success('status');receipt=accepted['receipt']
assert accepted['status']=='ACCEPTED' and accepted['workspace_id']==workspace and accepted['action_id']=='discussion.post' and accepted['command_id']==task_command and accepted['sequence']==4
assert receipt['actor_id']==item['owner_actor_id'] and receipt['instance_id']==instance and receipt['action_id']=='discussion.post' and receipt['command_id']==task_command and receipt['sequence']==4 and receipt['commit_hash']==accepted['commit_hash'] and len(receipt['effects'])==1
effect=receipt['effects'][0];assert effect['schema_ref']=='discussion.message'
after=success('read');assert after['workspace_id']==workspace and after['sequence']==4 and after['head']==accepted['commit_hash'] and after['structure_status']=='ACTIVE'
notes=[r for r in after['objects'] if r['kind']=='records' and r['value'].get('payload',{}).get('message')==message]
assert len(notes)==1
record=notes[0];assert record['id']==effect['record_id'] and record['value']['schema_ref']=='discussion.message' and record['value']['instance_id']==instance and record['value']['protocol_digest']==item['protocol_digest'] and record['value']['payload']==dict(message=message,reply_to=None,author=item['owner_actor_id'])
before=observed();assert count()==4 and count(task_command)==1 and len(before)==3 and before[-1]['command_id']==task_command
assert success('retry')==accepted and count()==4 and observed()==before
print(json.dumps(dict(result='PASS',classification='operator_synthetic',interface=interface,mode=item['mode'],source_cohort='c5e7a3d8e59ff913da545db2c82e6969646fbe1a',source_removed=True,protocol_digest=item['protocol_digest'],composition_source_digest=item['source_digest'],compiler_own_source_digest=oracle['compiler_own_source_digest'],explicit_dependencies=1,service_commits=4,native_commit_posts=3,original_begin_count=1,granted_action_count=1,decrypted_record_count=1)),flush=True)
