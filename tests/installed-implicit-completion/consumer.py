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
assert item['interface']==interface and interface in ['python','node','cli'] and item['mode'] in ['direct-implicit-page-applied-loss','direct-implicit-completed-end']
completed_map=item['mode'].endswith('completed-end')
origin=fixture['origin'];workspace=item['workspace_id'];instance=item['instance_id'];command=instance if completed_map else item['pending_command_id']
assert origin.startswith('http://127.0.0.1:') and STATE.stat().st_mode&0o077==0
database=STATE/'kernel/control.sqlite';native=STATE/'native';config=dict(origin=origin,state_dir=str(native),allow_loopback_http=True)
config_file=STATE/'config.json';config_file.write_text(json.dumps(config));config_file.chmod(0o600)
source_input=dict(workspace_id=workspace,protected_ts_state_path=item['state_path'],protected_ts_intent_db_path=item['intent_db_path'],protected_owner_pkcs8_path=item['pem_path'],expected_owner_actor_id=item['owner_actor_id'],expected_owner_key_id=item['owner_key_id'])
source_file=STATE/'source-input.json';source_file.write_text(json.dumps(source_input));source_file.chmod(0o600)
options_path=Path(item['options_path']);material_path=Path(item['material_path']);options=options_path.read_text();material=material_path.read_text()
parsed=json.loads(options);oracle=item['compiler_oracle'];composition=item['composition']
assert 'dependencies' not in parsed and item['original_dependencies_omitted'] is True
assert len(composition['dependencies'])==1 and composition['dependencies'][0]['manifest']['dependencies']==[]
assert parsed['manifest']==composition['source_manifest'] and composition['source_digest']==item['source_digest']
assert item['explicit_dependency_count']==0 and item['authenticated_dependency_count']==1 and item['compiler_equality'] is True
assert Path(peerwork.__file__).is_relative_to(SOURCE/'dist/python-consumer')
initial=item['latest_sequence'];final=initial if completed_map else item['initial_sequence']+4
begin=item['original_begin_command_id']

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
            if operation=='inspect':value=(owner.inspect_completed_direct_install(**source_input,selected_instance_id=selected_command,options_json=selected_options,material_json=selected_material) if completed_map else owner.inspect_pending_direct_install_packet(**source_input,selected_command_id=selected_command,options_json=selected_options,material_json=selected_material))
            elif operation=='attach':value=(owner.attach_completed_direct_install(**source_input,selected_instance_id=selected_command,expected_ts_state_digest=digest,options_json=selected_options,material_json=selected_material) if completed_map else owner.attach_pending_direct_install_packet(**source_input,selected_command_id=selected_command,expected_ts_state_digest=digest,options_json=selected_options,material_json=selected_material))
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

def success(operation,**kwargs):
    result=invoke(operation,**kwargs);assert result['ok'],dict(interface=interface,phase=operation,code=result.get('code'));return result['value']

assert count()==initial and count(begin)==1 and observed()==[] and success('attachments')==[]
assert completed_map or count(command)==1
inventory=success('inspect')
assert inventory['instance_id']==instance and inventory['intent_hash']==item['intent_hash']
if completed_map:
    assert inventory['status']=='COMPLETED_IN_SIGNED_REPLAY' and inventory['end_sequence']==initial and inventory['begin_command_id']==begin and inventory['begin_commit_hash']==item['original_begin_commit_hash'] and inventory['protocol_digest']==item['protocol_digest']
else:
    assert inventory['status']=='APPLIED_IN_SIGNED_REPLAY' and inventory['command_id']==command and inventory['original_commit_hash']==item['pending_commit_hash']
assert invoke('inspect',selected_material='{}')==dict(ok=False,code='SOURCE_UNRESOLVED')
assert invoke('attach',digest='0'*64)==dict(ok=False,code='SOURCE_CHANGED')
assert success('attachments')==[] and count()==initial and observed()==[]
progress=success('attach',digest=inventory['ts_state_digest']);attach_id=progress['attach_id']
assert progress['status']==('ATTACHED' if completed_map else 'ATTACHED_RESTRICTED') and progress['sequence']==initial and progress['pending_direct_install_status']==('ACCEPTED' if completed_map else 'BEGIN_ACCEPTED_CONTINUATION_PENDING') and progress['pending_direct_install_command_id']==(begin if completed_map else command) and progress['pending_direct_install_instance_id']==instance
assert count()==initial and observed()==[]
shutil.move(str(STATE/item['fixture_dir']),str(STATE/'source-removed'))
for key in ['state_path','pem_path','intent_db_path','options_path','material_path']:assert not Path(item[key]).exists()
assert success('attachments')==[progress] and success('resume',attachment=attach_id)==progress
if not completed_map:
    assert invoke('recover',attachment=attach_id,selected_command='z'*43)==dict(ok=False,code='ATTACH_CONFLICT')
    for _ in range(8):
        if progress['status']=='ATTACHED':break
        progress=success('recover',attachment=attach_id)
assert progress['status']=='ATTACHED' and progress['pending_direct_install_status']=='ACCEPTED' and progress['sequence']==final
assert count()==final and count(begin)==1 and len(observed())==final-initial
with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
    commits=db.execute('SELECT sequence,command_id,action_id,commit_hash,artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence',(workspace,)).fetchall()
assert commits[item['initial_sequence']][1:4]==(begin,'secure.structure.begin',item['original_begin_commit_hash'])
if not completed_map:
    selected=commits[item['pending_sequence']-1];assert selected[1]==command and selected[3]==item['pending_commit_hash'] and selected[2]=='secure.structure.page' and count(command)==1
    # Applied PAGE is reconciled: only the next PAGE and END may be posted.
    new=commits[initial:];assert [r[2] for r in new]==['secure.structure.page','secure.structure.end']
    assert all(r['command_id']!=command for r in observed())
    for row,request in zip(new,observed()):
        assert hashlib.sha256(row[4].encode()).hexdigest()==row[3]
        assert request['method']=='POST' and request['path']==item['expected_native_request']['path'] and request['command_id']==row[1] and request['body_sha256']==hashlib.sha256(('{"commit":'+row[4]+'}').encode()).hexdigest()
    assert success('recover',attachment=attach_id)==progress
before=observed();assert success('resume',attachment=attach_id)==progress and success('attachments')==[progress] and success('installs')==[] and observed()==before and count()==final
read=success('read');assert read['workspace_id']==workspace and read['sequence']==final and read['head']==commits[-1][3] and read['structure_status']=='ACTIVE'
instances=[r for r in read['objects'] if r['kind']=='instances' and r['id']==instance]
assert instances and all(r['value']['protocol_digest']==item['protocol_digest'] and r['value']['origin_entrypoint']==item['entrypoint'] for r in instances)
protocols=[r for r in read['objects'] if r['kind']=='protocols' and r['id']==item['protocol_digest']];assert len(protocols)==1
protocol=protocols[0]['value'];assert protocol['workspace_id']==workspace and protocol['manifest']==oracle['compiled_manifest'] and protocol['resolved_manifest']==oracle['compiled_manifest'] and protocol['composition']==composition
node=composition['dependencies'][0]
deps=[r for r in read['objects'] if r['kind']=='protocols' and r['id']==node['digest']];assert len(deps)==1
assert deps[0]['value']['manifest']==node['manifest']
assert any(r['kind']=='instances' and r['value'].get('origin_entrypoint')=='implicit_dependency' and r['value']['protocol_digest']==node['digest'] for r in read['objects'])
print(json.dumps(dict(result='PASS',classification='operator_synthetic',interface=interface,mode=item['mode'],source_cohort='d47bbd57f5a1e374d6e60cb8f8aa1c565f9c3559',source_removed=True,protocol_digest=item['protocol_digest'],composition_source_digest=item['source_digest'],implicit_dependencies=1,initial_commits=initial,final_commits=final,native_commit_posts=len(before),selected_page_command_id=None if completed_map else command,selected_page_count=0 if completed_map else count(command),original_begin_command_id=begin,original_begin_count=count(begin),final_head=read['head'],python_module=peerwork.__file__)),flush=True)
