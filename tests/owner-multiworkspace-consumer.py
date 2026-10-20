"""Installed native Python SDK: existing A/B Owner, guard activation and leases."""
import json,sys,secrets,time
from pathlib import Path
import peerwork
config,source,meta=(json.loads(Path(p).read_text()) for p in sys.argv[1:4])
def progress(stage):
    Path(sys.argv[1]+'.progress.json').write_text(json.dumps(dict(stage=stage,utc_epoch=time.time()))+'\n')
progress('read-A-before')
owner=peerwork.SecureOwnerWorkspaceClient(**config)
before=owner.read(meta['workspace_a'])
progress('attach-B')
attached=owner.attach(**source)
assert attached['status']=='ATTACHED' and attached['coordination_intents']==[]
assert owner.attach(**source)['attach_id']==attached['attach_id']
directory=Path(source['protected_ts_state_path']).parent
directory.rename(directory.with_name(directory.name+'-removed'))
owner=peerwork.SecureOwnerWorkspaceClient(**config)
assert owner.resume_attachment(attached['attach_id'])['status']=='ATTACHED'
progress('reopen-A-and-B')
after=owner.read(meta['workspace_a'])
assert (after['head'],after['sequence'])==(before['head'],before['sequence'])
workspace=meta['workspace_b']
assert 'Existing canary ticket' in json.dumps(owner.read(workspace))
root=Path(__file__).resolve().parents[1]/'examples/private-bounded-lease'
pins=json.loads((root/'package-pins.json').read_text())
identity=peerwork.open_identity(str(Path(config['state_dir'])/'identity.state'))
instance=secrets.token_urlsafe(32)
installer=owner.private_package_installer(workspace)
grants=[dict(actor_id=identity['actor_id'],actions=['lease.claim','lease.renew','lease.reclaim','lease.use'],protocol_roles=['LEASE_ACTOR'],capabilities=['LEASE'],expires_at=None)]
progress('install-B-lease-protocol')
installed=installer.begin_direct((root/'closure.json').read_text(),pins['root_package_digest'],pins['protocol_digest'],instance,'boundedLease',grants_json=json.dumps(grants),disclose=[])
deadline=time.monotonic()+60
while installed['status']!='ACCEPTED':
    assert time.monotonic()<deadline,'original install remains pending'
    installed=installer.continue_install(installed['begin_command_id'])
read=owner.read(workspace)
guard=owner.guard_time(workspace)
progress('enable-B-trusted-time')
guard_operation=secrets.token_urlsafe(32)
enabled=guard.enable(expected_policy_hash=read['policy_hash'],audience=meta['audience'],service_key=meta['service_key'],disclosure='GUARD_WINDOW',operation_id=guard_operation)
deadline=time.monotonic()+60
while enabled['status']=='PENDING':
    assert time.monotonic()<deadline,'original guard activation remains pending'
    enabled=guard.resume(guard_operation)
assert enabled['status'] in ('ACCEPTED','ALREADY_ENABLED')
actions=owner.private_actions(workspace)
def act(action,body):
    progress('lease.'+action)
    result=actions.submit('lease.'+action,instance,body,operation_id=secrets.token_urlsafe(32))
    result=actions.reconcile(result['command_id'])
    assert result['status']=='ACCEPTED'
    return result
first=int(time.time()*1000)+10000
act('claim',dict(expected_generation=0,generation=1,expires_at=first))
renewed=max(int(time.time()*1000)+12000,first+1000)
act('renew',dict(expected_generation=1,expires_at=renewed))
act('use',dict(expected_generation=1,result='generation one'))
time.sleep(max(0,(renewed-time.time()*1000+100)/1000))
act('reclaim',dict(expected_generation=1,generation=2,expires_at=int(time.time()*1000)+45000))
checkpoint=owner.read(workspace)['sequence']
try: act('use',dict(expected_generation=1,result='stale generation'))
except peerwork.SecureActionError as error: assert error.code in ('ACTION_PREPARE_FAILED','ACTION_INPUT_INVALID')
else: raise AssertionError('stale generation accepted')
assert owner.read(workspace)['sequence']==checkpoint
act('use',dict(expected_generation=2,result='generation two'))
assert owner.read(meta['workspace_a'])['head']==before['head']
assert len(owner.attachments())==2
print(json.dumps(dict(status='PASS',fresh_A_B_reads=True,source_unavailable=True,guard_enabled=True,lease=dict(generation=2,claim=True,renew=True,reclaim=True,stale_generation_refused=True))))
