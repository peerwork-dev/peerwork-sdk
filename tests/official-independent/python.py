"""Public installed Python API adapter; no Node invocation."""
import json,sys,os
from pathlib import Path
import peerwork
sdk=Path(os.environ['PEERWORK_TEST_SDK_ROOT']);assert Path(peerwork.__file__).is_relative_to(sdk/'dist/python-consumer')
assert not Path('/opt/node24/bin/node').exists()
r=json.loads(Path(sys.argv[1]).read_text());c=r['config'];op=r['op'];x=r.get('input',{});w=r.get('workspace');cmd=r.get('command');origin=c['origin'];state=c['state_dir']
o=peerwork.SecureOwnerWorkspaceClient(origin,state,allow_loopback_http=True)
def member():return peerwork.SecurePublicActionClient(origin,state,c['identity_path'],c['workspace_id'],owner_actor_id=c['owner_actor_id'],owner_key_id=c['owner_key_id'],allow_loopback_http=True)
if op=='runtime':
 import peerwork._peerwork_native as native,hashlib
 v=dict(module=peerwork.__file__,native=native.__file__,wrapper_sha256=hashlib.sha256(Path(peerwork.__file__).read_bytes()).hexdigest(),native_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),executable=sys.executable,node_absent=True)
elif op=='prepare':v=o.prepare('Independent official business','PUBLIC',structured=True)
elif op=='resume':v=o.resume(cmd)
elif op=='identity':v=peerwork.open_identity(state+'/identity.state')
elif op=='owner-read':v=o.read(w)
elif op=='install-begin':v=o.public_installer(w).begin(**x)
elif op=='install-continue':v=o.public_installer(w).continue_install(cmd)
elif op=='owner-submit':v=o.public_actions(w).submit(x['action_id'],x['instance_id'],x['body'],exact_input_refs=x.get('exact_input_refs'),command_id=x['command_id'])
elif op=='owner-status':v=o.public_actions(w).reconcile(cmd)
elif op=='owner-retry':v=o.public_actions(w).retry_saved(cmd)
elif op.startswith('recipient-'):
 a=peerwork.SecureRecipientEnrollmentClient(origin,state,allow_loopback_http=True);v=a.create_local()if op=='recipient-create'else a.publish()
elif op=='lookup':v=peerwork.SecureIdentityDirectoryClient(origin,state,allow_loopback_http=True).lookup(x['actor_id'],x['key_id'])
elif op=='offer':v=o.public_admission(w).offer(x['certificate_json'],json.dumps(x['scopes']),message='Adopt exact proposal')
elif op=='deliver':v=o.public_admission(w).deliver(cmd)
elif op=='delivery-resume':v=o.public_admission(w).retry_delivery(cmd)
elif op in ['consent','receive','receive-resume']:
 a=peerwork.SecureInvitationClient(origin,state,c['workspace_id'],c['owner_actor_id'],c['owner_key_id'],allow_loopback_http=True);v=a.decide(cmd,'ACCEPT')if op=='consent'else a.retry_receive(cmd)if op=='receive-resume'else a.receive(cmd)
elif op=='member-read':v=member().read()
elif op=='member-submit':v=member().submit(x['action_id'],x['instance_id'],x['body'],exact_input_refs=x['exact_input_refs'],command_id=x['command_id'])
elif op=='member-status':v=member().reconcile(cmd)
elif op=='member-retry':v=member().retry_saved(cmd)
else:raise AssertionError(op)
print(json.dumps(v))
