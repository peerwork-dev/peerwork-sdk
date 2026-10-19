#!/usr/bin/env python3
"""Installed peerwork-sdk only: no Node, TypeScript bridge, PEM import or raw envelope."""
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import urlparse
from urllib.request import urlopen
import peerwork

parser = argparse.ArgumentParser()
parser.add_argument('--origin', required=True)
parser.add_argument('--state-dir', required=True, type=Path)
parser.add_argument('--audience', required=True)
parser.add_argument('--service-key', required=True)
parser.add_argument('--allow-loopback-http', action='store_true')
args = parser.parse_args()
origin = urlparse(args.origin)
if origin.username is not None or origin.password is not None or args.origin != f'{origin.scheme}://{origin.netloc}' or not (origin.scheme == 'https' or args.allow_loopback_http and origin.scheme == 'http' and origin.hostname in ('localhost', '127.0.0.1', '::1')):
    raise SystemExit('TRUSTED_ORIGIN_REQUIRED')

def read_public(path):
    url = args.origin + path
    with urlopen(url, timeout=15) as response:
        if response.url != url:
            raise RuntimeError('SERVICE_REDIRECT_REFUSED')
        data = response.read(65537)
        if len(data) > 65536:
            raise RuntimeError('SERVICE_METADATA_TOO_LARGE')
        return json.loads(data)

version = importlib.metadata.version('peerwork-sdk')
parts = version.split('.')
if tuple(int(x.split('-')[0]) for x in parts[:3]) < (0, 1, 4):
    raise SystemExit('PEERWORK_SDK_0_1_4_REQUIRED')
discovery = read_public('/api/workspace/v1/discovery')
if discovery['audience'] != args.audience or discovery['receipt_public_key'] != args.service_key:
    raise SystemExit('SERVICE_PIN_MISMATCH')
capability = read_public('/api/workspace/v1/guard-time-capabilities')
if capability.get('expression_profile') != 'time-add-guard-window-v1' or capability.get('effects') != 'TIME_FREE':
    raise SystemExit('BOUNDED_LEASE_PROFILE_UNSUPPORTED')
root = Path(__file__).resolve().parent
pins = json.loads((root / 'package-pins.json').read_text())
closure = (root / 'closure.json').read_text()
args.state_dir.mkdir(mode=0o700)  # Explicitly new owner; do not overwrite/restart an uncertain run.
os.umask(0o077)
owner = peerwork.SecureOwnerWorkspaceClient(args.origin + "/", str(args.state_dir), allow_loopback_http=args.allow_loopback_http)
progress = {'sdk_version': version, 'operations': []}
def save():
    temporary = args.state_dir / 'example-progress.json.tmp'
    temporary.write_text(json.dumps(progress, indent=2) + '\n')
    os.replace(temporary, args.state_dir / 'example-progress.json')

deadline = time.monotonic() + 30
while True:
    try:
        prepared = owner.prepare('Installed SDK bounded lease example', 'PRIVATE', structured=True)
        break
    except peerwork.OwnerWorkspaceError as error:
        if error.code != 'ENROLLMENT_PENDING' or time.monotonic() >= deadline:
            raise
        time.sleep(0.25)
progress.update(workspace_id=prepared['workspace_id'], create_command_id=prepared['command_id']); save()
created = owner.resume(prepared['command_id'])
if created['status'] != 'CREATED':
    raise RuntimeError('WORKSPACE_PENDING: resume saved create_command_id')
workspace = created['workspace_id']
actor = peerwork.open_identity(str(args.state_dir / 'identity.state'))['actor_id']
instance = secrets.token_urlsafe(32)
progress['instance_id'] = instance; save()
installer = owner.private_package_installer(workspace)
grants = [dict(actor_id=actor, actions=['lease.claim', 'lease.renew', 'lease.reclaim', 'lease.use'], protocol_roles=['LEASE_ACTOR'], capabilities=['LEASE'], expires_at=None)]
installed = installer.begin_direct(closure, pins['root_package_digest'], pins['protocol_digest'], instance, 'boundedLease', grants_json=json.dumps(grants), disclose=[])
progress['install_begin_command_id'] = installed['begin_command_id']; save()
deadline = time.monotonic() + 60
while installed['status'] != 'ACCEPTED':
    if time.monotonic() >= deadline:
        raise RuntimeError('INSTALL_PENDING: continue saved install_begin_command_id')
    installed = installer.continue_install(progress['install_begin_command_id'])
read = owner.read(workspace)
operation = secrets.token_urlsafe(32)
progress['guard_time_operation_id'] = operation; save()
guard = owner.guard_time(workspace)
try:
    enabled = guard.enable(expected_policy_hash=read['policy_hash'], audience=args.audience, service_key=args.service_key, disclosure='GUARD_WINDOW', operation_id=operation)
except peerwork.OwnerWorkspaceError as error:
    if error.code not in ('GUARD_TIME_TRANSPORT_FAILED', 'GUARD_TIME_SERVER_REJECTED'):
        raise
    # The server may already have committed. Reconcile the same persisted intent.
    enabled = guard.resume(operation)
deadline = time.monotonic() + 60
while enabled['status'] == 'PENDING':
    if time.monotonic() >= deadline:
        raise RuntimeError('GUARD_TIME_PENDING: resume saved guard_time_operation_id')
    enabled = guard.resume(operation)
    if enabled['status'] == 'PENDING':
        time.sleep(0.1)
if enabled['status'] not in ('ACCEPTED', 'ALREADY_ENABLED'):
    raise RuntimeError('GUARD_TIME_PENDING: resume saved guard_time_operation_id')
actions = owner.private_actions(workspace)
def act(name, body):
    intent = {'action': 'lease.' + name, 'operation_id': secrets.token_urlsafe(32)}
    progress['operations'].append(intent); save()
    result = actions.submit(intent['action'], instance, body, operation_id=intent['operation_id'])
    intent['command_id'] = result['command_id']; save()
    result = actions.reconcile(result['command_id'])
    if result['status'] != 'ACCEPTED':
        raise RuntimeError('ACTION_PENDING: reconcile saved command_id before any retry')
    return result

# These are proposals. Only the signed transaction admission T authorizes them.
first = int(time.time() * 1000) + 10000
act('claim', dict(expected_generation=0, generation=1, expires_at=first))
renewed = max(int(time.time() * 1000) + 12000, first + 1000)
act('renew', dict(expected_generation=1, expires_at=renewed))
act('use', dict(expected_generation=1, result='synthetic work at generation 1'))
time.sleep(max(0, (renewed - time.time() * 1000 + 150) / 1000))
act('reclaim', dict(expected_generation=1, generation=2, expires_at=int(time.time() * 1000) + 45000))
before = owner.read(workspace)['sequence']
try:
    act('use', dict(expected_generation=1, result='stale work'))
except peerwork.SecureActionError as error:
    if error.code not in ('ACTION_PREPARE_FAILED', 'ACTION_INPUT_INVALID'):
        raise
else:
    raise RuntimeError('STALE_GENERATION_ACCEPTED')
if owner.read(workspace)['sequence'] != before:
    raise RuntimeError('REJECTED_ACTION_CHANGED_CHECKPOINT')
act('use', dict(expected_generation=2, result='synthetic work at generation 2'))
final = owner.read(workspace)
progress['status'] = 'PASS'; save()
print(json.dumps(dict(status='PASS', sdk_version=version, workspace_id=workspace, instance_id=instance, generation=2, stale_generation_rejected=True, sequence=final['sequence'], head=final['head'])))
