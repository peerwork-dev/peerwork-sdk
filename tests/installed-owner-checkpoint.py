"""An existing worker identity uses the converted space through the wheel."""
import json
import os
from pathlib import Path
import sys
import time
import peerwork

prefix = Path(os.environ['PEERWORK_INSTALLED_PREFIX'])
assert Path(peerwork.__file__).is_relative_to(prefix / 'python')
request = json.loads(Path(sys.argv[1]).read_text())
directory = Path(request['worker_dir'])
identity = directory / 'identity.state'
before = identity.read_bytes()
context = peerwork.bind_structure_context(
    profile=directory / 'context.json', expected_actor=request['worker'],
    expected_service='checkpoint-candidate', origin=request['origin'],
    identity_path=identity, journal_path=directory / 'operations.sqlite',
    workspace_ids=[request['workspace']], allow_loopback_http=True)
workspace = request['workspace']
scope = dict(instance_id=request['instance'], protocol_digest=request['protocol'])
records = context.execute_structure_intent(workspace, dict(
    action='structure.records.read', body={'limit': 1}, **scope))
assert records['status'] == 'verified'
assert records['opened_contents'][0]['state'] == 'KEY_UNAVAILABLE'
assert records['result']['records'][0]['source']['assurance'] == 'OWNER_ATTESTED_CONVERSION'

def act(name, values, revision, key):
    result = context.operate(workspace, {'kind': 'protocol.action', **scope,
        'expected_instance_revision': revision, 'action_id': name,
        'values': values}, key)
    assert result['status'] == 'verified', result
    assert result['result']['status'] == 'APPLIED', result
    return result

claimed = act('lease.claim', dict(expected_generation=0, generation=1,
    expires_at=int(time.time() * 1000) + 10000), 1, 'converted-claim')
assert claimed['result']['state']['holder'] == request['worker']
renewed = act('lease.renew', dict(expected_generation=1,
    expires_at=int(time.time() * 1000) + 20000), 2, 'converted-renew')
assert renewed['result']['state']['expires_at'] > claimed['result']['state']['expires_at']
completed = act('lease.use', dict(expected_generation=1,
    result='Converted work delivered'), 3, 'converted-deliver')
assert completed['result']['state']['last_result'] == 'Converted work delivered'
assert identity.read_bytes() == before
print(json.dumps({'status': 'PASS', 'actor_id': request['worker'],
    'holder': completed['result']['state']['holder'], 'generation': 1,
    'body_delivery': 'KEY_UNAVAILABLE_WITH_STRUCTURE_PRESERVED'}))
