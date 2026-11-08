"""Real locally installed wheel, selected identity and backend Context."""
import json
import base64
import os
from pathlib import Path
import sqlite3
import sys
import peerwork

assert Path(peerwork.__file__).is_relative_to(Path(os.environ['PEERWORK_INSTALLED_PREFIX']) / 'python'), peerwork.__file__
input = json.loads(Path(sys.argv[1]).read_text())
worker_dir = Path(input['worker_dir'])
identity = worker_dir / 'identity.state'
before = identity.read_bytes()
kernel = peerwork.KernelClient(input['origin'], str(worker_dir / 'operations.sqlite'), str(identity), allow_loopback_http=True)
key = kernel.ensure_local_content_key(input['workspace'])
assert key['workspace_id'] == input['workspace']
context = peerwork.bind_structure_context(profile=worker_dir / 'context.json', expected_actor=input['worker'],
    expected_service='installed-candidate', origin=input['origin'], identity_path=identity,
    journal_path=worker_dir / 'operations.sqlite', workspace_ids=[input['workspace']], allow_loopback_http=True)
assert identity.read_bytes() == before
assert context.descriptor['execution_profile'] == 'backend-structure-v1'
page = context.discover(input['workspace'], limit=1)
assert page['result']['instances'][0]['instance_id'] == input['instance']
current = context.describe(input['workspace'], input['instance'], protocol_digest=input['protocol'])
assert current['result']['state']['holder'] is None
intent = {'kind': 'protocol.action', 'instance_id': input['instance'], 'protocol_digest': input['protocol'],
          'expected_instance_revision': current['result']['revision'], 'action_id': 'claim', 'values': {},
          'plaintext_contents': [{'record_index': 0, 'text': 'Installed private body 🚀'}]}
pending = context.operate(input['workspace'], intent, 'claim-once')
assert pending['status'] == 'pending', pending
assert pending['result']['code'] == 'OUTCOME_UNKNOWN', pending
page = kernel.pending_page(limit=1)
assert [p['command_id'] for p in page['items']] == [pending['command_id']]
restored = context.recover(input['workspace'], operation_id='claim-once')
assert restored['status'] == 'verified', restored
assert restored['command_id'] == pending['command_id']
assert restored['result']['state']['holder'] == input['worker']
assert context.operate(input['workspace'], intent, 'claim-once')['command_id'] == restored['command_id']
assert kernel.pending_page(limit=1)['items'] == []
records = context.execute_structure_intent(input['workspace'], {'action': 'structure.records.read',
    'instance_id': input['instance'], 'protocol_digest': input['protocol'], 'body': {'schema': 'claim', 'limit': 1}})
assert len(records['result']['records']) == 1
assert records['result']['records'][0]['source']['actor_id'] == input['worker']
assert records['opened_contents'][0]['state'] == 'OPENED'
assert records['opened_contents'][0]['text'] == 'Installed private body 🚀'
assert records['opened_contents'][0]['key_id'] == key['key_id']
assert 'Installed private body' not in json.dumps(records['result'])
# Same identity/service, different Context and outbox: key reuse is independent
# of operation recovery and never imports an identity or retained history.
fresh = peerwork.bind_structure_context(profile=worker_dir / 'fresh-context.json', expected_actor=input['worker'],
    expected_service='installed-candidate', origin=input['origin'], identity_path=identity,
    journal_path=worker_dir / 'fresh-operations.sqlite', workspace_ids=[input['workspace']], allow_loopback_http=True)
fresh_records = fresh.execute_structure_intent(input['workspace'], {'action': 'structure.records.read',
    'instance_id': input['instance'], 'protocol_digest': input['protocol'], 'body': {'limit': 1}})
assert fresh_records['opened_contents'][0]['text'] == 'Installed private body 🚀'
events = context.execute_structure_intent(input['workspace'], {'action': 'structure.events.read',
    'body': {'after_sequence': input['after_sequence'], 'limit': 4}})
assert len(events['result']['events']) == 1
assert events['result']['events'][0]['actor_id'] == input['worker']
with sqlite3.connect(worker_dir / 'operations.sqlite') as db:
    intents = db.execute('SELECT count(*) FROM kernel_intents').fetchone()[0]
    accepted = db.execute('SELECT count(*) FROM accepted_responses').fetchone()[0]
    for signed, http_body in db.execute('SELECT signed_jws, http_body FROM kernel_intents'):
        payload = signed.split('.')[1]
        saved = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        assert 'Installed private body' not in json.dumps(saved)
        assert 'plaintext_contents' not in saved
        assert saved['body']['contents'][0]['body']['key_id'] == key['key_id']
        assert 'Installed private body' not in bytes(http_body).decode()
assert intents == accepted == 1, (intents, accepted)
assert identity.read_bytes() == before
print(json.dumps({'actor_id': context.descriptor['actor_id'], 'state_holder': restored['result']['state']['holder'],
                  'fingerprint': context.descriptor['fingerprint'], 'durable_intents': intents, 'accepted_responses': accepted}))
