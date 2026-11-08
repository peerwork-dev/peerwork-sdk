#!/usr/bin/env python3
"""Offline interoperability check against the actual published Node store.

Node/Python are fixture drivers only; the installed importer has no language
runtime dependency. No service, user profile or host conversation is opened.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


def run(argv, *, code=0):
    p = subprocess.run([str(v) for v in argv], capture_output=True, text=True,
                       encoding='utf-8', timeout=45)
    assert p.returncode == code, f'fixture command failed with exit {p.returncode}: {p.stderr[-1200:]}'
    return json.loads(p.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    args = parser.parse_args()
    sdk = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('installed_smoke', sdk / 'tests/installed-participant-smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    with tempfile.TemporaryDirectory(prefix='peerwork-old-delivery-') as temporary:
        root = Path(temporary).resolve()
        smoke.protect(root)
        source = root / 'source'
        archive = root / 'archive'
        identity = run([args.cli, 'identity', 'create', root / 'identity'])
        # Produce with the official old implementation, not a hand-copied schema.
        produce = r'''
const {ReceiverStore}=require(process.argv[1]);
const path=require('node:path'),fs=require('node:fs');
const binding={binding:{expected_origin:'https://example.invalid',expected_actor:process.argv[3]},host:{kind:'codex',thread_id:'original'},includeSelf:false};
const store=new ReceiverStore(process.argv[2],binding);
store.set('selftest',{status:'UNCERTAIN',message_id:'original-probe'});
store.persist(Array.from({length:65},(_,i)=>({sequence:i+1,kind:'BUSINESS',marker:'ORIGINAL-PRIVATE-SYNTHETIC'})));
store.mark(1,'UNCERTAIN',null,'a'.repeat(64));
store.mark(2,'ACKED','original-receipt');
const digest=store.get('binding');store.close();
console.log(JSON.stringify({binding_digest:digest,binding}));
'''
        produced = run([args.node, '-e', produce, sdk / 'bindings/node/delivery/store.cjs', source, identity['actor_id']])
        selection = {'format': 'peerwork.legacy-delivery-import.v1', 'source_directory': str(source),
                     'archive_directory': str(archive), 'identity_path': str(root / 'identity'),
                     'expected_actor': identity['actor_id'], 'expected_binding_digest': produced['binding_digest'],
                     'kind': 'RECEIVER', 'source_stopped': True}
        path = root / 'selection.json'
        path.write_text(json.dumps(selection))
        path.chmod(0o600)
        imported = run([args.cli, 'runtime', 'import-node-delivery', path])
        assert imported['state'] == 'LEGACY_EVIDENCE_IMPORTED', imported
        assert imported['archived_records'] == 67, imported
        assert imported == run([args.cli, 'runtime', 'import-node-delivery', path])
        unknown = run([args.cli, 'runtime', 'legacy-evidence', path, 'delivery:1'])
        assert unknown['evidence']['original_status'] == 'UNCERTAIN'
        assert unknown['evidence']['original_body_hash'] == 'a' * 64
        assert unknown['native_delivery'] == 'NOT_CREATED'
        assert unknown['assurance'] == 'LOCAL_LEGACY_EVIDENCE_NOT_REVERIFIED'
        assert 'ORIGINAL-PRIVATE-SYNTHETIC' in unknown['evidence']['original_event_json']
        acked = run([args.cli, 'runtime', 'legacy-evidence', path, 'delivery:2'])
        assert acked['evidence']['original_receipt'] == 'original-receipt'
        assert acked['model_response'] == 'NOT_ATTESTED'
        # The same published constructor must refuse the retired installation.
        reopen = r'''
const {ReceiverStore}=require(process.argv[1]);
try{const s=new ReceiverStore(process.argv[2],JSON.parse(process.argv[3]));s.close();console.log(JSON.stringify({code:'UNEXPECTED_REOPEN'}));}
catch(e){console.log(JSON.stringify({code:e.code}));}
'''
        refused = run([args.node, '-e', reopen, sdk / 'bindings/node/delivery/store.cjs', source, json.dumps(produced['binding'])])
        assert refused['code'] == 'DELIVERY_BINDING_MISMATCH', refused
        assert not (archive / 'inbox.sqlite').exists()
        assert not (archive / 'participant.sqlite').exists()
        assert b'ORIGINAL-PRIVATE-SYNTHETIC' not in (archive / 'legacy-delivery.sqlite').read_bytes()
    print(json.dumps({'state': 'PASS', 'fixture': 'ACTUAL_PUBLISHED_NODE_RECEIVER_STORE',
                      'records_preserved': 67, 'original_unknown_retained': True,
                      'old_constructor_refused': True, 'network_requests': 0,
                      'host_inputs': 0, 'synthetic_state_removed': True}))


if __name__ == '__main__':
    main()
