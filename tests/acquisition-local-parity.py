"""Compiled-native local parity only: no service, installed cohort or external traffic."""
import asyncio
import faulthandler
faulthandler.dump_traceback_later(30, exit=True)
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
TARGET=Path(os.environ['PEERWORK_ACQUISITION_TARGET'])
NODE=os.environ['PEERWORK_ACQUISITION_NODE']

def ref(kind,n): return f'obs:{kind}:{n:032x}'
def checked(n): return dict(status='checked',reference=ref('evidence',n))
with tempfile.TemporaryDirectory(prefix='peerwork-observation-local-') as temp:
    tmp=Path(temp)
    package=tmp/'python'/'peerwork'
    package.mkdir(parents=True)
    shutil.copyfile(ROOT/'bindings/python/peerwork/__init__.py',package/'__init__.py')
    shutil.copyfile(TARGET/'debug/lib_peerwork_native.so',package/'_peerwork_native.abi3.so')
    sys.path.insert(0,str(package.parent))
    import peerwork
    npm=tmp/'node_modules'/'@peerwork'
    wrapper=npm/'agent-sdk'; wrapper.mkdir(parents=True)
    shutil.copyfile(ROOT/'bindings/node/index.cjs',wrapper/'index.cjs')
    shutil.copyfile(ROOT/'bindings/node/package.json',wrapper/'package.json')
    native=npm/'agent-sdk-linux-x64-gnu';native.mkdir()
    shutil.copyfile(TARGET/'debug/libpeerwork_node_native.so',native/'index.node')
    (native/'package.json').write_text('{"main":"index.node"}')
    state=tmp/'observations.state'
    config={'path':str(state)}
    config_file=tmp/'config.json';config_file.write_text(json.dumps(config))
    client=peerwork.AcquisitionObservations(str(state))
    assert not state.exists(), 'constructor must remain inert'
    now=int(time.time()*1000)
    event=dict(event_id=ref('event',1),occurred_at=now,environment='local_test',
        audience_class='operator_synthetic',principal_ref=ref('principal',1),
        principal_binding=checked(1),external_status_evidence=checked(2),
        newness='unknown',newness_evidence={'status':'unknown','reference':None},
        journey_id=ref('journey',1),task_ref=ref('task',1),logical_operation_id=ref('operation',1),
        attempt_id=ref('attempt',1),event_type='qualified_start',outcome='pending',
        attempt_class='first_attempt',evidence=checked(3),observer='local-parity-fixture',observer_version='1')
    first=client.append(event)
    assert first['disposition']=='APPENDED'
    assert asyncio.run(client.append_async(event))==dict(first,disposition='DUPLICATE')
    attestation=dict(attestation_id=ref('attestation',1),principal_ref=ref('principal',1),
        binding_evidence_ref=ref('evidence',1),external_status_evidence_ref=ref('evidence',2),
        observer='local-parity-fixture',observer_version='1',
        statement='observer_checked_external_principal_binding',evidence_basis='consented_controller_grouping')
    assert client.attest_external_principal(attestation)['disposition']=='APPENDED'
    assert asyncio.run(client.attest_external_principal_async(attestation))['disposition']=='DUPLICATE'
    assert len(asyncio.run(client.attestations_async()))==1
    vector=json.loads((ROOT/'conformance/public-package-vectors.json').read_text())
    import base64
    bundle=base64.urlsafe_b64decode(vector['canonical_package_base64']+'==').decode()
    metadata=json.loads(vector['bundle']['files']['package.json'])
    release=dict(catalog_origin='https://example.com/',namespace=None,
        package_id=metadata['package_id'],version=metadata['version'],bundle_digest=vector['package_digest'])
    catalog=dict(event, event_id=ref('event',2),event_type='release_verified',outcome='pass',release=release)
    inspected=dict(catalog_origin=release['catalog_origin'],bundle_digest=release['bundle_digest'],
        bundle_canonical_json=bundle,raw_response='MUST_NOT_ENTER_LEDGER')
    assert client.record_catalog_result(catalog,inspected)['disposition']=='APPENDED'
    assert asyncio.run(client.record_catalog_result_async(catalog,inspected))['disposition']=='DUPLICATE'
    selected=dict(event,event_id=ref('event',3),event_type='adoption_selected',outcome='pass',release=release,
        protocol_digest=vector['protocol_digest'],instance_ref=ref('instance',1),adoption_branch='existing_install',association_evidence=checked(4))
    install=dict(event=selected,closure_json=json.dumps(vector['closure']),bindings_json=None,
        expected_package_id=release['package_id'],expected_package_version=release['version'],
        expected_package_digest=release['bundle_digest'],expected_protocol_digest=vector['protocol_digest'],
        selected_instance_id='z'*43,result_package_digest=None,result_protocol_digest=vector['protocol_digest'],
        result_instance_id='z'*43,result_status='ACTIVE',result_step_action_id=None,result_commit_hash=None)
    assert client.record_install_result(install)['disposition']=='APPENDED'
    assert asyncio.run(client.record_install_result_async(install))['disposition']=='DUPLICATE'
    # Shape-only SDK DTO fixture; does not assert a signed business result.
    outcome=dict(selected,event_id=ref('event',4),event_type='task_outcome_verified',
        acceptance_predicate_ref=ref('predicate',1),signed_result_evidence=checked(5))
    result=dict(status='ACCEPTED',command_id='c'*43,commit_hash='a'*64,sequence=1,
        receipt={'private':'MUST_NOT_ENTER_LEDGER'},workspace_id='MUST_NOT_ENTER_LEDGER')
    assert client.record_action_result(outcome,'z'*43,'z'*43,result)['disposition']=='APPENDED'
    assert asyncio.run(client.record_action_result_async(outcome,'z'*43,'z'*43,result))['disposition']=='DUPLICATE'
    for raw in [dict(event,raw_response='raw'),dict(event,observed_at=1)]:
        try: client.append(raw)
        except peerwork.AcquisitionObservationError as error: assert error.code=='OBSERVATION_INPUT_INVALID'
        else: raise AssertionError('raw fields accepted')
    bad=dict(install,expected_protocol_digest='f'*64)
    try: client.record_install_result(bad)
    except peerwork.AcquisitionObservationError as error: assert error.code=='OBSERVATION_INPUT_INVALID'
    else: raise AssertionError('mismatched source accepted')
    assert len(client.export())==4
    assert asyncio.run(client.export_async())==client.export()
    exported=json.dumps(client.export())
    for forbidden in ['MUST_NOT_ENTER_LEDGER','closure_json','bundle_canonical_json','receipt','workspace_id','z'*43]:
        assert forbidden not in exported
    as_of=int(time.time()*1000)
    window={'from':now-1,'to_exclusive':as_of+1,'as_of':as_of}
    score=client.scorecard(from_ms=window['from'],to_exclusive=window['to_exclusive'],as_of=as_of)
    assert score['scorecard']['excluded_synthetic_seed']==4
    assert all(metric['value'] is None for metric in score['scorecard']['metrics'])
    assert asyncio.run(client.scorecard_async(from_ms=window['from'],to_exclusive=window['to_exclusive'],as_of=as_of))==score
    assert asyncio.run(client.snapshots_async())==client.snapshots()
    (tmp/'inputs.json').write_text(json.dumps(dict(event=event,catalog=catalog,inspected=inspected,install=install,
        outcome=outcome,result=result,attestation=attestation,window=window,score=score)))
    node_script=tmp/'parity.cjs'
    node_script.write_text('''const assert=require('node:assert/strict');const fs=require('node:fs');
const sdk=require('@peerwork/agent-sdk');const i=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
(async()=>{const o=sdk.openAcquisitionObservations({path:process.argv[3]});
for(const result of [await o.append(i.event),await o.recordCatalogResult(i.catalog,i.inspected),
 await o.recordInstallResult(i.install),await o.recordActionResult(i.outcome,'z'.repeat(43),'z'.repeat(43),i.result),
 await o.attestExternalPrincipal(i.attestation)])assert.equal(result.disposition,'DUPLICATE');
assert.equal((await o.export()).length,4);assert.equal((await o.attestations()).length,1);
assert.deepEqual(await o.scorecard(i.window),i.score);assert.equal((await o.snapshots()).length,1);
let accessed=false;const accessor={};Object.defineProperty(accessor,'event_id',{enumerable:true,get(){accessed=true;throw Error('getter');}});
await assert.rejects(o.append(accessor),TypeError);assert.equal(accessed,false);
assert.equal((await o.export()).length,4);console.log('Node compiled-native local parity passed');
})().catch(()=>{process.exitCode=1;console.error('Node compiled-native local parity failed');});''')
    subprocess.run([NODE,str(node_script),str(tmp/'inputs.json'),str(state)],check=True,timeout=30)
    cli=TARGET/'debug/peerwork'
    def invoke(verb,input_value=None,expected_code=0):
        args=[str(cli),'observations',verb,str(config_file)]
        if input_value is not None:
            path=tmp/'input.json';path.write_text(json.dumps(input_value));args.append(str(path))
        completed=subprocess.run(args,check=False,capture_output=True,text=True,timeout=30)
        assert completed.returncode==expected_code
        return json.loads(completed.stdout)
    for verb,value in [('append',event),('catalog-result',dict(event=catalog,catalog_origin=release['catalog_origin'],bundle_digest=release['bundle_digest'],bundle_canonical_json=bundle)),
        ('install-result',install),('action-result',dict(event=outcome,selected_instance_id='z'*43,result_instance_id='z'*43,
        result_status='ACCEPTED',result_command_id='c'*43,result_commit_hash='a'*64,result_sequence=1)),('attest-external-principal',attestation)]:
        assert invoke(verb,value)['value']['disposition']=='DUPLICATE'
    assert invoke('export')['value']==client.export()
    assert invoke('attestations')['value']==client.attestations()
    assert invoke('scorecard',window)['value']==score
    assert invoke('snapshots')['value']==client.snapshots()
    assert invoke('append',dict(event,raw_response='raw'),1)['code']=='OBSERVATION_INPUT_INVALID'
    assert invoke('unknown',None,1)['code']=='OBSERVATION_INPUT_INVALID'
    assert len(client.export())==4
print('Python sync/async, Node and CLI compiled-native local parity passed; synthetic only, no HTTP business claim')
