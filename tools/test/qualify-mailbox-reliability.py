#!/usr/bin/env python3
"""Reproducible synthetic HTTP/SSE recovery qualification; no live profiles.

Run in the designated local TEST environment with an isolated PostgreSQL
endpoint, compiled product root and Node fixture executable already selected.
No production diagnostics, host-session discovery or model calls occur here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args()
    for name in ['PEERWORK_POSTGRES_TEST_URL','PEERWORK_STRUCTURE_REFERENCE_ROOT','PEERWORK_TEST_NODE']:
        if not os.environ.get(name):parser.error(name+' must explicitly select synthetic TEST dependencies')
    if urlsplit(os.environ['PEERWORK_POSTGRES_TEST_URL']).hostname not in ['localhost','127.0.0.1','::1']:
        parser.error('synthetic PostgreSQL must use an explicitly selected loopback TEST endpoint')
    root=Path(__file__).resolve().parents[2]
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    groups=[('peerwork-core',['--test','native_mail'],None),
            ('peerwork-runtime',['--lib'],'reliability'),
            ('peerwork-runtime',['--lib'],'kernel_access::public_error_tests'),
            ('peerwork-runtime',['--lib'],'fresh_member_read_http400_has_no_saved_intent_and_corrected_read_succeeds'),
            ('peerwork-runtime',['--lib'],'automatic_native_program_watch_spools_offline_consumes_and_reconnects'),
            ('peerwork-runtime',['--lib'],'runtime_host_dispatch_persists_unknown_and_blocks_only_same_conversation_across_restart'),
            ('peerwork-runtime',['--lib'],'native_bridge_receives_genuine_verified_e2ee_mail_from_shared_runtime')]
    files=['crates/core/src/communication.rs','crates/core/tests/native_mail.rs','crates/runtime/src/participant_watch.rs','crates/runtime/src/participant_inbox.rs','crates/runtime/src/participant.rs','crates/runtime/src/kernel_access.rs','crates/runtime/src/structure_intent.rs','crates/runtime/src/participant_reliability_http_tests.rs','tests/participant-service.mjs']
    product=Path(os.environ['PEERWORK_STRUCTURE_REFERENCE_ROOT'])
    service_files=[p for directory in ['src','dist-workspace/src'] for p in sorted((product/directory).rglob('*')) if p.is_file()]
    service_files += [product/'package.json',product/'package-lock.json',product/'dist-workspace/tests/fixtures/workspace-postgres-fixture.js']
    service_inputs={str(p.relative_to(product)):hashlib.sha256(p.read_bytes()).hexdigest() for p in service_files}
    environment=dict(os.environ)
    manifest=args.output/'service-manifest.json'
    manifest.write_text(json.dumps({'format':'peerwork.structure-candidate.v1','files':{name:digest for name,digest in service_inputs.items() if name!='dist-workspace/tests/fixtures/workspace-postgres-fixture.js'}}))
    environment['PEERWORK_STRUCTURE_REFERENCE_MANIFEST']=str(manifest.resolve())
    report={'format':'peerwork.mailbox-reliability-qualification.v1','scope':'SYNTHETIC_LOCAL_TEST','production_touched':False,'model_response':'NOT_QUALIFIED_BY_PROGRAM_FIXTURES','source_files':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files},'service_inputs_sha256':hashlib.sha256(json.dumps(service_inputs,sort_keys=True).encode()).hexdigest(),'checks':[],'state':'RUNNING'}
    for index,(package,selection,group) in enumerate(groups):
        command=['cargo','test','--locked']+(['--offline'] if args.offline else [])+['-p',package]+selection+([group] if group else [])+['--','--include-ignored','--test-threads=1']
        started=time.monotonic();log=args.output/(str(index)+'.log')
        try:
            with log.open('w') as stream:r=subprocess.run(command,cwd=root,env=environment,stdout=stream,stderr=stream,timeout=600)
            code=r.returncode
        except subprocess.TimeoutExpired:code=124
        text=log.read_text(errors='replace')
        matches=re.findall(r'test result: ok\. ([0-9]+) passed;',text)
        passed=sum(map(int,matches))
        report['checks'].append({'group':group or package+'::native_mail','exit':code,'passed':passed,'elapsed_seconds':round(time.monotonic()-started,3),'log':log.name})
        report['state']='FAILED' if code or not passed else 'RUNNING'
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report['checks'][-1]),flush=True)
        if report['state']=='FAILED':return 1
    report['state']='PASS'
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0

if __name__=='__main__':raise SystemExit(main())
