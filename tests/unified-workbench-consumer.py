"""Installed wheel parity consumer. All fixtures are synthetic and local."""
import json
import sys
from pathlib import Path
import peerwork

request = json.loads(Path(sys.argv[1]).read_text())
mode = request.pop('mode', 'offline')
if mode == 'offline':
    fixture = peerwork.build_protocol_fixture(request['protocols'], seed=request['seed'], time_ms=request['time_ms'])
    result = peerwork.simulate_protocol(fixture, request['steps'], seed=request['seed'])
    plan = peerwork.plan_protocol_actions(fixture, request['steps'], seed=request['seed'])
    print(json.dumps({'fixture': fixture, 'result': result, 'plan': plan}, ensure_ascii=True))
elif mode == 'export':
    print(json.dumps(peerwork.export_protocol_fixture(request['profile'], request['instance_ids'], time_ms=request['time_ms'], cached=request.get('cached', False))))
elif mode == 'resume':
    print(json.dumps(peerwork.resume_protocol_plan(request['profile'], request['operation_id'])))
else:
    raise ValueError('unknown consumer mode')
