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
elif mode == 'async-guard':
    import asyncio
    async def check():
        client = peerwork.SecureOwnerWorkspaceClient(**request['owner_config']).guard_time(request['workspace_id'])
        try:
            await client.enable_async(**request['enable'])
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == 'PRODUCER_UNSUPPORTED', error
        else:
            raise AssertionError('unknown producer was accepted')
        assert await client.history_async() == []
        try:
            await client.resume_async('m' * 43)
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == 'GUARD_TIME_OPERATION_NOT_FOUND', error
        else:
            raise AssertionError('missing operation was accepted')
        return {'status': 'PASS', 'native_async_guard_calls': 3}
    print(json.dumps(asyncio.run(check())))
elif mode == 'resume':
    print(json.dumps(peerwork.resume_protocol_plan(request['profile'], request['operation_id'])))
else:
    raise ValueError('unknown consumer mode')
