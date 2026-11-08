"""Installed Python parity over synthetic protected Owner profiles only."""
import asyncio
import json
import sys
from pathlib import Path
from peerwork import SecureOwnerWorkspaceClient, PrivatePackageInstallError
mode, config, workspace, argument = sys.argv[1:]
owner = SecureOwnerWorkspaceClient(**json.loads(Path(config).read_text()))
installer = owner.private_package_installer(workspace)
if mode == 'diagnose':
    first = installer.diagnose(argument)
    second = asyncio.run(installer.diagnose_async(argument))
    assert first == second
    assert first['submitted'] is False
    print(json.dumps(first))
elif mode == 'plan':
    first = installer.recovery_plan(argument)
    second = asyncio.run(installer.recovery_plan_async(argument))
    assert first == second
    assert first['submitted'] is False
    print(json.dumps(first))
elif mode == 'recover':
    request = json.loads(Path(argument).read_text())
    first = installer.recover_invalid(request['begin_command_id'], expected_review_hash=request['expected_review_hash'], operation_id=request['operation_id'])
    second = asyncio.run(installer.recover_invalid_async(request['begin_command_id'], expected_review_hash=request['expected_review_hash'], operation_id=request['operation_id']))
    assert first['operation_id'] == second['operation_id'] == request['operation_id']
    print(json.dumps(second))
elif mode == 'mismatch':
    try:
        installer.begin_direct(**json.loads(Path(argument).read_text()))
        raise AssertionError('Old native library was not refused')
    except PrivatePackageInstallError as error:
        assert error.code == 'SDK_NATIVE_VERSION_MISMATCH'
        assert not Path(json.loads(Path(config).read_text())['state_dir']).exists()
        print(json.dumps({'code': error.code}))
else:
    raise ValueError('Unsupported synthetic acceptance operation')
