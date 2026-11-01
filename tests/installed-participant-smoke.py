#!/usr/bin/env python3
"""Installed native process/ownership smoke. Python is a CI driver, not a client dependency.

Creates only synthetic local state. Does not open user profiles or a service;
local readiness is not host/model or network readiness.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


def protect(path):
    if os.name == 'nt':
        script = '''
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm("O:${sid}D:P(A;OICI;FA;;;$sid)")
Set-Acl -LiteralPath $env:PEERWORK_SMOKE_ROOT -AclObject $acl -ErrorAction Stop
'''
        subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                       env={**os.environ, 'PEERWORK_SMOKE_ROOT': str(path)}, check=True, timeout=20)
    else:
        path.chmod(0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    args = parser.parse_args()
    cli = args.cli.absolute()
    assert cli.is_file(), 'installed native executable missing'
    with tempfile.TemporaryDirectory(prefix='peerwork installed Ω ') as temp:
        # macOS temporary roots may use /var -> /private/var. Provision the
        # synthetic state under its canonical path, as the native contract
        # requires; do not weaken production symlink rejection.
        root = Path(temp).resolve(strict=True)
        protect(root)
        children = []

        def write(name, value):
            path = root / name
            with path.open('x', encoding='utf-8') as stream:
                if os.name != 'nt':
                    os.fchmod(stream.fileno(), 0o600)
                json.dump(value, stream)
            return str(path)

        def run(*words, success=True):
            result = subprocess.run([str(cli), *map(str, words)], cwd=root,
                                    capture_output=True, text=True, encoding='utf-8', timeout=20)
            assert (result.returncode == 0) == success, 'unexpected native exit status'
            return json.loads(result.stdout)

        # Interface maturity is a property of these bytes. Publication and
        # remote/host readiness cannot be inferred from a compiled help string.
        for words in [('agent', '--help'), ('agent', 'tools'), ('runtime', '--help'),
                      ('bridge', '--help')]:
            description = run(*words)
            assert description['maturity'] == 'EXPERIMENTAL'
            assert 'availability' not in description

        assert run('connect','--help')['state']=='HELP'
        local=root/'unconfigured participant'
        context=run('connect','--local',local,'--context')
        assert context['state']=='NOT_CONFIGURED' and context['participants']==[]
        assert context['remote_or_host_readiness']=='NOT_ATTESTED'
        # Exercise the installed OS process before any profile, actor or service
        # exists. Discovery must not require an administrator-made profile or
        # accidentally expose signing/business tools to an unselected identity.
        mcp=subprocess.Popen([str(cli),'agent','--local',str(local),'mcp'],cwd=root,
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             text=True,encoding='utf-8')
        frames=queue.Queue()
        def read_mcp():
            for line in mcp.stdout:
                try:frames.put(json.loads(line))
                except ValueError:frames.put({'invalid_frame':True})
        threading.Thread(target=read_mcp,daemon=True).start()
        def rpc(identifier,method,params):
            mcp.stdin.write(json.dumps({'jsonrpc':'2.0','id':identifier,'method':method,'params':params})+'\n');mcp.stdin.flush()
            value=frames.get(timeout=20)
            assert value.get('id')==identifier and 'error' not in value,value
            return value['result']
        try:
            rpc(1,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'native-installed-onboarding','version':'1'}})
            mcp.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');mcp.stdin.flush()
            tools=rpc(2,'tools/list',{})['tools']
            assert {tool['name'] for tool in tools}=={'peerwork_context','peerwork_connect'}
            value=rpc(3,'tools/call',{'name':'peerwork_context','arguments':{}})
            assert value['structuredContent']['state']=='NOT_CONFIGURED'
            assert value['structuredContent']['participants']==[]
        finally:
            mcp.stdin.close()
            try:mcp.wait(timeout=20)
            except subprocess.TimeoutExpired:mcp.kill();mcp.wait(timeout=10);raise
        assert mcp.returncode==0,'unconfigured MCP process did not close cleanly'
        assert run('agent','--local',local,'context')['state']=='NOT_CONFIGURED'

        identity = root / 'synthetic identity.state'
        created = run('identity', 'create', identity)
        assert set(created) == {'actor_id', 'key_id'}, 'identity exposed unexpected fields'
        assert run('identity', 'info', identity) == created, 'identity reopen mismatch'
        config = write('runtime.json', {
            'format': 'peerwork.participant-runtime.v1', 'state_directory': str(root / 'runtime'),
            'engines': [{'name': 'one', 'origin': 'http://127.0.0.1:1',
                         'expected_actor': created['actor_id'], 'identity_path': str(identity),
                         'state_directory': str(root / 'engine'), 'allow_loopback_http': True,
                         'max_inflight': 1, 'max_pending': 2}],
            'clients': [{'name': 'reader', 'engine': 'one', 'capability': {
                'operations': ['structure.workspace.get'], 'allow_root': False,
                'workspace_ids': ['synthetic'], 'instance_ids': None,
                'protocol_digests': None, 'business_actions': None}}], 'hosts': [],
        })
        capability_request = write('capabilities.json', {'method': 'capabilities'})
        stopped = []

        def start():
            process = subprocess.Popen([str(cli), 'runtime', 'run', config], cwd=root,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding='utf-8')
            children.append(process)
            observed = queue.Queue(maxsize=1)
            threading.Thread(target=lambda: observed.put(process.stdout.readline()), daemon=True).start()
            ready = json.loads(observed.get(timeout=20))
            assert ready['state'] == 'LOCAL_READY', 'native process did not own the local runtime'
            return process, ready

        try:
            process, ready = start()
            endpoint = ready['client_endpoints']['reader']
            capability = run('runtime', 'call', endpoint, capability_request)
            assert capability['ok'] and capability['value']['actor_id'] == created['actor_id']
            assert capability['value']['admin'] is False, 'client gained admin capability'
            assert capability['value']['maturity'] == 'EXPERIMENTAL'
            assert 'availability' not in capability['value']
            denied = run('runtime', 'admin', endpoint, 'stop', success=False)
            assert denied.get('ok') is False and process.poll() is None, 'client stopped the runtime'
            competing = run('runtime', 'run', config, success=False)
            assert competing['error']['code'] == 'RUNTIME_ALREADY_OWNED', 'second owner was admitted'
            # Kill only this captured child; wait for its terminal result before restart.
            process.kill()
            process.wait(timeout=20)
            stopped.append(process.returncode)
            process, ready = start()
            assert run('identity', 'info', identity) == created, 'restart replaced the identity'
            capability = run('runtime', 'call', ready['client_endpoints']['reader'], capability_request)
            assert capability['ok'] and capability['value']['actor_id'] == created['actor_id']
            result = run('runtime', 'admin', ready['admin_endpoint'], 'stop')
            assert result['ok'] and result['value']['state'] == 'STOPPING'
            process.communicate(timeout=20)
            assert process.returncode == 0, 'native shutdown failed'
            stopped.append(process.returncode)
        finally:
            for process in children:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=20)
        print(json.dumps({'state': 'PASS', 'scope': 'installed native local process, synthetic identity only',
                          'checks': ['protected Unicode path', 'unconfigured connect discovery', 'unconfigured installed MCP catalog/context', 'identity reopen', 'scoped encrypted IPC',
                                     'admin denial', 'single owner', 'kill/restart', 'graceful shutdown'],
                          'children_terminal': len(stopped), 'service_or_model': 'NOT_EXERCISED'}))


if __name__ == '__main__':
    main()
