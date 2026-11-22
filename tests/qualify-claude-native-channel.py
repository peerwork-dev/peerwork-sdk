"""Exercise the installed Claude entry in an isolated interactive host fixture."""
import fcntl
import json
import os
from pathlib import Path
import pty
import shlex
import signal
import subprocess
import time
import sys
import termios
from collections import deque

def host(args):
    session, channel, order, outcome = args
    server = channel.removeprefix('server:')
    env = dict(os.environ, CLAUDE_CODE_SESSION_ID=session)
    entry = json.loads(Path('.mcp.json').read_text())['mcpServers'][server]
    settings = json.loads(Path('.claude/settings.local.json').read_text())
    def hook(event):
        command = next(
            handler['command'] for group in settings['hooks'][event]
            for handler in group['hooks'] if handler['command'].endswith(' ' + server)
        )
        result = subprocess.run(shlex.split(command), input=json.dumps({
            'hook_event_name':event, 'session_id':session,
            'source':'resume' if order == 'after' else 'startup',
        }), text=True, capture_output=True, env=env, timeout=3)
        assert result.returncode == 0, result.stdout
    if outcome != 'inbox' and order == 'before':
        hook('SessionStart')
    requests = 0
    pending = deque()
    with subprocess.Popen([entry['command'], *entry['args']], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env) as mcp:
        def write(message):
            mcp.stdin.write(json.dumps(dict(message,jsonrpc='2.0'))+'\n')
            mcp.stdin.flush()
        def read():
            line=mcp.stdout.readline()
            assert line, 'SDK stopped responding'
            return json.loads(line)
        def request(method, args):
            nonlocal requests
            requests+=1
            write({'id':requests,'method':method,'params':args})
            while True:
                value=read()
                if value.get('id') == requests:
                    return value['result']
                assert value['method'] == 'notifications/claude/channel'
                pending.append(value)
        def tool(name,args):
            return request('tools/call',{'name':name,'arguments':args})['structuredContent']
        def notification():
            value=pending.popleft() if pending else read()
            assert value['method'] == 'notifications/claude/channel', value
            return value['params']['meta']
        try:
            request('initialize', {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'native-claude-fixture','version':'1'}})
            write({'method':'notifications/initialized'})
            request('tools/list', {})
            expected = 'CLAUDE_CHANNEL_LAUNCH_REQUIRED' if outcome == 'inbox' else 'CLAUDE_CHANNEL_LIFECYCLE_UNCONFIRMED'
            if outcome == 'inbox' or order == 'after':
                assert tool('peerwork_context',{})['host_channel']['validation_error']==expected
                denied=tool('peerwork_delivery',{'mode': 'self_test', 'scope': 'one'})
                assert denied['error']['code']==expected, denied
                assert denied['error']['effect_certainty']=='NOT_SUBMITTED', denied
                assert not pending
            if outcome == 'inbox':
                return
            if order == 'after': hook('SessionStart')
            startup=notification()
            assert startup['kind']=='activation'
            assert tool('peerwork_inbox',{'batch':startup['batch']})['state']=='CLAUDE_CHANNEL_CONFIRMED'
            if outcome == 'mismatch':
                for _ in range(45):
                    scopes=tool('peerwork_context',{})['host_channel']['scopes']
                    if any(scope.get('code')=='CLAUDE_CHANNEL_SESSION_MISMATCH' for scope in scopes.values()):
                        break
                    time.sleep(.2)
                else:
                    raise AssertionError(scopes)
            else:
                accepted=tool('peerwork_delivery',{'mode': 'self_test', 'scope': 'one'})
                assert not accepted.get('error'), accepted
                notice=notification()
                assert tool('peerwork_inbox',{'batch':notice['batch']})['state']=='SELF_TEST_OBSERVED'
            hook('SessionEnd')
            assert tool('peerwork_context',{})['host_channel']['validation_error']=='CLAUDE_CHANNEL_SESSION_ENDED'
        finally:
            mcp.stdin.close()
            mcp.wait(timeout=8)

def run(server, session):
    for outcome, order, selected in (
        ('inbox','before',session),('attached','before',session),('attached','after',session),
        ('mismatch','before','1dd1d4f6-b535-44e6-aeb6-624856bddf1b'),
    ):
        master, slave=pty.openpty()
        def terminal():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        flag='--dangerously-load-development-channels' if outcome!='inbox' else '--fixture-inbox-only'
        # argv[0] stands in for the installed native Claude executable.
        child=subprocess.Popen(
            ['claude', __file__, 'host', '--session-id', selected, flag, 'server:'+server, order, outcome],
            executable=sys.executable, stdin=slave, start_new_session=True, preexec_fn=terminal)
        os.close(slave)
        try:
            assert child.wait(timeout=45)==0, outcome
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            os.close(master)
    print(json.dumps({'state':'PASS','direct_launch_first_binding':True,'same_session_restart':True,
        'different_session_rejected':True,'tools_only_declines_self_test':True,'late_hook':True}))

if sys.argv[1] == 'host':
    host([sys.argv[3], *sys.argv[5:]])
else:
    run(*sys.argv[1:])
