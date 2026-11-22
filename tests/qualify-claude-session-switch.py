"""Exercise native SessionEnd and MCP lifecycle in a real Claude TUI on loopback."""
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid


class TranscriptModel(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_error(404)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['content-length'])))
        if '/count_tokens' in self.path:
            return self.send_body(b'{"input_tokens":10}', 'application/json')
        if not self.path.startswith('/v1/messages'):
            return self.send_error(404)
        identity = 'msg_' + uuid.uuid4().hex
        result = {'id': identity, 'type': 'message', 'role': 'assistant',
                  'model': request['model'], 'stop_reason': 'end_turn',
                  'stop_sequence': None, 'content': [{'type': 'text', 'text': 'Fixture reply.'}],
                  'usage': {'input_tokens': 10, 'output_tokens': 3}}
        if not request.get('stream'):
            return self.send_body(json.dumps(result).encode(), 'application/json')
        events = [
            {'type': 'message_start', 'message': {**result, 'content': [], 'stop_reason': None}},
            {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}},
            {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'Fixture reply.'}},
            {'type': 'content_block_stop', 'index': 0},
            {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None},
             'usage': {'output_tokens': 3}},
            {'type': 'message_stop'},
        ]
        body = ''.join(f"event: {item['type']}\ndata: {json.dumps(item)}\n\n" for item in events)
        self.send_body(body.encode(), 'text/event-stream')

    def send_body(self, body, content_type):
        self.send_response(200)
        self.send_header('content-type', content_type)
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def json_lines(path):
    if not path.is_file():
        return []
    return [json.loads(row) for row in path.read_text().splitlines() if row.endswith('}')]


def screen(data):
    return b' '.join(re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b' ', bytes(data)).lower().split())


def terminal_process(command, root, env):
    primary, terminal = pty.openpty()
    try:
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack('HHHH', 48, 160, 0, 0))
        host = subprocess.Popen(command, cwd=root, env=env,
                                stdin=terminal, stdout=terminal, stderr=terminal,
                                start_new_session=True, preexec_fn=lambda:fcntl.ioctl(0,termios.TIOCSCTTY,0))
    finally:
        os.close(terminal)
    return primary, host


def stop_terminal(host, primary):
    if host.poll() is None:
        os.killpg(host.pid,signal.SIGTERM)
        try:
            host.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(host.pid,signal.SIGKILL)
            host.wait(timeout=2)
    os.close(primary)


def seed_interactive(claude, destination, root, config, env):
    primary, host = terminal_process([str(claude), '--session-id', destination, '--model',
         'claude-sonnet-4-6', '--permission-mode', 'default'], root, env)
    seen = bytearray()
    key = sent = renamed = quit_sent = False
    settled_at = 0
    try:
        until = time.monotonic()+20
        while time.monotonic()<until and host.poll() is None:
            if select.select([primary],[],[],0.2)[0]:
                try:
                    seen.extend(os.read(primary,32768))
                except OSError:
                    break
            current = screen(seen)
            if not key and b'detected a custom api key' in current:
                os.write(primary,b'\x1b[A\r')
                key = True
            if not sent and b'for agents' in current:
                os.write(primary,b'Destination fixture transcript.\r')
                sent = True
            if not renamed and b'fixture reply.' in current:
                os.write(primary,b'/rename Destination fixture\r')
                renamed = True
                settled_at = time.monotonic()+1
            if not quit_sent and renamed and time.monotonic()>settled_at:
                os.write(primary,b'/exit\r')
                quit_sent = True
        assert sent and renamed and quit_sent, current[-1300:]
        saved = list(config.rglob(f'{destination}.jsonl'))
        assert saved and 'Destination fixture transcript.' in saved[0].read_text()
    finally:
        stop_terminal(host,primary)


def executable(path, body):
    path.write_text(f'#!{sys.executable}\n' + body)
    path.chmod(0o700)
    return path


cli = Path(sys.argv[1]).resolve(strict=True)
claude = Path(sys.argv[2]).resolve(strict=True)
require_hooks = '--disable-hooks' not in sys.argv[3:]
with tempfile.TemporaryDirectory(prefix='peerwork-claude-switch-') as temporary:
    root = Path(temporary)
    config = root / 'config'
    config.mkdir(mode=0o700)
    (config / '.claude.json').write_text(json.dumps({
        'hasCompletedOnboarding': True, 'theme': 'dark',
        'projects': {str(root): {'hasTrustDialogAccepted': True}},
    }))
    original, destination = str(uuid.uuid4()), str(uuid.uuid4())
    server = 'peerwork-0123456789abcdef'
    model = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TranscriptModel)
    threading.Thread(target=model.serve_forever, daemon=True).start()
    env = {
        'PATH': str(root) + os.pathsep + os.environ['PATH'],
        'HOME': str(root), 'CLAUDE_CONFIG_DIR': str(config), 'TERM': 'xterm-256color',
        'DISABLE_AUTOUPDATER': '1', 'DISABLE_TELEMETRY': '1',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1',
        'ANTHROPIC_BASE_URL': f'http://127.0.0.1:{model.server_port}',
        'ANTHROPIC_API_KEY': 'sk-ant-api03-synthetic-peerwork-loopback-only',
        'PW_PROBE_HOME': str(root), 'PW_PROBE_CLAUDE': str(claude),
    }
    for name, session in [('Original', original)]:
        seeded = subprocess.run(
            [str(claude), '--print', '--output-format', 'json', '--tools', '',
             '--model', 'claude-sonnet-4-6', '--session-id', session, f'{name} fixture transcript.'],
            env=env, cwd=root, capture_output=True, text=True, timeout=25)
        assert seeded.returncode == 0, (seeded.stdout[-1000:], seeded.stderr[-1000:])
        assert json.loads(seeded.stdout)['session_id'] == session
        assert list(config.rglob(f'{session}.jsonl')), 'real host did not save transcript'

    seed_interactive(claude,destination,root,config,env)

    executable(root/'claude', """
import os, sys
from pathlib import Path
root = Path(os.environ['PW_PROBE_HOME'])
(root/'launch.json').write_text(os.environ['PEERWORK_CLAUDE_CHANNEL_LAUNCH'])
real = os.environ['PW_PROBE_CLAUDE']
os.execv(real, [real, *sys.argv[1:], '--debug-file', str(root/'claude.log'),
                '--model', 'claude-sonnet-4-6', '--permission-mode', 'default'])
""")
    event_hook = executable(root/'observe-hook', """
import json, os, sys, time
from pathlib import Path
item = json.load(sys.stdin)
record = {'event':item['hook_event_name'], 'id':item['session_id'],
          'reported_session':os.environ.get('CLAUDE_CODE_SESSION_ID'), 'reason':item.get('reason'), 'at':time.monotonic_ns()}
with (Path(os.environ['PW_PROBE_HOME'])/'events.jsonl').open('a') as out:
    out.write(json.dumps(record)+'\\n')
""")
    settings = {'hooks': {event:[{'hooks':[{'type':'command', 'command':shlex.quote(str(event_hook))}]}]
                          for event in ('SessionStart', 'SessionEnd')}}
    if not require_hooks:
        settings['disableAllHooks'] = True
    (config/'settings.json').write_text(json.dumps(settings))
    mcp = executable(root/'trace-peerwork', """
import hashlib, json, os, sys, time
from pathlib import Path
root = Path(os.environ['PW_PROBE_HOME'])
launch = os.environ.get('PEERWORK_CLAUDE_CHANNEL_LAUNCH','')
with (root/'children.jsonl').open('a') as out:
    out.write(json.dumps({'pid':os.getpid(), 'session':os.environ.get('CLAUDE_CODE_SESSION_ID'),
                          'at':time.monotonic_ns(), 'launch':hashlib.sha256(launch.encode()).hexdigest() if launch else None})+'\\n')
sdk = sys.argv[1]
fd = os.open(root/'mcp-child-stderr.log', os.O_WRONLY|os.O_CREAT|os.O_APPEND, 0o600)
os.dup2(fd, 2)
os.close(fd)
os.execv(sdk, [sdk, *sys.argv[2:]])
""")
    profile = root/'profile.json'
    profile.write_text(json.dumps({'format':'peerwork.agent-profile.v1',
                                   'endpoint_path':str(root/'unused-synthetic-endpoint.json'),
                                   'expected_origin':'https://example.invalid', 'expected_actor':'A'*43,
                                   'scopes':{}}))
    profile.chmod(0o600)
    registered = subprocess.run([str(claude), 'mcp', 'add', '--scope', 'local', '--transport', 'stdio',
                                 server, '--', str(mcp), str(cli), 'agent', '--profile', str(profile),
                                 'mcp', '--claude-channel'],
                                env=env, cwd=root, capture_output=True, text=True, timeout=15)
    assert registered.returncode == 0, registered.stderr

    primary, host = terminal_process(
        [str(cli),'agent','claude-start',server,'--resume',original,'--select-session'],root,env)
    listener = None
    seen = bytearray()
    accepted_key = accepted_channel = sent_resume = fence_signal = False
    children_before = []
    resume_choice_sent = False
    mcp_opened = mcp_submenu = mcp_reload = False
    settled_deadline = None
    first_mcp_live = False
    normalized = b''
    try:
        deadline = time.monotonic()+30
        while time.monotonic()<deadline and host.poll() is None:
            marker = root/'launch.json'
            if listener is None and marker.is_file() and marker.stat().st_size:
                launch = json.loads(marker.read_text())
                key = hashlib.sha256(f"{launch['server']}:{launch['order']['nonce']}".encode()).hexdigest()
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(f'\0peerwork-claude-{key}')
                listener.listen(1)
            watched = [primary] + ([listener] if listener is not None else [])
            ready = select.select(watched, [], [], 0.2)[0]
            if listener in ready:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(1.0)
                    assert connection.recv(1)==b'\x01'
                    connection.sendall(b'\x01')
                fence_signal = sent_resume
            if primary in ready:
                try:
                    seen.extend(os.read(primary, 32768))
                except OSError:
                    break
            normalized = screen(seen)
            if not accepted_key and b'detected a custom api key' in normalized:
                os.write(primary,b'\x1b[A\r')
                accepted_key=True
                continue
            if not accepted_channel and b'i am using this for local development' in normalized:
                os.write(primary,b'\r')
                accepted_channel=True
                continue
            events = json_lines(root/'events.jsonl')
            children = json_lines(root/'children.jsonl')
            ran_start = any(row['event']=='SessionStart' and row['id']==original for row in events)
            initial_visible = b'original fixture transcript.' in normalized and b'for agents' in normalized
            if not sent_resume and listener is not None and children and initial_visible and (ran_start or not require_hooks):
                children_before = children
                os.write(primary, b'/resume\r')
                sent_resume = True
            if sent_resume and not resume_choice_sent and b'destination fixture' in normalized and b'resume' in normalized:
                os.write(primary,b'\r')
                resume_choice_sent = True
            new_start = any(row['event']=='SessionStart' and row['id']==destination for row in events)
            switched = (fence_signal and new_start) if require_hooks else (
                resume_choice_sent and b'session renamed to: destination fixture' in normalized)
            if switched and not mcp_opened:
                first_mcp_live = any(Path(f"/proc/{row['pid']}").exists() for row in children_before)
                os.write(primary,b'/mcp\r')
                mcp_opened = True
                settled_deadline = time.monotonic()+8
            recent = normalized[-2100:]
            if mcp_opened and not mcp_submenu and b'manage mcp servers' in recent and server.encode() in recent:
                os.write(primary,b'\r')
                mcp_submenu = True
            if mcp_submenu and not mcp_reload and b'reconnect' in recent:
                # The default item is Reconnect in a failed server, View tools
                # in an active server. Use the visible selection.
                if b'view tools' in recent:
                    os.write(primary,b'\x1b[B')
                os.write(primary,b'\r')
                mcp_reload = True
            if (mcp_reload and len(children)>len(children_before)) or (settled_deadline and time.monotonic()>settled_deadline):
                break
        events = json_lines(root/'events.jsonl')
        children = json_lines(root/'children.jsonl')
        ended = [row for row in events if row['event']=='SessionEnd' and row['reason']=='resume']
        switched = any(row['event']=='SessionStart' and row['id']==destination for row in events)
        original_child_survived = any(c['session']==original and Path(f"/proc/{c['pid']}").exists() for c in children_before)
        updated_child = any(row['session']==destination for row in children[len(children_before):])
        launch_digest = hashlib.sha256((root/'launch.json').read_bytes()).hexdigest()
        old_launch_retained = any(row['session']==destination and row.get('launch')==launch_digest
                                  for row in children[len(children_before):])
        end_matches = len(ended)==1 and ended[0]['id']==original
        hook_gate = fence_signal and switched and end_matches if require_hooks else not fence_signal and not events
        state = 'PASS' if hook_gate and updated_child and old_launch_retained and host.poll() is None else 'INCONCLUSIVE'
        summary = {'state':state,'real_original_host_stayed_live':host.poll() is None,
                   'resume_sent':sent_resume,'old_session_end_matches_launch':bool(ended and ended[0]['id']==original),
                   'native_end_signal':fence_signal,'new_session_start_observed':switched,
                   'original_mcp_child_survived':original_child_survived,'mcp_spawn_count':len(children),
                   'before_switch_mcp_children':len(children_before),'loopback_transcript_model':True,
                   'authenticated_channel_wake':False,'binary_sha256':hashlib.sha256(cli.read_bytes()).hexdigest()}
        summary.update({'original_child_live_after_switch':first_mcp_live, 'mcp_menu_opened':mcp_opened,
                        'mcp_reload_requested':mcp_reload, 'mcp_spawn_after_switch':len(children)>len(children_before),
                        'mcp_after_switch_uses_new_id':updated_child, 'mcp_after_switch_keeps_original_launch':old_launch_retained,
                        'hooks_disabled_in_fixture':not require_hooks,
                        'first_mcp_uses_original_id':any(row['session']==original for row in children_before),
                        'channels_reported_unavailable':b'channels are not currently available' in normalized})
        starts=[row['at'] for row in events if row['event']=='SessionStart' and row['id']==original]
        summary['first_session_start_preceded_child']=bool(starts and children_before and starts[0]<children_before[0]['at'])
        print(json.dumps(summary),flush=True)
        if not first_mcp_live:
            trace = root/'claude.log'
            lines = trace.read_text(errors='replace').splitlines() if trace.is_file() else []
            relevant = [line for line in lines if server in line and any(word in line.lower()
                        for word in ('failed','error','success','connected','disconnect','exit','stderr','ready'))]
            child_error = root/'mcp-child-stderr.log'
            print(json.dumps({'mcp_host_lines':relevant[-8:], 'mcp_child_stderr':child_error.read_text(errors='replace')[-400:] if child_error.is_file() else ''}))
        if not mcp_reload or not summary['mcp_spawn_after_switch']:
            print(json.dumps({'mcp_ui_tail':normalized[-1750:].decode(errors='replace')}),flush=True)
        if state!='PASS':
            print(json.dumps({'terminal':normalized[-2700:].decode(errors='replace'),
                              'events':[{'event':r['event'],'reason':r['reason'],
                                         'original':r['id']==original,'destination':r['id']==destination} for r in events],
                              'mcp_children':[{'original':row['session']==original, 'destination':row['session']==destination, 'session_observed':bool(row['session']), 'live':Path(f"/proc/{row['pid']}").exists()} for row in children]}),flush=True)
            sys.exit(1)
    finally:
        if listener is not None:
            listener.close()
        stop_terminal(host,primary)
        model.shutdown()
        model.server_close()
