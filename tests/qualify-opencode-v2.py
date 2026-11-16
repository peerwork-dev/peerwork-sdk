#!/usr/bin/env python3
"""Qualify real OpenCode V2, native MCP and E2EE with a deterministic local model.

Maintainer fixture only: no paid model, existing identity or user session. A real
V2 process executes the tools; the local model selects only the test inbox,
reply and consume calls. This establishes interoperability, not model quality
or a production response-time SLA. PostgreSQL must be isolated test data.
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time
import urllib.request


def atomic(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.chmod(0o600)
    temp.replace(path)


def wait_for(predicate, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.05)
    raise TimeoutError('FIXTURE_OBSERVATION_BUDGET_EXCEEDED')


class Model(ThreadingHTTPServer):
    def __init__(self, output):
        self.output, self.requests, self.calls = output, 0, []
        self.items = {}
        super().__init__(('127.0.0.1', 0), Completion)

    def complete(self, request):
        self.requests += 1
        assert self.requests <= 48, 'BOUNDED_MODEL_REQUESTS_EXCEEDED'
        atomic(self.output / ('model-request-%02d.json' % self.requests), request)
        messages = request['messages']
        tools = {t['function']['name']: t['function'] for t in request.get('tools', [])}
        user = max(i for i, m in enumerate(messages) if m['role'] == 'user')
        current = messages[user:]
        text = current[0]['content']
        if isinstance(text, list):
            text = ' '.join(p.get('text', '') for p in text)
        match = re.search(r'\{"batch":"([A-Za-z0-9_-]{43})"\}', text)
        if not match:
            return None, 'Synthetic qualification: no notification.'
        batch = match[1]
        results = [m for m in current if m['role'] == 'tool']
        if not results:
            name, arguments = 'peerwork_inbox', {'batch': batch}
        else:
            calls = {c['id']: c['function']['name'] for m in current for c in m.get('tool_calls', [])}
            last = results[-1]
            called = calls[last['tool_call_id']]
            if called.endswith('peerwork_inbox'):
                content = last['content']
                if isinstance(content, list):
                    content = '\n'.join(v.get('text', '') for v in content)
                page = json.loads(content)
                if 'content' in page:
                    page = json.loads(next(v['text'] for v in page['content'] if v['type'] == 'text'))
                items = [v for v in page.get('items', []) if v.get('message', {}).get('text', '').startswith('PING ')]
                if not items:
                    return None, 'Synthetic qualification: notification observed.'
                assert len(items) == 1, 'EXPECTED_ONE_SYNTHETIC_PING'
                item = self.items[batch] = items[0]
                nonce = item['message']['text'].split()[1].rstrip('.')
                name = 'peerwork_reply'
                arguments = dict(item['reply']['arguments'], operation_id='v2-pong-' + str(item['item']['sequence']), text='PONG ' + nonce)
            elif called.endswith('peerwork_reply'):
                name = 'peerwork_consume'
                arguments = self.items[batch]['consume']['arguments']
            else:
                assert called.endswith('peerwork_consume'), called
                return None, 'Synthetic qualification: reply and consume completed.'
        selected = [key for key in tools if key.endswith(name)]
        assert len(selected) == 1, {'missing_tool': name, 'available': list(tools)}
        self.calls.append({'tool': name, 'arguments': arguments})
        atomic(self.output / 'model-calls.json', self.calls)
        return {'index': 0, 'id': 'call_%d' % self.requests, 'type': 'function',
                'function': {'name': selected[0], 'arguments': json.dumps(arguments)}}, None


class Completion(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert self.path == '/v1/chat/completions', self.path
            call, text = self.server.complete(request)
            delta = {'role': 'assistant'}
            delta.update({'tool_calls': [call]} if call else {'content': text})
            chunk = {'id': 'chatcmpl-fixture', 'object': 'chat.completion.chunk', 'created': int(time.time()),
                     'model': 'fixture', 'choices': [{'index': 0, 'delta': delta, 'finish_reason': None}]}
            end = dict(chunk, choices=[{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls' if call else 'stop'}],
                       usage={'prompt_tokens': 10, 'completion_tokens': 10, 'total_tokens': 20})
            body = ('data: ' + json.dumps(chunk) + '\n\ndata: ' + json.dumps(end) + '\n\ndata: [DONE]\n\n').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as error:
            atomic(self.server.output / 'model-error.json', {'error': repr(error)})
            self.send_error(500, 'SYNTHETIC_MODEL_FIXTURE_ERROR')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('opencode', 'test-binary', 'cli', 'sdk', 'product', 'node', 'postgres', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    project = root / 'project'
    (project / '.opencode').mkdir(mode=0o700, parents=True)
    model = Model(root)
    threading.Thread(target=model.serve_forever, daemon=True).start()
    config = {'model': 'fixture/fixture', 'update': 'disable',
              'permissions': [{'action': '*', 'resource': '*', 'effect': 'allow'}],
              'providers': {'fixture': {'name': 'Local deterministic fixture', 'env': ['PEERWORK_FIXTURE_KEY'],
                  'package': '@opencode/ai/providers/openai-compatible',
                  'settings': {'baseURL': 'http://127.0.0.1:%d/v1' % model.server_port},
                  'models': {'fixture': {'name': 'Fixture', 'capabilities': {'tools': True},
                                         'limit': {'context': 128000, 'output': 4096}}}}}}
    config_path = project / '.opencode/opencode.json'
    atomic(config_path, config)
    env = dict(os.environ, PEERWORK_FIXTURE_KEY='synthetic-no-paid-provider', OPENCODE_DISABLE_FREE_MODELS='1')
    for key in ('STATE', 'CONFIG', 'DATA', 'CACHE'):
        directory = root / ('xdg-' + key.lower())
        directory.mkdir(mode=0o700)
        env['XDG_' + key + '_HOME'] = str(directory)
    service = Path(env['XDG_STATE_HOME']) / 'opencode/service.json'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    host = fixture = None
    facts = {'state': 'PREPARING', 'host': 'OpenCode V2', 'model': 'DETERMINISTIC_LOCAL_TOOL_FIXTURE', 'production_data': False}

    def api(path, body=None):
        registration = json.loads(service.read_text())
        auth = base64.b64encode(('opencode:' + registration['password']).encode()).decode()
        req = urllib.request.Request(registration['url'].rstrip('/') + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'})
        return json.loads(opener.open(req, timeout=10).read())

    def start():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        log = (root / 'opencode.log').open('a')
        child = subprocess.Popen([args.opencode, 'serve', '--service', '--hostname', '127.0.0.1', '--port', str(port)],
            cwd=project, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            wait_for(lambda: service.is_file() and json.loads(service.read_text()).get('pid') == child.pid)
            def ready():
                assert child.poll() is None, 'OWNED_OPENCODE_EXITED'
                try:
                    return api('/api/info')['version'].startswith('2.')
                except (OSError, ValueError):
                    return False
            wait_for(ready)
        except BaseException:
            child.terminate()
            child.wait(timeout=15)
            raise
        return child

    try:
        host = start()
        session = api('/api/session', {'location': {'directory': str(project)}, 'title': 'Native Peerwork V2 qualification'})['data']['id']
        facts['session_id'] = session
        state = root / 'native-state'
        atomic(root / 'host.json', {'kind': 'opencode', 'service_file': str(service), 'session_id': session, 'directory': str(project)})
        fixture_env = dict(os.environ, PEERWORK_TEST_NODE=args.node, PEERWORK_STRUCTURE_REFERENCE_ROOT=args.product,
            PEERWORK_POSTGRES_TEST_URL=args.postgres, PEERWORK_PARTICIPANT_CLI=args.cli,
            PEERWORK_LIVE_HOST_CONFIG=str(root / 'host.json'), PEERWORK_LIVE_HOST_STATE_DIR=str(state),
            PEERWORK_LIVE_HOST_REPORT=str(state / 'result.json'), PEERWORK_LIVE_HOST_NONCE='OPENCODE-V2-' + os.urandom(8).hex(),
            PEERWORK_LIVE_HOST_ROUNDS='2', PEERWORK_LIVE_HOST_REQUIRE_CONSUMED='1', PEERWORK_LIVE_HOST_START_GATE='1')
        with (root / 'native-fixture.log').open('w') as log:
            fixture = subprocess.Popen([args.test_binary, '--exact', 'participant_live_host_tests::program_master_existing_session_and_native_agent_reply',
                '--ignored', '--nocapture', '--test-threads=1'], cwd=args.sdk, env=fixture_env, stdout=log, stderr=log, start_new_session=True)
        def native_ready():
            assert fixture.poll() is None, 'INSPECT_NATIVE_FIXTURE_STARTUP_LOG'
            return (state / 'result.json').exists()
        wait_for(native_ready, 35)
        assert fixture.poll() is None, 'NATIVE_FIXTURE_EXITED_EARLY'
        # Configure only this synthetic project after its native profile exists.
        config['mcp'] = {'servers': {'peerwork': {'type': 'local', 'command': [args.cli, 'agent', '--profile', str(state / 'worker-agent.json'), 'mcp'],
                                                'protocol': '2026-07-28', 'codemode': False}}}
        atomic(config_path, config)
        host.terminate()
        host.wait(timeout=15)
        host = start()
        assert api('/api/session/' + session)['data']['id'] == session
        (state / 'observed-host-ready').write_text('Original selected session retained after service restart.\n')
        facts['fixture_exit_code'] = fixture.wait(timeout=230)
        result = json.loads((state / 'result.json').read_text())
        facts.update(state='PASS' if fixture.returncode == 0 and result['state'] == 'COMPLETED' else 'FAILED',
                     native_result=result, model_requests=model.requests, tool_calls=[v['tool'] for v in model.calls])
        assert facts['state'] == 'PASS', 'INSPECT_RETAINED_FIXTURE_LOG'
        assert facts['tool_calls'].count('peerwork_reply') == 2
        assert facts['tool_calls'].count('peerwork_consume') == 2
    finally:
        for child in (fixture, host):
            if child and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=15)
        model.shutdown()
        model.server_close()
        facts['owned_processes_stopped'] = True
        atomic(root / 'qualification.json', facts)
        print(json.dumps(facts), flush=True)


if __name__ == '__main__':
    main()
