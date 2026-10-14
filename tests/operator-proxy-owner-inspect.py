#!/usr/bin/env python3
"""Deterministic signed inspection using a guarded prepared fixture; no actor.

SCRIPT PREPARED_TASK NEW_CLI; fixture setup is separately owned and supervised.
Only hash/status/effect summaries are printed. Raw results stay protected.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: operator-proxy-owner-inspect.py PREPARED_TASK NEW_CLI")
task = Path(sys.argv[1]).resolve()
cli = Path(sys.argv[2]).resolve()
actor, observer = task / "actor", task / "observer"
fixture = json.loads((observer / "fixture.json").read_text())
# Exact policy source is the preserved frozen trial, not an in-run hint.
invocation = json.loads(Path('/root/workdir/message/.test-data/agent-trial-pending-e131-20261014-one/observer/agent-attempt-1/invocation.json').read_text())
arguments = invocation['argv']
policy = []
for index, value in enumerate(arguments):
    if value == '-c':
        policy.extend((value, arguments[index + 1]))
work = observer / 'operator-proxy-regression'
resume = os.environ.get('PEERWORK_PROXY_TEST_RESUME') == '1'
work.mkdir(mode=0o700, exist_ok=resume)
if resume:
    assert not (work / 'native-state/identity.state').exists(), 'resume must precede identity import'
config = json.loads((actor / 'owner-config.json').read_text())
config['state_dir'] = str(work / 'native-state')
(work / 'owner-config.json').write_text(json.dumps(config))
(work / 'owner-config.json').chmod(0o600)
child = work / 'child.py'
child.write_text('''import os,subprocess,sys
mode,cli,*args=sys.argv[1:]
env=dict(os.environ);env.pop("PEERWORK_HTTP_PROXY",None)
if mode=="explicit":
 assert env.get("CODEX_NETWORK_PROXY_ACTIVE"),"runtime proxy absent"
 env["PEERWORK_HTTP_PROXY"]=env["HTTP_PROXY"]
result=subprocess.run([cli,*args],env=env,capture_output=True,timeout=120)
sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr);sys.exit(result.returncode)
''')
child.chmod(0o600)
def commits():
    with sqlite3.connect('file:' + fixture['control_database'] + '?mode=ro', uri=True) as connection:
        total = connection.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=?', (fixture['workspace_id'],)).fetchone()[0]
        original = connection.execute('SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?', (fixture['workspace_id'], fixture['original_command_id'])).fetchone()[0]
    return total, original

def run(label, binary, mode, args):
    command = [arguments[0], 'sandbox', '-P', 'trial', '-C', str(work), *policy,
               'python3', str(child), mode, str(binary), *args]
    env = dict(os.environ);env.pop('PEERWORK_HTTP_PROXY', None)
    result = subprocess.run(command,env=env,capture_output=True,timeout=135)
    for stream in ('stdout', 'stderr'):
        path = work / (label + '.' + stream)
        path.write_bytes(getattr(result, stream));path.chmod(0o600)
    payload = result.stdout if result.returncode == 0 else result.stderr
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeError):
        parsed = {}
    summary = {'exit': result.returncode, 'code': parsed.get('code'),
        'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
        'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
    return summary, parsed

inspection = ['secure','owner-stage-multipart-inspect',str(work / 'owner-config.json'),
              str(actor / 'selected-source.json'),str(actor / 'selected-source/selected-package-material.json')]
before = commits()
def preserved(label):
    stdout = (work / (label + '.stdout')).read_bytes()
    stderr = (work / (label + '.stderr')).read_bytes()
    code = json.loads(stderr)['code']
    assert not stdout and code == 'VERIFICATION_FAILED'
    return {'exit':1, 'code':code, 'stdout_sha256':hashlib.sha256(stdout).hexdigest(),
            'stderr_sha256':hashlib.sha256(stderr).hexdigest(), 'reused_preserved_result':True}
if resume:
    old = preserved('old-explicit')
    generic = preserved('new-generic')
    # Preserve the actual failed first explicit inspection and its traceback.
    for stream in ('stdout', 'stderr'):
        original = work / ('new-explicit-pre-identity.' + stream)
        original.rename(work / ('first-timeout.' + stream))
else:
    old, _ = run('old-explicit', actor / 'peerwork', 'explicit', inspection)
    generic, _ = run('new-generic', cli, 'generic', inspection)
assert old['exit'] != 0 and old['code'] == 'VERIFICATION_FAILED', old
assert generic['exit'] != 0 and generic['code'] == 'VERIFICATION_FAILED', generic
pre, pre_value = run('new-explicit-pre-identity', cli, 'explicit', inspection)
assert pre['exit'] == 0, pre
assert not (work / 'native-state/identity.state').exists(), 'inspection implicitly created identity'
identity, identity_value = run('identity-import', cli, 'generic',
    ['identity','import-legacy-owner-pem',str(work / 'owner-config.json'),str(actor / 'selected-source/owner-private.pem')])
assert identity['exit'] == 0, identity
selected = json.loads((actor / 'selected-source.json').read_text())
assert identity_value['actor_id'] == selected['expected_owner_actor_id']
assert identity_value['key_id'] == selected['expected_owner_key_id']
post, post_value = run('new-explicit-post-identity', cli, 'explicit', inspection)
assert post['exit'] == 0 and pre_value == post_value, post
assert commits() == before == (2, 0), 'inspection or identity changed service effects'
summary = {'scope':'deterministic operator signed-source inspection under unchanged localhost-only policy',
    'old_explicit':old,'new_generic':generic,'pre_identity':pre,'identity_import':identity,'post_identity':post,
    'service_commits_before':before[0],'service_commits_after':commits()[0],
    'original_command_commits':commits()[1], 'implicit_identity_created':False,
    'business_installation':'NOT_EXERCISED','agent_workflow':'NOT_ASSESSED'}
(work / 'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
(work / 'summary.json').chmod(0o600)
print(json.dumps(summary))
