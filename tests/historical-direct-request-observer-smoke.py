#!/usr/bin/env python3
"""Small real-service regression for the hash-only operator observer."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import urllib.error
import urllib.request

sdk = Path(__file__).resolve().parents[1]
node = Path('/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/direct-begin-e131/rootfs-managed/opt/node24/bin/node')
reference = Path('/root/workdir/message/.worktrees/e2ee-main-integration-20261006')
with tempfile.TemporaryDirectory(prefix='direct-observer-') as temporary:
    state = Path(temporary);state.chmod(0o700)
    output = state / 'requests.jsonl';output.touch(mode=0o600)
    env = dict(os.environ, PEERWORK_REFERENCE_ROOT=str(reference),PEERWORK_TEST_STATE=str(state),
        PEERWORK_TEST_FIRST_POST_MODE='normal',PEERWORK_TEST_REQUEST_OBSERVER=str(output))
    server = subprocess.Popen([str(node),'--require',str(sdk/'tests/historical-direct-request-observer.cjs'),
        str(sdk/'tests/reference-kernel-server.mjs')],cwd=sdk,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        first = server.stdout.readline();assert first,'fixture exited before READY'
        origin = json.loads(first)['origin']
        body = json.dumps({'commit':{'payload':{'command_id':'c'*43}}},separators=(',',':')).encode()
        path = '/api/workspace/v1/secure/workspaces/'+'w'*43+'/commits'
        request = urllib.request.Request(origin.rstrip('/')+path,data=body,
            headers={'content-type':'application/json'},method='POST')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request,timeout=5) as result:status=result.status
        except urllib.error.HTTPError as error:status=error.code
        assert 400 <= status < 500,'invalid unsigned fixture request was accepted'
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        from urllib.parse import urlsplit
        outer = [row for row in rows if row['host']==urlsplit(origin).netloc]
        assert len(outer)==1 and outer[0]['path']==path and outer[0]['method']=='POST'
        assert outer[0]['body_sha256']==hashlib.sha256(body).hexdigest()
        assert outer[0]['body_bytes']==len(body) and outer[0]['command_id']=='c'*43
        assert all(set(row)=={'method','path','host','command_id','body_bytes','body_sha256'} for row in rows)
        with sqlite3.connect('file:'+str(state/'control.sqlite')+'?mode=ro',uri=True) as database:
            assert database.execute('SELECT count(*) FROM secure_commits').fetchone()[0]==0
        prepared = subprocess.run([str(node),str(sdk/'tests/legacy-owner-install-intent.mjs'),
            origin,str(state/'signed-source'),str(reference),'direct-completed-end'],
            cwd=sdk,env=env,capture_output=True,text=True,timeout=120)
        assert prepared.returncode == 0,'observer changed genuine signed completion'
        fixture = json.loads(prepared.stdout)
        assert fixture['pending_count']==0 and fixture['latest_sequence']==3
        rows = [json.loads(line) for line in output.read_text().splitlines()]
        signed = [row for row in rows if row['host']==urlsplit(origin).netloc
            and row['path']==f"/api/workspace/v1/secure/workspaces/{fixture['workspace_id']}/commits"]
        assert len(signed)==2 and len({row['command_id'] for row in signed})==2
        with sqlite3.connect('file:'+str(state/'control.sqlite')+'?mode=ro',uri=True) as database:
            assert database.execute('SELECT count(*) FROM secure_commits').fetchone()[0]==3
            accepted = {row[0] for row in database.execute('SELECT command_id FROM secure_commits')}
        assert all(row['command_id'] in accepted for row in signed)
        for row in signed:
            matching = [other for other in rows if other['command_id']==row['command_id']]
            assert len(matching)==2 and len({other['body_sha256'] for other in matching})==1
        print(json.dumps({'scope':'real pinned service observer unsigned and signed regression',
            'invalid_request_http_status':status,'signed_outer_requests':len(signed),
            'service_commits':3,'signed_pending_count':0,'request_body_persisted':False}))
    finally:
        server.terminate();server.wait(timeout=10)
