#!/usr/bin/env python3
"""Deterministic proxy-only runtime regression; never launches a model.

Run with authorized local binding: python3 SCRIPT CLI CODEX [OLD_CLI].
The parent owns one local test server. Children retain the reviewed
localhost-only trial sandbox, with external destinations denied.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

if len(sys.argv) not in (3, 4):
    raise SystemExit("usage: cli-explicit-proxy-sandbox.py CLI CODEX [OLD_CLI]")
cli, codex = [Path(value).resolve() for value in sys.argv[1:3]]
old = Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None
policy = [
    'approval_policy="never"', 'default_permissions="trial"',
    'permissions.trial.extends=":workspace"',
    'permissions.trial.network.enabled=true',
    'permissions.trial.network.domains={"127.0.0.1"="allow"}',
    'permissions.trial.network.allow_local_binding=false',
    'permissions.trial.network.allow_upstream_proxy=false',
    'features.network_proxy.enabled=true',
    'features.network_proxy.domains={"127.0.0.1"="allow"}',
    'features.network_proxy.allow_local_binding=false',
    'features.network_proxy.allow_upstream_proxy=false',
    'features.network_proxy.enable_socks5=false',
    'features.network_proxy.enable_socks5_udp=false',
    'web_search="disabled"', 'tools.web_search=false',
    'apps._default.enabled=false', 'features.multi_agent=false', 'mcp_servers={}',
]
requests = []
wire = b'{"items":[],"next":null,"watermark":0}'
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)
    def log_message(self, *_):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix="proxy-cli-", dir=os.environ.get("TMPDIR")) as temporary:
        task = Path(temporary)
        config = task / "catalog.json"
        config.write_text(json.dumps({"origin": f"http://127.0.0.1:{server.server_port}/", "allow_loopback_http": True}))
        runner = task / "child.py"
        runner.write_text('''import json,os,subprocess,sys
cli,config,mode=sys.argv[1:]
env=dict(os.environ);env.pop("PEERWORK_HTTP_PROXY",None)
if mode=="explicit":
 assert env.get("CODEX_NETWORK_PROXY_ACTIVE"),"runtime did not supply its required proxy"
 env["PEERWORK_HTTP_PROXY"]=env["HTTP_PROXY"]
elif mode=="invalid":env["PEERWORK_HTTP_PROXY"]="invalid-proxy"
p=subprocess.run([cli,"secure","catalog-search",config,"transport"],env=env,capture_output=True,text=True,timeout=20)
print(json.dumps({"exit":p.returncode,"stdout":p.stdout,"stderr":p.stderr}))
''')
        def run(binary, mode):
            args = [str(codex), "sandbox", "-P", "trial", "-C", str(task)]
            for setting in policy:
                args.extend(("-c", setting))
            args.extend(("python3", str(runner), str(binary), str(config), mode))
            env = dict(os.environ)
            env.pop("PEERWORK_HTTP_PROXY", None)
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, f"sandbox runtime failed: {result.returncode}"
            return json.loads(result.stdout)
        if old:
            before = run(old, "explicit")
            assert before["exit"] != 0 and "CATALOG_TRANSPORT_FAILED" in before["stderr"], before
            assert requests == [], "old binary unexpectedly reached the server"
        generic = run(cli, "generic")
        assert generic["exit"] != 0 and "CATALOG_TRANSPORT_FAILED" in generic["stderr"], generic
        assert requests == [], "generic proxy environment was implicitly adopted"
        invalid = run(cli, "invalid")
        assert invalid["exit"] != 0 and "CATALOG_INPUT_INVALID" in invalid["stderr"], invalid
        assert requests == [], "invalid explicit proxy did not fail closed"
        explicit = run(cli, "explicit")
        assert explicit["exit"] == 0, explicit
        value = json.loads(explicit["stdout"])
        assert json.loads(value["listing_canonical_json"]) == json.loads(wire)
        assert len(requests) == 1 and requests[0].startswith("/api/protocol-catalog/v1/packages?"), requests
        print(json.dumps({"scope": "deterministic proxy-only CLI transport; synthetic HTTP fixture",
            "old_binary_refused": bool(old), "generic_proxy_ignored": True,
            "invalid_proxy_refused": True, "explicit_proxy_exact_response": True,
            "server_gets": len(requests), "cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest()}))
finally:
    server.shutdown()
    server.server_close()
