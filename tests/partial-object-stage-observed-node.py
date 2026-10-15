#!/usr/bin/env python3
"""Observe the genuine applied final part without changing server PID/requests."""
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

node = os.environ["PEERWORK_OBSERVER_REAL_NODE"]
output = Path(os.environ["PEERWORK_TEST_REQUEST_OBSERVER"])
args = sys.argv[1:]
if not args:
    raise SystemExit("observed node needs a script")
script = Path(args[0]).name
if script == "reference-kernel-server.mjs":
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": "OBSERVER_SERVER_START", "pid": os.getpid()}) + "\n")
    os.execv(node, [node, "--require", str(Path(__file__).with_name("staged-install-request-observer.cjs")), *args])
result = subprocess.run([node, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
if script == "legacy-owner-partial-object-stage.mjs" and result.returncode == 0:
    if len(args) != 5 or args[4] != "part1-applied-loss":
        raise SystemExit("observer requires exact genuine applied final-part fixture")
    fixture = json.loads(result.stdout)
    assert fixture["part_index"] == 1 and fixture["part_count"] == 2
    assert fixture["accepted_part_count"] == 2 and fixture["install_intent_count"] == 0
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": "PARTIAL_FIXTURE_BASELINE", "host": urlsplit(args[1]).netloc,
                                 "path": f'/api/workspace/v1/secure/workspaces/{fixture["workspace_id"]}/commits',
                                 "selected_command_id": fixture["pending_command_id"]}) + "\n")
raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
