#!/usr/bin/env python3
"""Operator adapter; preserve native test server PID and exact fixture behavior."""
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
    # Reuse accepted pass-through metadata observer; original Rust Drop owns PID.
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": "OBSERVER_SERVER_START", "pid": os.getpid()}) + "\n")
    os.execv(node, [node, "--require", str(Path(__file__).with_name("staged-install-request-observer.cjs")), *args])
result = subprocess.run([node, *args], check=False)
if script == "legacy-owner-install-intent.mjs" and result.returncode == 0:
    if len(args) != 5 or args[4] != "direct-object-begin-before-post":
        raise SystemExit("observer requires exact genuine complete-object BEGIN fixture")
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event": "FIXTURE_COMPLETE_BASELINE", "host": urlsplit(args[1]).netloc,
                                 "mode": args[4]}) + "\n")
raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
