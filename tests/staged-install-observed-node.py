#!/usr/bin/env python3
"""Operator-only launch adapter; preserve exact native product binary."""
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
    command = [node, "--require", str(Path(__file__).with_name("staged-install-request-observer.cjs")), *args]
    # Preserve the server PID so the original Rust Drop guard kills/waits it.
    os.execv(node, command)
else:
    command = [node, *args]
result = subprocess.run(command, check=False)
if script == "legacy-owner-install-intent.mjs" and result.returncode == 0:
    if len(args) != 5 or args[4] != "direct-staged-package-begin-before-post":
        raise SystemExit("observer baseline requires the selected genuine BEGIN fixture")
    # The child has finished public staging and saved BEGIN-before-POST.
    # Its exact stdout/stderr is inherited; only operator metadata is appended.
    record = {"event": "FIXTURE_COMPLETE_BASELINE", "host": urlsplit(args[1]).netloc,
              "mode": args[4]}
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
