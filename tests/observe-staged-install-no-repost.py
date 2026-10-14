#!/usr/bin/env python3
"""One fresh genuine BEGIN gate, with immutable reviewed runtime binary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

binary, reference, node, output = map(Path, sys.argv[1:])
expected = "18b743be58fdf3c728cb0726e493fe0b85fdda855107d20767bc7da5b817a57a"
assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
output.mkdir(mode=0o700)
requests = output / "requests.jsonl"
requests.touch(mode=0o600)
env = dict(os.environ)
env.pop("PEERWORK_HTTP_PROXY", None)
env.update(PEERWORK_REFERENCE_ROOT=str(reference), PEERWORK_OBSERVER_REAL_NODE=str(node),
           PEERWORK_NODE_BIN=str(Path(__file__).with_name("staged-install-observed-node.py").resolve()),
           PEERWORK_TEST_REQUEST_OBSERVER=str(requests),
           PEERWORK_STAGED_SOURCE_INSTALL_MODE="direct-staged-package-begin-before-post")
with (output / "native.log").open("x", encoding="utf-8") as log:
    result = subprocess.run([str(binary), "secure_owner_attach::tests::actual_service_imports_staged_package_source_install",
                             "--exact", "--nocapture"], env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
assert result.returncode == 0, "reviewed native gate failed; retain original log"
rows = [json.loads(line) for line in requests.read_text().splitlines()]
markers = [index for index, row in enumerate(rows) if row.get("event") == "FIXTURE_COMPLETE_BASELINE"]
assert len(markers) == 1
index = markers[0]
host = rows[index]["host"]
posts = lambda values: [row for row in values if row.get("method") == "POST" and row.get("host") == host]
before, after = posts(rows[:index]), posts(rows[index + 1:])
assert all(isinstance(row.get("action_id"), str) for row in before + after)
stages = [row for row in before if row["action_id"] == "secure.protocol-package.stage"]
assert stages, "positive control must observe genuine encrypted-stage action metadata"
assert after, "native recovery positive control must submit a request after baseline"
assert any(row["action_id"] == "secure.structure.begin" for row in after)
assert any(row["action_id"] == "secure.structure.end" for row in after)
assert not any(row["action_id"] == "secure.protocol-package.stage" for row in after), "no stage POST after genuine prefix, including retries/refusals"
assert hashlib.sha256(binary.read_bytes()).hexdigest() == expected
summary = {"passed": True, "binary_sha256": expected, "genuine_stage_posts_before_baseline": len(stages),
           "post_baseline_posts": len(after), "post_baseline_stage_posts": 0,
           "requests_sha256": hashlib.sha256(requests.read_bytes()).hexdigest(),
           "native_log_sha256": hashlib.sha256((output / "native.log").read_bytes()).hexdigest()}
(output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary))
