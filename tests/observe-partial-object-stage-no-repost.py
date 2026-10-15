#!/usr/bin/env python3
"""One real applied-final-part recovery: prove no selected stage retransmission."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

binary, reference, node, output = map(Path, sys.argv[1:])
expected = "fb3196392f6d09b934972cb58cda15ad1de7884b39c4a2f7722af6347e0dc69e"
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert digest(binary) == expected
assert digest(Path(__file__).with_name("staged-install-request-observer.cjs")) == "2fc1dc6cdbb83b200832e7b1dee7bb642351d21a76be72c4fe0e0e93216741ce"
output.mkdir(mode=0o700)
requests = output / "requests.jsonl"
requests.touch(mode=0o600)
env = dict(os.environ)
env.pop("PEERWORK_HTTP_PROXY", None)
env.update(PEERWORK_REFERENCE_ROOT=str(reference), PEERWORK_OBSERVER_REAL_NODE=str(node),
           PEERWORK_NODE_BIN=str(Path(__file__).with_name("partial-object-stage-observed-node.py").resolve()),
           PEERWORK_TEST_REQUEST_OBSERVER=str(requests), PEERWORK_PARTIAL_OBJECT_STAGE_MODE="part1-applied-loss",
           PEERWORK_PARTIAL_OBJECT_NATIVE_ROOT=str(output / "native-state"))
log_path = output / "native.log"
with log_path.open("x", encoding="utf-8") as log:
    os.chmod(log_path, 0o600)
    result = subprocess.run([str(binary), "secure_owner_attach::tests::actual_service_imports_final_partial_protocol_object_stage",
                             "--exact", "--nocapture"], env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
assert result.returncode == 0, "native gate failed; preserve log/state"
rows = [json.loads(line) for line in requests.read_text().splitlines()]
servers = [row["pid"] for row in rows if row.get("event") == "OBSERVER_SERVER_START"]
assert len(servers) == 1 and isinstance(servers[0], int) and servers[0] > 0
assert not Path(f"/proc/{servers[0]}").exists(), "owned server must have exited and been reaped"
markers = [index for index, row in enumerate(rows) if row.get("event") == "PARTIAL_FIXTURE_BASELINE"]
assert len(markers) == 1
index = markers[0]
baseline = rows[index]
def posts(values):
    return [row for row in values if row.get("method") == "POST" and row.get("host") == baseline["host"]
            and row.get("path") == baseline["path"]]
before, after = posts(rows[:index]), posts(rows[index + 1:])
stages = [row for row in before if row.get("action_id") == "secure.protocol-object.stage"]
assert len(stages) == 2, "positive control must observe both genuine stage packets"
assert sum(row["command_id"] == baseline["selected_command_id"] for row in stages) == 1
assert not any(row.get("action_id") == "secure.structure.begin" for row in before)
assert [row.get("action_id") for row in after] == ["secure.structure.begin", "secure.structure.end"]
assert all(row["command_id"] != baseline["selected_command_id"] for row in after)
assert digest(binary) == expected
summary = {"passed": True, "binary_sha256": expected, "server_pid": servers[0], "server_exited_and_reaped": True,
           "genuine_stage_posts_before_baseline": len(stages), "selected_stage_posts_before_baseline": 1,
           "post_baseline_posts": len(after), "post_baseline_stage_posts": 0,
           "requests_sha256": digest(requests), "native_log_sha256": digest(log_path)}
summary_path = output / "summary.json"
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
os.chmod(summary_path, 0o600)
print(json.dumps(summary))
