"""Assert refusal of the supported PRIVATE member action and unchanged head.

The Python error is deliberately reported at its actual generic boundary
(ACTION_PREPARE_FAILED). The exact AUTHOR_SCOPE_DENIED cause is qualified
separately by qualify-private-member-denial.mjs against the same verified
policy, objects, body, and reference; this test does not claim an HTTP 403.
"""

import json
import os
import sys
from pathlib import Path

from peerwork import SecureActionError, SecurePrivateActionClient, SecureReadClient


fixture = json.loads(Path(sys.argv[1]).read_text())
output_path = Path(sys.argv[2])
profile = json.loads(Path(fixture["profile_path"]).read_text())
denial = fixture["denial"]
assert fixture["workspace_id"] == profile["workspace_id"]
assert denial["action_id"] == "wiki.revise"
assert denial["instance_id"] == fixture["new_action"]["instance_id"]

def reader():
    return SecureReadClient(
        profile["origin"], profile["state_dir"], profile["identity_path"],
        profile["workspace_id"], owner_actor_id=profile["owner_actor_id"],
        owner_key_id=profile["owner_key_id"],
        allow_loopback_http=profile["allow_loopback_http"],
    )

before = reader().read_private()
assert before["sequence"] == fixture["node_expected_sequence"]
record = next(row for row in before["objects"]
              if row.get("kind") == "records" and row.get("id") == denial["record_id"])
assert record.get("value", {}).get("revision") == denial["revision"]
assert any(row.get("kind") == "instances" and row.get("id") == denial["instance_id"]
           and row.get("value", {}).get("origin_entrypoint") == "wiki"
           for row in before["objects"])
client = SecurePrivateActionClient(
    profile["origin"], profile["state_dir"], profile["identity_path"],
    profile["workspace_id"], owner_actor_id=profile["owner_actor_id"],
    owner_key_id=profile["owner_key_id"],
    allow_loopback_http=profile["allow_loopback_http"],
)
try:
    result = client.submit(
        denial["action_id"], denial["instance_id"], denial["body"],
        exact_input_refs=[{"record_id": denial["record_id"], "revision": denial["revision"]}],
        command_id=denial["command_id"], operation_id=denial["operation_id"],
    )
except SecureActionError as error:
    # This facade maps core preparation and server refusal to distinct generic
    # SDK codes. Keep this test's claim at the observed preparation boundary.
    assert error.code in {"ACTION_PREPARE_FAILED", "SERVER_REJECTED"}, error.code
    denied_code = error.code
else:
    raise AssertionError(f"unsupported permission outcome: {result['status']}")

after = reader().read_private()
assert after["sequence"] == before["sequence"]
assert after["head"] == before["head"]
summary = {
    "status": "PASS",
    "scope": "installed Python PRIVATE member facade refused wiki.revise preparation for the existing wiki record; signed head unchanged",
    "cause_qualification": "separate offline reference-engine result; Python ACTION_PREPARE_FAILED does not expose AUTHOR_SCOPE_DENIED",
    "workspace_id": fixture["workspace_id"],
    "member_actor_id": fixture["member_actor_id"],
    "action_id": denial["action_id"],
    "before_sequence": before["sequence"],
    "after_sequence": after["sequence"],
    "head_unchanged": True,
    "error_code": denied_code,
}
fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    output.write(json.dumps(summary, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
