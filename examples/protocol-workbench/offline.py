"""Run with an installed peerwork-sdk 0.1.9 wheel; no service or identity needed."""
import copy
import json
from pathlib import Path

from peerwork import (
    ProtocolWorkbenchError, build_protocol_fixture, plan_protocol_actions,
    protocol_compatibility, simulate_protocol,
)


def reject(fixture, steps, code):
    before = copy.deepcopy(fixture)
    try:
        simulate_protocol(fixture, steps)
    except ProtocolWorkbenchError as error:
        assert error.code == code, error.envelope
    else:
        raise AssertionError("negative case unexpectedly succeeded")
    assert fixture == before


# An explicit archival copy, not a transfer of claim authority. Both immutable
# versions coexist. A real authority transfer needs its own close/fence actions.
v1 = {
    "name": "example.ticket", "display_version": "1",
    "semantics": "peerwork.kernel.v1", "dependencies": [], "initial_state": {},
    "record_schemas": {"ticket": {"type": "object", "fields": {"title": "string"},
        "required": ["title"], "max_bytes": 4096}},
    "actions": [{"id": "create", "reads": [], "writes": [],
        "revisionEffects": {"control": False, "contentEntities": []},
        "variants": [{"when": [], "effects": [{"op": "append", "schema": "ticket",
            "value": {"from": "body", "path": []}}]}]}],
}
v2 = copy.deepcopy(v1)
v2["display_version"] = "2"
v2["record_schemas"]["ticket"]["fields"]["source"] = "json"
v2["record_schemas"]["ticket"]["required"].append("source")
ref = {"from": "ref", "source": "body", "path": ["source"],
       "schema": "ticket", "scope": "WORKSPACE"}
v2["actions"] = [{"id": "import", "reads": [], "writes": [],
    "revisionEffects": {"control": False, "contentEntities": []},
    "variants": [{"when": [{"op": "exact_ref", "ref": ref}], "effects": [
        {"op": "append", "schema": "ticket", "value": {"from": "object", "fields": {
            "title": {"from": "resolved_payload", "ref": ref, "path": ["title"]},
            "source": {"from": "body", "path": ["source"]}}}}]}]}]
fixture = build_protocol_fixture([
    {"instance_id": "v1", "manifest": v1}, {"instance_id": "v2", "manifest": v2},
], seed="copy-example", time_ms=0)
source = {"record_id": "R" * 43, "revision": 1}
steps = [
    {"instance_id": "v1", "action_id": "create", "body": {"title": "Original"},
     "allocations": [{"record_id": source["record_id"], "entity_id": "E" * 43}]},
    {"instance_id": "v2", "action_id": "import", "body": {"source": source},
     "exact_input_refs": [source]},
]
result = simulate_protocol(fixture, steps, seed="copy-example")
assert result["steps"][1]["effects"][0]["value"]["payload"] == {
    "title": "Original", "source": source,
}
plan = plan_protocol_actions(fixture, steps, seed="copy-example")
assert plan["authoritative"] is False and len(plan["dependency_checkpoints"]) == 3
bad = copy.deepcopy(steps)
bad[1]["exact_input_refs"][0]["revision"] = 2
reject(fixture, bad, "REFERENCE_NOT_FOUND")

# The same actual bounded-lease manifest used by the service example. Its effects
# copy an explicit expiry; trusted time appears in guards, never a local clock.
manifest = json.loads((Path(__file__).parent.parent /
    "private-bounded-lease/manifest.json").read_text())
lease = build_protocol_fixture([{"instance_id": "lease", "manifest": manifest}],
    actors=[{"name": "worker", "workspace_role": "MEMBER",
             "protocol_roles": ["LEASE_ACTOR"], "capabilities": ["LEASE"]}],
    time_ms=1000, seed="lease-example")
claim = {"instance_id": "lease", "action_id": "lease.claim", "time_ms": 1000,
         "body": {"expected_generation": 0, "generation": 1, "expires_at": 2000}}
claimed = simulate_protocol(lease, [claim])["fixture"]
renew = {"instance_id": "lease", "action_id": "lease.renew", "time_ms": 1999,
         "body": {"expected_generation": 1, "expires_at": 3000}}
assert simulate_protocol(claimed, [renew])["steps"][0]["output_state"]["expires_at"] == 3000
renew["time_ms"] = 2000
reject(claimed, [renew], "CONSTRAINT_FAILED")
reclaim = {"instance_id": "lease", "action_id": "lease.reclaim", "time_ms": 2000,
           "body": {"expected_generation": 1, "generation": 2, "expires_at": 3000}}
assert simulate_protocol(claimed, [reclaim])["steps"][0]["output_state"]["generation"] == 2
for expiry in [1999, 61001]:
    bad_claim = copy.deepcopy(claim)
    bad_claim["body"]["expires_at"] = expiry
    reject(lease, [bad_claim], "CONSTRAINT_FAILED")

coverage = protocol_compatibility(["protocol.action", "workspace.invitation.finalize"])
assert coverage["supported"] and not coverage["service_verified"]
print(json.dumps({"status": "PASS", "simulated": True, "authoritative": False,
    "cases": ["v1-v2-explicit-copy", "missing-reference", "claim-ttl-bounds",
              "renew-before-expiry", "reclaim-at-expiry", "producer-coverage"]}))
