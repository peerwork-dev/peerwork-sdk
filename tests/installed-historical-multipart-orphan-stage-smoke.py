"""Scripted installed Owner recovery of one genuine index-1 packetless TS stage.

The host fixture supplies protected caller-selected files and a loopback POST
barrier. This test uses public Python, Node and CLI APIs only. Its proxy sees
outbound HTTP bytes; the SDK consumer never reads private native state.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, key in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("tests/legacy-owner-source.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[key]
fixture = json.loads(Path(os.environ["PEERWORK_TEST_HOST_FIXTURE_JSON"]).read_text())
origin = fixture["origin"]
source = fixture["source"]
assert origin.startswith("http://127.0.0.1:") and STATE.is_dir()
assert STATE.stat().st_mode & 0o077 == 0


def barrier(method: str, path: str):
    request = urllib.request.Request(origin + "__proxy/" + path, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def count(database: Path, workspace: str, command: str | None = None):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        if command is None:
            return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=?", (workspace,)).fetchone()[0]
        return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?", (workspace, command)).fetchone()[0]


def node_call(config: dict, operation: str, **values):
    script = r'''
void (async () => {
  const fs = require('node:fs');
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(fs.readFileSync(0, 'utf8'));
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'inspect': result = await owner.inspectMultipartOrphanPackageStage(value.input, value.materialJson); break;
    case 'attach': result = await owner.attachMultipartOrphanPackageStage(value.input, value.materialJson); break;
    case 'replan': result = await owner.replanOrphanPackageStage(value.attachId, value.originalCommandId); break;
    case 'attachments': result = await owner.attachments(); break;
    default: throw new Error('invalid test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => console.log(JSON.stringify({ok:false,code:error.code,message:error.message})));
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_OWNER_CONFIG=json.dumps(config), PEERWORK_TEST_OPERATION=operation)
    result = subprocess.run([NODE, "-e", script], env=env, input=json.dumps(values),
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def cli(config_file: Path, verb: str, *args):
    result = subprocess.run([CLI, "secure", verb, str(config_file), *(str(arg) for arg in args)],
                            capture_output=True, text=True, timeout=120)
    return dict(ok=result.returncode == 0,
                value=json.loads(result.stdout if result.returncode == 0 else result.stderr))


def source_input():
    return dict(workspace_id=source["workspace_id"], protected_ts_state_path=source["state_path"],
                protected_ts_intent_db_path=source["intent_db_path"],
                protected_owner_pkcs8_path=source["pem_path"],
                expected_owner_actor_id=source["owner_actor_id"],
                expected_owner_key_id=source["owner_key_id"])


def node_input(value):
    return dict(workspaceId=value["workspace_id"],
                protectedTsStatePath=value["protected_ts_state_path"],
                protectedTsIntentDbPath=value["protected_ts_intent_db_path"],
                protectedOwnerPkcs8Path=value["protected_owner_pkcs8_path"],
                expectedOwnerActorId=value["expected_owner_actor_id"],
                expectedOwnerKeyId=value["expected_owner_key_id"],
                selectedOrphanPackageStageCommandId=value.get("selected_orphan_package_stage_command_id"),
                expectedTsStateDigest=value.get("expected_ts_state_digest"))


database = STATE / "control.sqlite"
workspace = source["workspace_id"]
original = source["stage_marker"]["command_id"]
parts = source["stage_part_count"]
material = source["orphan_stage_material_json"]
assert source["visibility"] == "PRIVATE" and source["structure_mode"] == "STRUCTURED"
assert source["policy_v"] == 3 and source["pending_count"] == 0
assert source["stage_marker"]["part_index"] == 1 and parts >= 3
assert source["stage_applied"] is False and len(source["stage_parts"]) == parts
assert count(database, workspace) == 2 and count(database, workspace, original) == 0
assert isinstance(material, str) and material

native = STATE / "native-orphan"
owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native), allow_loopback_http=True)
node_config = dict(origin=origin, stateDir=str(native), allowLoopbackHttp=True)
config_file = STATE / "owner-config.json"
config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native), allow_loopback_http=True)))
material_file = STATE / "selected-material.json"
material_file.write_text(material)
initial = source_input()
inventory = owner.inspect_multipart_orphan_package_stage(**initial, material_json=material)
assert inventory["command_id"] == original
assert inventory["source_id"] == source["stage_marker"]["source_id"]
assert inventory["source_sha256"] == source["stage_marker"]["source_sha256"]
assert inventory["part_index"] == 1 and inventory["part_count"] == parts
assert inventory["status"] == "ORPHAN_NO_PACKET" and len(inventory["ts_state_digest"]) == 64
assert node_call(node_config, "inspect", input=node_input(initial), materialJson=material) == dict(ok=True, value=inventory)
inspect_file = STATE / "inspect.json"
inspect_file.write_text(json.dumps(initial))
assert cli(config_file, "owner-stage-multipart-orphan-inspect", inspect_file, material_file) == dict(ok=True, value=inventory)
assert owner.attachments() == [] and count(database, workspace) == 2

selected = dict(initial, selected_orphan_package_stage_command_id=original,
                expected_ts_state_digest=inventory["ts_state_digest"])
wrong = dict(selected, selected_orphan_package_stage_command_id="z" * 43)
wrong_result = node_call(node_config, "attach", input=node_input(wrong), materialJson=material)
assert wrong_result["ok"] is False and wrong_result["code"] == "SOURCE_UNRESOLVED"
assert owner.attachments() == [] and count(database, workspace) == 2
wrong = dict(selected, expected_ts_state_digest="0" * 64)
wrong_file = STATE / "wrong-digest.json"
wrong_file.write_text(json.dumps(wrong))
wrong_result = cli(config_file, "owner-stage-multipart-orphan-attach", wrong_file, material_file)
assert wrong_result["ok"] is False and wrong_result["value"]["code"] == "SOURCE_CHANGED"
assert owner.attachments() == [] and count(database, workspace) == 2
conflict = node_input(selected)
conflict["selectedPendingPackageStageCommandId"] = "z" * 43
bad = node_call(node_config, "attach", input=conflict, materialJson=material)
assert bad["ok"] is False and "select one pending or orphan" in bad["message"]
assert owner.attachments() == [] and count(database, workspace) == 2

attached = node_call(node_config, "attach", input=node_input(selected), materialJson=material)
assert attached["ok"] is True
restricted = attached["value"]
assert restricted["status"] == "ATTACHED_RESTRICTED"
assert restricted["orphan_package_stage_status"] == "ORPHAN_NO_PACKET"
assert restricted["orphan_package_stage_command_id"] == original
assert restricted["owner_actor_id"] == source["owner_actor_id"]
assert restricted["owner_key_id"] == source["owner_key_id"]
assert count(database, workspace) == 2 and owner.attachments() == [restricted]
attach_id = restricted["attach_id"]
archived = STATE / "archived-legacy-orphan"
shutil.move(str(STATE / "legacy-orphan"), str(archived))
for key in ("state_path", "pem_path", "intent_db_path"):
    assert not Path(source[key]).exists()
assert owner.read(workspace)["sequence"] == 2  # Authenticated online read.

barrier("POST", "arm")
blocked = subprocess.Popen([CLI, "secure", "owner-stage-orphan-replan", str(config_file),
                            attach_id, original, str(material_file)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    deadline = time.monotonic() + 120
    observed = None
    while time.monotonic() < deadline:
        observed = barrier("GET", "status")
        if observed["held"]:
            break
        assert blocked.poll() is None, "replan exited before later POST transport barrier"
        time.sleep(0.1)
    assert observed and observed["held"] and observed["post_count"] == 2
    assert len(observed["held_request_sha256"]) == 64
    assert count(database, workspace) == 3  # New part zero only; later POST is withheld.
finally:
    blocked.terminate()
    blocked.communicate(timeout=10)
    barrier("POST", "discard")
assert count(database, workspace) == 3
saved = owner.attachments()[0]  # Public protected local listing, fresh process next.
assert saved["status"] == "ATTACHED_RESTRICTED"
assert saved["orphan_replan_stage_id"] and saved["orphan_replan_command_id"]
new_stage_id = saved["orphan_replan_stage_id"]
assert new_stage_id != original
assert count(database, workspace, original) == 0

barrier("POST", "compare")
recovered = node_call(node_config, "replan", attachId=attach_id, originalCommandId=original)
assert recovered["ok"] or recovered["code"] == "ORPHAN_STAGE_UNRESOLVED"
complete = recovered["value"] if recovered["ok"] else None
assert barrier("GET", "status")["compared"], "saved later signed request changed on fresh retry"
fresh = peerwork.SecureOwnerWorkspaceClient(origin, str(native), allow_loopback_http=True)
for _ in range(8):
    if complete is not None and complete["status"] == "ATTACHED":
        break
    complete = fresh.replan_orphan_package_stage(attach_id, original)
assert complete["status"] == "ATTACHED"
assert complete["orphan_package_stage_status"] == "ORPHAN_REPLANNED"
assert complete["orphan_replan_stage_id"] == new_stage_id
assert count(database, workspace) == 2 + parts
assert count(database, workspace, original) == 0
assert node_call(node_config, "replan", attachId=attach_id, originalCommandId=original) == dict(ok=True, value=complete)
assert count(database, workspace) == 2 + parts
assert cli(config_file, "owner-attachments") == dict(ok=True, value=[complete])

read = fresh.read(workspace)
assert read["sequence"] == 2 + parts
rows = [row for row in read["objects"] if row["kind"] == "protocol_package_part"
        and row["value"]["source_id"] == source["stage_marker"]["source_id"]]
assert len(rows) == parts
for index, expected in enumerate(source["stage_parts"]):
    matching = [row for row in rows if row["id"] == expected["id"]]
    assert len(matching) == 1
    assert matching[0]["value"]["index"] == index
    assert matching[0]["value"]["sha256"] == expected["sha256"]

installer = fresh.private_package_installer(workspace)
instance_id = "z" * 43
started = installer.begin(new_stage_id, instance_id, "multipart-orphan-replan",
    grants_json=json.dumps([{"actor_id": source["owner_actor_id"],
        "actions": ["discussion.post"], "protocol_roles": ["CONTRIBUTOR"],
        "capabilities": ["POST"]}]))
begin_id = started["begin_command_id"]
progress = started
for _ in range(8):
    if progress["status"] == "ACCEPTED":
        break
    progress = installer.continue_install(begin_id)
assert progress["status"] == "ACCEPTED"
assert installer.installs()[0]["stage_id"] == new_stage_id
installed_read = fresh.read(workspace)
assert any(row["kind"] == "protocols" and row["id"] == progress["protocol_digest"]
           for row in installed_read["objects"])
assert any(row["kind"] == "instances" and row["id"] == instance_id
           and row["value"]["protocol_digest"] == progress["protocol_digest"]
           and row["value"]["origin_entrypoint"] == "multipart-orphan-replan"
           for row in installed_read["objects"])
after_install = count(database, workspace)
assert installer.continue_install(begin_id) == progress
assert count(database, workspace) == after_install
print(json.dumps({"mode": "orphan-index1", "workspace_id": workspace,
                  "status": complete["status"], "stage_id": new_stage_id,
                  "part_count": parts, "sequence": installed_read["sequence"],
                  "transport_digest_matched": True}), flush=True)
