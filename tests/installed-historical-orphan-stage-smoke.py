"""Installed, scripted Owner handoff of one genuine TS stage marker without a saved packet.

The original marker has no signed packet. A new, explicitly selected stage
can be recovered after its applied POST reply is lost. The caller explicitly pairs its protected TS files; this test does
not establish natural Agent workflow compliance or independent interface flows.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
LEGACY = Path(os.environ["PEERWORK_TEST_LEGACY_ROOT"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, name in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("tests/legacy-owner-source.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[name]
host_fixture = os.environ.get("PEERWORK_TEST_HOST_FIXTURE_JSON")
if host_fixture is None:
    assert subprocess.check_output(["git", "-C", str(LEGACY), "rev-parse", "HEAD"], text=True).strip() == os.environ["PEERWORK_TEST_LEGACY_COMMIT"]
    assert subprocess.run(["git", "-C", str(LEGACY), "diff", "--quiet", "HEAD", "--", "src", "package.json", "package-lock.json"], check=False).returncode == 0
    STATE.mkdir(mode=0o700, parents=True, exist_ok=False)
else:
    assert STATE.is_dir() and STATE.stat().st_mode & 0o077 == 0


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'inspect': result = await owner.inspectOrphanPackageStage(value.input); break;
    case 'attach': result = await owner.attach(value.input); break;
    case 'replan': result = await owner.replanOrphanPackageStage(value.attachId, value.commandId, value.materialJson); break;
    case 'attachments': result = await owner.attachments(); break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => console.log(JSON.stringify({ok:false,code:error.code,message:error.message})));
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_VALUES=json.dumps(values),
               PEERWORK_TEST_OPERATION=operation)
    output = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert output.returncode == 0, output.stderr[-800:]
    return json.loads(output.stdout)


def cli(config_file, verb, *arguments):
    output = subprocess.run([CLI, "secure", verb, str(config_file),
                             *(str(argument) for argument in arguments)],
                            capture_output=True, text=True, timeout=120)
    return dict(ok=output.returncode == 0,
                value=json.loads(output.stdout if output.returncode == 0 else output.stderr))


def source_input(source):
    return dict(workspace_id=source["workspace_id"],
                protected_ts_state_path=source["state_path"],
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


def count_command(database, workspace, command):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?",
            (workspace, command)).fetchone()[0]


def count_workspace(database, workspace):
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=?",
            (workspace,)).fetchone()[0]


server = None if host_fixture else subprocess.Popen(
    [NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    if server is None:
        fixture = json.loads(Path(host_fixture).read_text())
        origin = fixture["origin"]
        source = fixture["source"]
    else:
        line = server.stdout.readline()
        assert line, f"service did not start: {server.stderr.read()[-800:]}"
        origin = json.loads(line)["origin"]
    database = STATE / "control.sqlite"
    old_dir = STATE / "legacy-orphan"
    if server is not None:
        produced = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
                                   origin, str(old_dir), str(LEGACY), "stage-marker-orphan"],
                                  cwd=SOURCE, capture_output=True, text=True, timeout=120)
        assert produced.returncode == 0, produced.stderr[-800:]
        source = json.loads(produced.stdout)
    assert source["policy_v"] == 3 and source["visibility"] == "PRIVATE"
    assert source["structure_mode"] == "STRUCTURED" and source["stage_part_count"] == 1
    assert source["pending_count"] == 0 and source["stage_applied"] is False
    assert source["orphan_stage_material_json"]
    marker = source["stage_marker"]
    command = marker["command_id"]
    workspace = source["workspace_id"]
    assert count_workspace(database, workspace) == 1
    assert count_command(database, workspace, command) == 0

    native_dir = STATE / "native-orphan"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native_dir), allow_loopback_http=True)
    config = dict(origin=origin, stateDir=str(native_dir), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native_dir),
                                           allow_loopback_http=True)))
    input_value = source_input(source)
    inventory = owner.inspect_orphan_package_stage(**input_value)
    assert inventory == dict(ts_state_digest=inventory["ts_state_digest"],
        command_id=command, source_id=marker["source_id"],
        source_sha256=marker["source_sha256"], source_sequence=1,
        status="ORPHAN_NO_PACKET")
    assert len(inventory["ts_state_digest"]) == 64
    assert node_call(config, "inspect", input=node_input(input_value)) == dict(ok=True, value=inventory)
    inspect_file = STATE / "orphan-inspect.json"
    inspect_file.write_text(json.dumps(input_value))
    assert cli(config_file, "owner-stage-orphan-inspect", inspect_file) == dict(ok=True, value=inventory)
    assert owner.attachments() == [] and count_workspace(database, workspace) == 1

    selected = dict(input_value, selected_orphan_package_stage_command_id=command)
    try:
        owner.attach(**selected)
    except ValueError as error:
        assert "inspected TS state digest" in str(error)
    else:
        raise AssertionError("orphan attach without inspected digest was accepted")
    assert owner.attachments() == []
    selected["expected_ts_state_digest"] = "0" * 64
    wrong_digest_file = STATE / "wrong-digest.json"
    wrong_digest_file.write_text(json.dumps(selected))
    wrong_digest = cli(config_file, "owner-attach", wrong_digest_file)
    assert wrong_digest["ok"] is False and wrong_digest["value"]["code"] == "SOURCE_CHANGED"
    assert owner.attachments() == []
    selected["expected_ts_state_digest"] = inventory["ts_state_digest"]
    selected["selected_orphan_package_stage_command_id"] = "z" * 43
    wrong_id = node_call(config, "attach", input=node_input(selected))
    assert wrong_id["ok"] is False and wrong_id["code"] == "SOURCE_UNRESOLVED"
    assert owner.attachments() == [] and count_workspace(database, workspace) == 1

    selected["selected_orphan_package_stage_command_id"] = command
    attached = node_call(config, "attach", input=node_input(selected))
    assert attached["ok"] is True
    restricted = attached["value"]
    assert restricted["provenance"] == "HISTORICAL_TS_OWNER"
    assert restricted["status"] == "ATTACHED_RESTRICTED"
    assert restricted["workspace_id"] == workspace
    assert restricted["owner_actor_id"] == source["owner_actor_id"]
    assert restricted["owner_key_id"] == source["owner_key_id"]
    assert restricted["orphan_package_stage_command_id"] == command
    assert restricted["orphan_package_stage_status"] == "ORPHAN_NO_PACKET"
    assert restricted["sequence"] == 1 and count_workspace(database, workspace) == 1
    attach_id = restricted["attach_id"]
    assert owner.attachments() == [restricted]
    before_read = owner.read(workspace)
    assert before_read["sequence"] == 1
    wiki = next(row["id"] for row in before_read["objects"]
                if row["kind"] == "instances" and row["value"]["origin_entrypoint"] == "wiki")
    for attempt, error_type in (
        (lambda: owner.private_actions(workspace).submit(
            "wiki.create", wiki, {"title": "Blocked", "body": "No stale write"}),
         peerwork.SecureActionError),
        (lambda: owner.private_package_installer(workspace).begin(
            command, "z" * 43, "wiki", grants_json="[]"),
         peerwork.PrivatePackageInstallError),
        (lambda: owner.submit_format_transition(workspace, "RAISE_PRIVATE_CEILING_TWO"),
         peerwork.OwnerWorkspaceError),
    ):
        try:
            attempt()
        except error_type as error:
            assert error.code == "ORPHAN_STAGE_UNRESOLVED"
        else:
            raise AssertionError("restricted orphan attachment permitted a signed operation")
        assert count_workspace(database, workspace) == 1
        assert owner.attachments() == [restricted]

    material = source["orphan_stage_material_json"]
    try:
        owner.replan_orphan_package_stage(attach_id, command, "{}")
    except peerwork.OwnerWorkspaceError as error:
        assert error.code == "SOURCE_UNRESOLVED"
    else:
        raise AssertionError("mismatched new material was accepted")
    assert count_workspace(database, workspace) == 1
    assert owner.attachments() == [restricted]
    archived = STATE / "archived-orphan"
    shutil.move(str(old_dir), str(archived))
    for path in (source["state_path"], source["pem_path"], source["intent_db_path"]):
        assert not Path(path).exists()
    assert owner.read(workspace)["sequence"] == 1  # authenticated online service read
    assert cli(config_file, "owner-attachments") == dict(ok=True, value=[restricted])

    material_file = STATE / "new-material.json"
    material_file.write_text(material)
    request = urllib.request.Request(origin + "__test/drop-next-post", data=b"{}", method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200
    lost = cli(config_file, "owner-stage-orphan-replan", attach_id, command, material_file)
    assert lost["ok"] is False and lost["value"]["code"] == "ORPHAN_STAGE_UNRESOLVED"
    assert count_workspace(database, workspace) == 2
    assert count_command(database, workspace, command) == 0
    saved = owner.attachments()[0]
    assert saved["status"] == "ATTACHED_RESTRICTED"
    assert saved["orphan_package_stage_status"] == "REPLAN_SELECTED_UNVERIFIED"
    new_id = saved["orphan_replan_command_id"]
    stage_id = saved["orphan_replan_stage_id"]
    assert new_id and stage_id and new_id != command
    assert count_command(database, workspace, new_id) == 1
    assert count_command(database, workspace, command) == 0
    final = owner.replan_orphan_package_stage(attach_id, command)
    assert final["status"] == "ATTACHED" and final["sequence"] == 2
    assert final["orphan_package_stage_status"] == "ORPHAN_REPLANNED"
    assert final["orphan_package_stage_command_id"] == command
    assert final["orphan_replan_command_id"] == new_id
    assert final["orphan_replan_stage_id"] == stage_id
    assert count_workspace(database, workspace) == 2
    read = owner.read(workspace)
    assert read["sequence"] == 2
    assert any(row["kind"] == "protocol_package_part" and row["id"] == marker["part_id"]
               and row["value"]["source_id"] == marker["source_id"]
               and row["value"]["sha256"] == marker["part_sha256"]
               for row in read["objects"])
    repeated = node_call(config, "replan", attachId=attach_id, commandId=command)
    assert repeated == dict(ok=True, value=final)
    wrong = cli(config_file, "owner-stage-orphan-replan", attach_id, "z" * 43)
    assert wrong["ok"] is False and wrong["value"]["code"] == "ATTACH_CONFLICT"
    assert count_workspace(database, workspace) == 2
    assert owner.attachments() == [final]
    print(json.dumps(dict(result="pass", workspace_id=workspace,
        original_command_id=command, new_command_id=new_id, source_id=marker["source_id"],
        stage_id=stage_id, sequence=read["sequence"], commits=2)), flush=True)
finally:
    if server is not None:
        server.terminate()
        server.wait(timeout=10)
