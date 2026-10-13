"""Installed, scripted Owner handoff of a saved nonzero TS package-stage part.

The two f828 fixture modes distinguish an applied reply loss from a packet
saved before POST. Complete source material is caller-selected, then verified
against the original saved packet and signed prefix. This is a mixed-interface
scripted test, not natural Agent workflow or independent interface coverage.
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
    case 'inspect': result = await owner.inspectPendingMultipartPackageStage(value.input, value.materialJson); break;
    case 'attach': result = await owner.attachPendingMultipartPackageStage(value.input, value.materialJson); break;
    case 'recover': result = await owner.recoverPendingPackageStage(value.attachId, value.commandId); break;
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
                selectedPendingPackageStageCommandId=value.get("selected_pending_package_stage_command_id"),
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


def material_file(name, material):
    path = STATE / name
    path.write_text(material)
    return path


server = None if host_fixture else subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    if server is None:
        fixture = json.loads(Path(host_fixture).read_text())
        origin = fixture["origin"]
        assert set(fixture["sources"]) == {"applied", "before"}
    else:
        line = server.stdout.readline()
        assert line, f"service did not start: {server.stderr.read()[-800:]}"
        origin = json.loads(line)["origin"]
    database = STATE / "control.sqlite"
    for name, mode, applied, initial_count in (
        ("applied", "stage-marker-multipart-pending-applied-index1", True, 3),
        ("before", "stage-marker-multipart-pending-before-post-index1", False, 2),
    ):
        old_dir = STATE / ("legacy-" + name)
        if server is None:
            source = fixture["sources"][name]
        else:
            produced = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
                                       origin, str(old_dir), str(LEGACY), mode],
                                      cwd=SOURCE, capture_output=True, text=True, timeout=120)
            assert produced.returncode == 0, produced.stderr[-800:]
            source = json.loads(produced.stdout)
        assert source["policy_v"] == 3 and source["visibility"] == "PRIVATE"
        assert source["structure_mode"] == "STRUCTURED" and source["stage_part_count"] >= 3
        assert source["pending_count"] == 1
        marker = source["stage_marker"]
        assert marker["part_index"] == 1
        command = marker["command_id"]
        workspace = source["workspace_id"]
        assert source["pending_command_id"] == command
        assert count_command(database, workspace, command) == int(applied)
        assert count_workspace(database, workspace) == initial_count
        material = source["pending_stage_material_json"]
        alternate_material = source["wrong_pending_stage_material_json"]
        assert isinstance(material, str) and isinstance(alternate_material, str)
        assert material != alternate_material
        material_path = material_file("material-" + name + ".json", material)
        native_dir = STATE / ("native-" + name)
        owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native_dir), allow_loopback_http=True)
        config = dict(origin=origin, stateDir=str(native_dir), allowLoopbackHttp=True)
        config_file = STATE / ("config-" + name + ".json")
        config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native_dir),
                                               allow_loopback_http=True)))
        input_value = source_input(source)
        inventory = owner.inspect_pending_multipart_package_stage(
            **input_value, material_json=material)
        assert inventory["command_id"] == command
        assert inventory["source_id"] == marker["source_id"]
        assert inventory["source_sha256"] == marker["source_sha256"]
        assert inventory["source_sequence"] == 1
        assert inventory["part_index"] == 1
        assert inventory["part_count"] == source["stage_part_count"]
        assert inventory["original_commit_hash"] == source["pending_commit_hash"]
        assert inventory["status"] == ("APPLIED_IN_SIGNED_REPLAY" if applied else "PENDING_UNRESOLVED")
        assert len(inventory["ts_state_digest"]) == 64
        node_inventory = node_call(config, "inspect", input=node_input(input_value), materialJson=material)
        assert node_inventory == dict(ok=True, value=inventory)
        input_file = STATE / ("inspect-" + name + ".json")
        input_file.write_text(json.dumps(input_value))
        assert cli(config_file, "owner-stage-multipart-inspect", input_file, material_path) == dict(ok=True, value=inventory)
        assert owner.attachments() == []
        assert count_command(database, workspace, command) == int(applied)

        try:
            owner.attach_pending_multipart_package_stage(
                **input_value, material_json=material,
                selected_pending_package_stage_command_id=command)
        except TypeError as error:
            assert "expected_ts_state_digest" in str(error)
        else:
            raise AssertionError("selected stage without inspected digest was accepted")
        assert owner.attachments() == []
        selected = dict(input_value, selected_pending_package_stage_command_id=command,
                        expected_ts_state_digest="0" * 64)
        wrong_file = STATE / ("wrong-digest-" + name + ".json")
        wrong_file.write_text(json.dumps(selected))
        wrong = cli(config_file, "owner-stage-multipart-attach", wrong_file, material_path)
        assert wrong["ok"] is False and wrong["value"]["code"] == "SOURCE_CHANGED"
        assert owner.attachments() == []
        selected["expected_ts_state_digest"] = inventory["ts_state_digest"]
        selected["selected_pending_package_stage_command_id"] = "z" * 43
        wrong_id = node_call(config, "attach", input=node_input(selected), materialJson=material)
        assert wrong_id["ok"] is False and wrong_id["code"] == "SOURCE_UNRESOLVED"
        assert owner.attachments() == []
        assert count_workspace(database, workspace) == initial_count

        conflict = node_input(dict(selected, selected_pending_package_stage_command_id=command))
        conflict["selectedOrphanPackageStageCommandId"] = "z" * 43
        refused = node_call(config, "attach", input=conflict, materialJson=material)
        assert refused["ok"] is False and "select one pending or orphan" in refused["message"]
        assert owner.attachments() == []
        assert count_workspace(database, workspace) == initial_count

        selected["selected_pending_package_stage_command_id"] = command
        try:
            owner.attach_pending_multipart_package_stage(
                **input_value, material_json=alternate_material,
                selected_pending_package_stage_command_id=command,
                expected_ts_state_digest=inventory["ts_state_digest"])
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == "SOURCE_UNRESOLVED"
        else:
            raise AssertionError("different compiled package material was accepted")
        assert owner.attachments() == []
        assert count_workspace(database, workspace) == initial_count

        attached = node_call(config, "attach", input=node_input(selected), materialJson=material)
        assert attached["ok"] is True
        result = attached["value"]
        assert result["provenance"] == "HISTORICAL_TS_OWNER"
        assert result["workspace_id"] == workspace
        assert result["owner_actor_id"] == source["owner_actor_id"]
        assert result["owner_key_id"] == source["owner_key_id"]
        assert result["pending_package_stage_command_id"] == command
        assert result["status"] == "ATTACHED_RESTRICTED"
        assert result["pending_package_stage_status"] == ("PART_ACCEPTED_CONTINUATION_PENDING" if applied else "PENDING_UNRESOLVED")
        stage_id = result["pending_package_stage_id"]
        assert isinstance(stage_id, str) and len(stage_id) == 43
        assert count_command(database, workspace, command) == int(applied)
        attach_id = result["attach_id"]
        assert owner.attachments() == [result]
        before_read = owner.read(workspace)
        assert before_read["sequence"] == initial_count
        before_restricted = count_workspace(database, workspace)
        wiki = next(row["id"] for row in before_read["objects"]
                    if row["kind"] == "instances"
                    and row["value"]["origin_entrypoint"] == "wiki")
        # The Owner selector rejects before BEGIN's stage-ID lookup; this
        # token-shaped command is not yet a selectable native staged source.
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
                assert error.code == "PENDING_PACKAGE_STAGE_UNRESOLVED"
            else:
                raise AssertionError("restricted attachment permitted a signed operation")
            assert count_workspace(database, workspace) == before_restricted
            assert owner.attachments() == [result]
        absent = "z" * 43
        assert absent != workspace
        try:
            owner.private_actions(absent).submit(
                "wiki.create", wiki, {"title": "Absent", "body": "No workspace"})
        except peerwork.SecureActionError as error:
            assert error.code == "NOT_FOUND"
        else:
            raise AssertionError("absent workspace unexpectedly selected an Owner")
        assert count_workspace(database, workspace) == before_restricted
        assert owner.attachments() == [result]

        archived = STATE / ("archived-" + name)
        shutil.move(str(old_dir), str(archived))
        for path in (source["state_path"], source["pem_path"], source["intent_db_path"]):
            assert not Path(path).exists()
        assert owner.read(workspace)["sequence"] == initial_count
        assert cli(config_file, "owner-attachments") == dict(ok=True, value=[result])
        final = None
        for _ in range(8):
            recovered = cli(config_file, "owner-stage-recover", attach_id, command)
            if recovered["ok"]:
                final = recovered["value"]
                break
            assert recovered["value"]["code"] == "PENDING_PACKAGE_STAGE_UNRESOLVED"
            assert owner.attachments()[0]["status"] == "ATTACHED_RESTRICTED"
        assert final is not None, "bounded exact-ID recovery did not verify full signed SOURCE"
        assert final["status"] == "ATTACHED" and final["pending_package_stage_status"] == "ACCEPTED"
        assert final["pending_package_stage_command_id"] == command
        assert final["pending_package_stage_id"] == stage_id
        assert count_command(database, workspace, command) == 1
        complete_count = 1 + source["stage_part_count"]
        assert count_workspace(database, workspace) == complete_count
        read = owner.read(workspace)
        assert read["sequence"] == complete_count
        parts = [row for row in read["objects"]
                 if row["kind"] == "protocol_package_part"
                 and row["value"]["source_id"] == marker["source_id"]]
        assert len(parts) == source["stage_part_count"]
        for index, expected in enumerate(source["stage_parts"]):
            matching = [row for row in parts if row["id"] == expected["id"]]
            assert len(matching) == 1
            assert matching[0]["value"]["index"] == index
            assert matching[0]["value"]["source_id"] == marker["source_id"]
            assert matching[0]["value"]["sha256"] == expected["sha256"]
        repeated = node_call(config, "recover", attachId=attach_id, commandId=command)
        assert repeated == dict(ok=True, value=final)
        assert count_workspace(database, workspace) == complete_count
        assert count_command(database, workspace, command) == 1
        assert owner.attachments() == [final]

        installer = owner.private_package_installer(workspace)
        instance_id = "z" * 43
        begin = installer.begin(stage_id, instance_id, "imported-discussion",
            grants_json=json.dumps([{"actor_id": source["owner_actor_id"],
                "actions": ["discussion.post"], "protocol_roles": ["CONTRIBUTOR"],
                "capabilities": ["POST"]}]))
        begin_id = begin["begin_command_id"]
        assert installer.installs()[0]["stage_id"] == stage_id
        progress = begin
        for _ in range(8):
            if progress["status"] == "ACCEPTED":
                break
            progress = installer.continue_install(begin_id)
        assert progress["status"] == "ACCEPTED"
        assert count_workspace(database, workspace) > complete_count
        installed_read = owner.read(workspace)  # authenticated online service read
        objects = installed_read["objects"]
        assert any(row["kind"] == "protocols" and row["id"] == progress["protocol_digest"]
                   for row in objects)
        assert any(row["kind"] == "instances" and row["id"] == instance_id
                   and row["value"]["protocol_digest"] == progress["protocol_digest"]
                   and row["value"]["origin_entrypoint"] == "imported-discussion"
                   for row in objects)
        print(json.dumps(dict(mode=name, workspace_id=workspace, command_id=command,
                              source_id=marker["source_id"], status=final["status"],
                              stage_id=stage_id, sequence=installed_read["sequence"],
                              stage_part_count=source["stage_part_count"])), flush=True)
finally:
    if server is not None:
        server.terminate()
        server.wait(timeout=10)
