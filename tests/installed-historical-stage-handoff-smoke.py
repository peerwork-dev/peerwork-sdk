"""Installed, scripted Owner handoff of one genuine saved TS package-stage packet.

The two fixture modes distinguish an applied reply loss from a packet saved
before POST. The caller explicitly pairs its protected TS files; this test does
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
assert subprocess.check_output(["git", "-C", str(LEGACY), "rev-parse", "HEAD"], text=True).strip() == os.environ["PEERWORK_TEST_LEGACY_COMMIT"]
assert subprocess.run(["git", "-C", str(LEGACY), "diff", "--quiet", "HEAD", "--", "src", "package.json", "package-lock.json"], check=False).returncode == 0
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'inspect': result = await owner.inspectPendingPackageStage(value.input); break;
    case 'attach': result = await owner.attach(value.input); break;
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


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    database = STATE / "control.sqlite"
    for name, mode, applied in (
        ("applied", "stage-marker-pending", True),
        ("before", "stage-marker-before-post", False),
    ):
        old_dir = STATE / ("legacy-" + name)
        produced = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
                                   origin, str(old_dir), str(LEGACY), mode],
                                  cwd=SOURCE, capture_output=True, text=True, timeout=120)
        assert produced.returncode == 0, produced.stderr[-800:]
        source = json.loads(produced.stdout)
        assert source["policy_v"] == 3 and source["visibility"] == "PRIVATE"
        assert source["structure_mode"] == "STRUCTURED" and source["stage_part_count"] == 1
        assert source["pending_count"] == 1
        marker = source["stage_marker"]
        command = marker["command_id"]
        workspace = source["workspace_id"]
        assert source["pending_command_id"] == command
        assert count_command(database, workspace, command) == int(applied)
        native_dir = STATE / ("native-" + name)
        owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native_dir), allow_loopback_http=True)
        config = dict(origin=origin, stateDir=str(native_dir), allowLoopbackHttp=True)
        config_file = STATE / ("config-" + name + ".json")
        config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native_dir),
                                               allow_loopback_http=True)))
        input_value = source_input(source)
        inventory = owner.inspect_pending_package_stage(**input_value)
        assert inventory["command_id"] == command
        assert inventory["source_id"] == marker["source_id"]
        assert inventory["source_sha256"] == marker["source_sha256"]
        assert inventory["source_sequence"] == 1
        assert inventory["status"] == ("APPLIED_IN_SIGNED_REPLAY" if applied else "PENDING_UNRESOLVED")
        assert len(inventory["ts_state_digest"]) == 64
        node_inventory = node_call(config, "inspect", input=node_input(input_value))
        assert node_inventory == dict(ok=True, value=inventory)
        input_file = STATE / ("inspect-" + name + ".json")
        input_file.write_text(json.dumps(input_value))
        assert cli(config_file, "owner-stage-inspect", input_file) == dict(ok=True, value=inventory)
        assert owner.attachments() == []
        assert count_command(database, workspace, command) == int(applied)

        try:
            owner.attach(**dict(input_value, selected_pending_package_stage_command_id=command))
        except ValueError as error:
            assert "inspected TS state digest" in str(error)
        else:
            raise AssertionError("selected stage without inspected digest was accepted")
        assert owner.attachments() == []
        selected = dict(input_value, selected_pending_package_stage_command_id=command,
                        expected_ts_state_digest="0" * 64)
        wrong_file = STATE / ("wrong-digest-" + name + ".json")
        wrong_file.write_text(json.dumps(selected))
        wrong = cli(config_file, "owner-attach", wrong_file)
        assert wrong["ok"] is False and wrong["value"]["code"] == "SOURCE_UNRESOLVED"
        assert owner.attachments() == []
        selected["expected_ts_state_digest"] = inventory["ts_state_digest"]
        selected["selected_pending_package_stage_command_id"] = "z" * 43
        wrong_id = node_call(config, "attach", input=node_input(selected))
        assert wrong_id["ok"] is False and wrong_id["code"] == "SOURCE_UNRESOLVED"
        assert owner.attachments() == []
        assert count_command(database, workspace, command) == int(applied)

        selected["selected_pending_package_stage_command_id"] = command
        attached = node_call(config, "attach", input=node_input(selected))
        assert attached["ok"] is True
        result = attached["value"]
        assert result["provenance"] == "HISTORICAL_TS_OWNER"
        assert result["workspace_id"] == workspace
        assert result["owner_actor_id"] == source["owner_actor_id"]
        assert result["owner_key_id"] == source["owner_key_id"]
        assert result["pending_package_stage_command_id"] == command
        assert result["status"] == ("ATTACHED" if applied else "ATTACHED_RESTRICTED")
        assert result["pending_package_stage_status"] == ("ACCEPTED" if applied else "PENDING_UNRESOLVED")
        assert count_command(database, workspace, command) == int(applied)
        attach_id = result["attach_id"]
        assert owner.attachments() == [result]
        before_read = owner.read(workspace)
        assert before_read["sequence"] == (2 if applied else 1)
        if not applied:
            before_restricted = count_workspace(database, workspace)
            wiki = next(row["id"] for row in before_read["objects"]
                        if row["kind"] == "instances"
                        and row["value"]["origin_entrypoint"] == "wiki")
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
                    assert error.code == "VERIFICATION_FAILED"
                else:
                    raise AssertionError("restricted attachment permitted a signed operation")
                assert count_workspace(database, workspace) == before_restricted
                assert owner.attachments() == [result]

        archived = STATE / ("archived-" + name)
        shutil.move(str(old_dir), str(archived))
        for path in (source["state_path"], source["pem_path"], source["intent_db_path"]):
            assert not Path(path).exists()
        assert owner.read(workspace)["sequence"] == (2 if applied else 1)
        assert cli(config_file, "owner-attachments") == dict(ok=True, value=[result])
        recovered = cli(config_file, "owner-stage-recover", attach_id, command)
        assert recovered["ok"] is True
        final = recovered["value"]
        assert final["status"] == "ATTACHED" and final["pending_package_stage_status"] == "ACCEPTED"
        assert final["pending_package_stage_command_id"] == command
        assert count_command(database, workspace, command) == 1
        read = owner.read(workspace)
        assert read["sequence"] == 2
        assert any(row["kind"] == "protocol_package_part"
                   and row["id"] == marker["part_id"]
                   and row["value"]["source_id"] == marker["source_id"]
                   and row["value"]["sha256"] == marker["part_sha256"]
                   for row in read["objects"])
        repeated = node_call(config, "recover", attachId=attach_id, commandId=command)
        assert repeated == dict(ok=True, value=final)
        assert count_command(database, workspace, command) == 1
        assert owner.attachments() == [final]
        print(json.dumps(dict(mode=name, workspace_id=workspace, command_id=command,
                              source_id=marker["source_id"], status=final["status"],
                              sequence=read["sequence"], exact_commits=1)), flush=True)
finally:
    server.terminate()
    server.wait(timeout=10)
