"""Scripted installed historical Owner import of selected current-client kernel JWS.

The TypeScript source paths are caller-declared protected files. Service SQLite
queries below are task-local test oracles, not SDK APIs or source-state reads.
This is a mixed-interface business gate, not natural Agent workflow evidence.
"""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
REFERENCE = Path(os.environ["PEERWORK_TEST_REFERENCE_ROOT"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_create.rs", "PEERWORK_TEST_OWNER_SOURCE_SHA256"),
    ("tests/historical-kernel-pending-source.mjs", "PEERWORK_TEST_KERNEL_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def source_input(value):
    return dict(workspace_id=value["workspace_id"],
                protected_ts_state_path=value["state_path"],
                protected_ts_intent_db_path=value["intent_db_path"],
                protected_owner_pkcs8_path=value["pem_path"],
                expected_owner_actor_id=value["owner_actor_id"],
                expected_owner_key_id=value["owner_key_id"])


def node_input(value):
    return dict(workspaceId=value["workspace_id"],
                protectedTsStatePath=value["protected_ts_state_path"],
                protectedTsIntentDbPath=value["protected_ts_intent_db_path"],
                protectedOwnerPkcs8Path=value["protected_owner_pkcs8_path"],
                expectedOwnerActorId=value["expected_owner_actor_id"],
                expectedOwnerKeyId=value["expected_owner_key_id"],
                kernelPendingCommandIds=value.get("kernel_pending_command_ids", []),
                expectedKernelIntentDbDigest=value.get("expected_kernel_intent_db_digest"))


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'inspect': result = await owner.inspectKernelPending(value.input); break;
    case 'attach': result = await owner.attach(value.input); break;
    case 'status': result = await owner.kernelCommandStatus(value.attachId); break;
    case 'recover': result = await owner.recoverKernelCommand(value.attachId, value.commandId); break;
    case 'attachments': result = await owner.attachments(); break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => console.log(JSON.stringify({ok:false,code:error.code,message:error.message})));
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUES=json.dumps(values))
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def cli(config_file, verb, *args):
    result = subprocess.run([CLI, "secure", verb, str(config_file), *(str(a) for a in args)],
                            capture_output=True, text=True, timeout=120)
    return dict(ok=result.returncode == 0,
                value=json.loads(result.stdout if result.returncode == 0 else result.stderr))


def oracle_count(query, arg):
    db = sqlite3.connect("file:" + str(STATE / "control.sqlite") + "?mode=ro", uri=True)
    try:
        return db.execute(query, (arg,)).fetchone()[0]
    finally:
        db.close()


def command_count(command_id):
    return oracle_count("SELECT count(*) FROM commands WHERE command_id=?", command_id)


def effect_count(workspace_id):
    return oracle_count("SELECT count(*) FROM events WHERE workspace_id=? AND kind='admin.view.set'", workspace_id)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal",
                         PEERWORK_TEST_HISTORICAL_ATTACH="1"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    for mode, applied in (("applied-loss-global", True), ("pre-send-global", False)):
        source_dir = STATE / ("source-" + mode)
        fixture = subprocess.run([NODE, str(SOURCE / "tests/historical-kernel-pending-source.mjs"),
                                  origin, str(source_dir), str(REFERENCE), mode],
                                 cwd=SOURCE, capture_output=True, text=True, timeout=120)
        assert fixture.returncode == 0, fixture.stderr[-800:]
        source = json.loads(fixture.stdout)
        assert source["policy_v"] == 1 and source["policy_visibility"] == "PUBLIC"
        assert source["pending_count"] == 3
        assert source["dropped_responses"] == int(applied)
        selected = source["selected_command_id"]
        unrelated = source["unrelated_command_id"]
        global_id = source["global_command_id"]
        workspace_id = source["workspace_id"]
        assert len({selected, unrelated, global_id}) == 3
        assert command_count(selected) == int(applied)
        assert command_count(unrelated) == command_count(global_id) == 0
        assert effect_count(workspace_id) == int(applied)

        native_root = STATE / ("native-" + mode)
        owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native_root), allow_loopback_http=True)
        config = dict(origin=origin, stateDir=str(native_root), allowLoopbackHttp=True)
        config_file = STATE / ("config-" + mode + ".json")
        config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native_root),
                                               allow_loopback_http=True)))
        base = source_input(source)
        inventory = owner.inspect_kernel_pending(**base)
        assert len(inventory["commands"]) == 1
        assert inventory["commands"][0]["command_id"] == selected
        assert inventory["commands"][0]["intent_digest"] == source["selected_intent_digest"]
        assert inventory["retained_other_pending_count"] == 1
        assert inventory["retained_nonworkspace_pending_count"] == 1
        assert node_call(config, "inspect", input=node_input(base)) == dict(ok=True, value=inventory)
        inspect_file = STATE / ("inspect-" + mode + ".json")
        inspect_file.write_text(json.dumps(base))
        assert cli(config_file, "owner-kernel-inspect", inspect_file) == dict(ok=True, value=inventory)

        # Selection is explicit and tied to the inspected complete SQLite snapshot.
        selected_input = dict(base, kernel_pending_command_ids=[selected],
                              expected_kernel_intent_db_digest=inventory["intent_db_digest"])
        try:
            owner.attach(**dict(base, kernel_pending_command_ids=[selected]))
        except ValueError as error:
            assert "inspected intent DB digest" in str(error)
        else:
            raise AssertionError("selected command lacked the inspected snapshot digest")
        wrong = dict(selected_input, expected_kernel_intent_db_digest="0" * 64)
        try:
            owner.attach(**wrong)
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == "SOURCE_CHANGED"
        else:
            raise AssertionError("wrong source snapshot was attached")
        assert owner.attachments() == []
        assert effect_count(workspace_id) == int(applied)
        attached = node_call(config, "attach", input=node_input(selected_input))
        assert attached["ok"] is True, attached
        row = attached["value"]
        assert row["provenance"] == "HISTORICAL_TS_OWNER" and row["status"] == "ATTACHED"
        assert row["workspace_id"] == workspace_id
        assert row["selected_kernel_count"] == 1 and row["retained_other_kernel_count"] == 2
        attach_id = row["attach_id"]
        assert owner.attachments() == [row]

        # Source exports are no longer available after the protected import.
        source_dir.rename(STATE / ("archived-" + mode))
        local = owner.kernel_command_status(attach_id)
        assert len(local) == 1 and local[0]["command_id"] == selected
        assert local[0]["intent_digest"] == source["selected_intent_digest"]
        assert local[0]["status"] == "PENDING"
        assert cli(config_file, "owner-kernel-status", attach_id) == dict(ok=True, value=local)
        recovered = cli(config_file, "owner-kernel-recover", attach_id, selected)
        assert recovered["ok"] is True, recovered
        status = recovered["value"]
        assert status["command_id"] == selected
        assert status["status"] == ("ACCEPTED" if applied else "RETAINED_UNRESOLVED")
        assert status["last_http_status"] == (None if applied else 409)
        assert owner.kernel_command_status(attach_id) == [status]
        assert node_call(config, "status", attachId=attach_id) == dict(ok=True, value=[status])
        assert command_count(selected) == int(applied)
        assert command_count(unrelated) == command_count(global_id) == 0
        assert effect_count(workspace_id) == int(applied)
        if applied:
            repeated = node_call(config, "recover", attachId=attach_id, commandId=selected)
            assert repeated == dict(ok=True, value=status)
            assert command_count(selected) == effect_count(workspace_id) == 1
        print(json.dumps(dict(mode=mode, workspace_id=workspace_id,
                              attach_id=attach_id, selected_command_id=selected,
                              status=status["status"], effect_count=effect_count(workspace_id))))
finally:
    server.terminate()
    server.wait(timeout=10)
