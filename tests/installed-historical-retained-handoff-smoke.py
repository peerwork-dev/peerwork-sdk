"""Scripted installed legacy Owner retain → ENFORCE upgrade → encrypted use.

The test-created TS state, PEM and SQLite intent store are explicitly paired
by the caller. This is a mixed-interface business path, not an Agent run.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
LEGACY = Path(os.environ["PEERWORK_TEST_LEGACY_ROOT"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_create.rs", "PEERWORK_TEST_OWNER_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_format_transition.rs", "PEERWORK_TEST_FORMAT_SOURCE_SHA256"),
    ("tests/legacy-owner-source.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
assert subprocess.check_output(["git", "-C", str(LEGACY), "rev-parse", "HEAD"],
                               text=True).strip() == os.environ["PEERWORK_TEST_LEGACY_COMMIT"]
assert subprocess.run(["git", "-C", str(LEGACY), "diff", "--quiet", "HEAD", "--",
                       "src", "package.json", "package-lock.json"], check=False).returncode == 0
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def request_json(origin, path, *, post=False):
    request = urllib.request.Request(origin + path, data=b"{}" if post else None,
                                     method="POST" if post else "GET")
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def counts(origin):
    return request_json(origin, "__test/secure-counts")["commits"]


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const input = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'retain': result = await owner.retainPendingAction(input.attachId, input.commandId); break;
    case 'format': result = await owner.submitFormatTransition(input); break;
    case 'history': result = await owner.attachments(); break;
    case 'read': result = await owner.read(input.workspaceId); break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => console.log(JSON.stringify({ok:false,code:error.code,message:error.message})));
'''
    result = subprocess.run([NODE, "-e", code], env=dict(os.environ,
        PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
        PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
        PEERWORK_TEST_OPERATION=operation,
        PEERWORK_TEST_VALUES=json.dumps(values)), capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def cli(config_file, verb, *args):
    result = subprocess.run([CLI, "secure", verb, str(config_file), *(str(arg) for arg in args)],
                            capture_output=True, text=True, timeout=120)
    return dict(ok=result.returncode == 0,
                value=json.loads(result.stdout if result.returncode == 0 else result.stderr))


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal",
                         PEERWORK_TEST_OWNER_FORMAT="1"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    legacy_dir = STATE / "legacy-unsent"
    source_run = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
        origin, str(legacy_dir), str(LEGACY), "pending-before-post"], cwd=SOURCE,
        capture_output=True, text=True, timeout=120)
    assert source_run.returncode == 0, source_run.stderr[-800:]
    source = json.loads(source_run.stdout)
    assert source["policy_v"] == 1 and source["sequence"] == 1
    assert source["visibility"] == "PRIVATE" and source["structured"] is False
    assert source["pending_count"] == 1 and source["pending_command_id"]
    for name in ("state_path", "pem_path", "intent_db_path"):
        assert Path(source[name]).is_absolute() and Path(source[name]).is_file()
    baseline = counts(origin)
    assert baseline == 1  # Legacy BOOTSTRAP; fixture intercepted ACTION before POST.
    phase = request_json(origin, "__test/activate-protocol-cutover", post=True)
    assert phase["phase"] == "ENFORCE"
    assert counts(origin) == baseline

    root = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(root), allow_loopback_http=True)
    config = dict(origin=origin, stateDir=str(root), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(root),
                                           allow_loopback_http=True)))
    selected = dict(workspace_id=source["workspace_id"],
        protected_ts_state_path=source["state_path"],
        protected_ts_intent_db_path=source["intent_db_path"],
        protected_owner_pkcs8_path=source["pem_path"],
        expected_owner_actor_id=source["owner_actor_id"],
        expected_owner_key_id=source["owner_key_id"],
        recover_pending_action=True)
    try:
        owner.attach(**selected)
    except peerwork.OwnerWorkspaceError as error:
        assert error.code == "PENDING_ACTION_CONFLICT", (error.code, str(error))
        for path in (source["state_path"], source["pem_path"], source["intent_db_path"]):
            assert path not in str(error)
    else:
        raise AssertionError("legacy pending ACTION unexpectedly attached under ENFORCE")
    history = owner.attachments()
    assert len(history) == 1 and history[0]["status"] == "PREPARED"
    assert history[0]["provenance"] == "HISTORICAL_TS_OWNER"
    assert history[0]["pending_action_command_id"] is None
    assert counts(origin) == baseline
    attach_id = history[0]["attach_id"]

    retained = node_call(config, "retain", attachId=attach_id,
                         commandId=source["pending_command_id"])
    assert retained["ok"] is True, retained
    retained = retained["value"]
    assert retained["status"] == "ATTACHED_RESTRICTED"
    assert retained["pending_action_command_id"] == source["pending_command_id"]
    assert retained["pending_action_status"] == "RETAINED_UNRESOLVED"
    assert owner.attachments() == [retained]
    assert cli(config_file, "owner-attach-retain", attach_id,
               source["pending_command_id"]) == dict(ok=True, value=retained)
    wrong = "A" * 43 if source["pending_command_id"] != "A" * 43 else "B" * 43
    wrong_retry = cli(config_file, "owner-attach-retain", attach_id, wrong)
    assert wrong_retry["ok"] is False and wrong_retry["value"]["code"] == "ATTACH_CONFLICT"
    assert counts(origin) == baseline

    # The protected native attachment is now self-contained. Keep the old
    # exportable state/key/SQLite together, but make them unavailable here.
    legacy_dir.rename(STATE / "legacy-unsent-archived")
    restricted_read = owner.read(source["workspace_id"])
    assert restricted_read["sequence"] == 1
    assert node_call(config, "read", workspaceId=source["workspace_id"])["value"]["head"] == restricted_read["head"]
    submitted = node_call(config, "format", workspaceId=source["workspace_id"],
                          transition="UPGRADE_WIRE_V3")
    assert submitted["ok"] is True and submitted["value"]["status"] == "PENDING"
    upgrade_id = submitted["value"]["command_id"]
    assert any(row["command_id"] == upgrade_id for row in owner.format_transitions(source["workspace_id"]))
    accepted = cli(config_file, "owner-format-resume", source["workspace_id"], upgrade_id)
    assert accepted["ok"] is True and accepted["value"]["status"] == "ACCEPTED"
    assert owner.resume_format_transition(source["workspace_id"], upgrade_id) == accepted["value"]
    assert counts(origin) == baseline + 1
    after_attach = owner.attachments()
    assert len(after_attach) == 1 and after_attach[0]["status"] == "ATTACHED"
    assert after_attach[0]["pending_action_command_id"] == source["pending_command_id"]
    assert after_attach[0]["pending_action_status"] == "RETAINED_UNRESOLVED"
    assert node_call(config, "history")["value"] == after_attach
    read = owner.read(source["workspace_id"])
    assert read["sequence"] == 2
    wiki = next(row for row in read["objects"] if row.get("kind") == "instances"
                and row.get("value", {}).get("origin_entrypoint") == "wiki")
    title, body = "Retained Owner wiki", "New encrypted content after cutover"
    action = owner.private_actions(source["workspace_id"]).submit("wiki.create", wiki["id"],
        {"title": title, "body": body})
    assert action["status"] == "PENDING"
    result = owner.private_actions(source["workspace_id"]).retry_saved(action["command_id"])
    assert result["status"] == "ACCEPTED" and len(result["receipt"]["effects"]) == 1
    assert result["receipt"]["actor_id"] == source["owner_actor_id"]
    record_id = result["receipt"]["effects"][0]["record_id"]
    read = owner.read(source["workspace_id"])
    assert read["sequence"] == 3
    record = next(row for row in read["objects"] if row.get("id") == record_id)
    assert record["value"]["payload"]["title"] == title
    assert record["value"]["payload"]["body"] == body
    assert counts(origin) == baseline + 2
    assert owner.private_actions(source["workspace_id"]).retry_saved(action["command_id"]) == result
    assert counts(origin) == baseline + 2
    assert owner.attachments()[0]["pending_action_status"] == "RETAINED_UNRESOLVED"

    server.terminate()
    server.wait(timeout=5)
    assert cli(config_file, "owner-attachments") == dict(ok=True, value=owner.attachments())
    print(json.dumps(dict(status="PASS", workspace_id=source["workspace_id"],
        attach_id=attach_id, retained_command_id=source["pending_command_id"],
        upgrade_id=upgrade_id, record_id=record_id, final_sequence=read["sequence"])))
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
