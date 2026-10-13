"""Scripted installed attachment of a real legacy wire-v1 PRIVATE Owner.

The caller explicitly pairs its protected TypeScript state and intent database.
Matching local hashes prove stability of that declared pair, not that independently
created empty stores historically belonged together. This is no Agent workflow test.
"""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
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
    ("tests/legacy-owner-source.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
head = subprocess.check_output(["git", "-C", str(LEGACY), "rev-parse", "HEAD"], text=True).strip()
assert head == os.environ["PEERWORK_TEST_LEGACY_COMMIT"]
assert subprocess.run(["git", "-C", str(LEGACY), "diff", "--quiet", "HEAD", "--",
                       "src", "package.json", "package-lock.json"], check=False).returncode == 0
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def service_counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def legacy_source(origin, mode):
    created_dir = STATE / ("legacy-" + mode)
    result = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"), origin,
                             str(created_dir), str(LEGACY), mode], cwd=SOURCE,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    value = json.loads(result.stdout)
    assert value["policy_v"] == 1 and value["sequence"] == 1
    assert value["pending_count"] == (1 if mode == "pending" else 0)
    for path in ("state_path", "pem_path", "intent_db_path"):
        assert Path(value[path]).is_absolute() and Path(value[path]).is_file()
    return value


def input_for(source):
    return dict(workspace_id=source["workspace_id"],
                protected_ts_state_path=source["state_path"],
                protected_ts_intent_db_path=source["intent_db_path"],
                protected_owner_pkcs8_path=source["pem_path"],
                expected_owner_actor_id=source["owner_actor_id"],
                expected_owner_key_id=source["owner_key_id"])


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'attach': result = await owner.attach(value.input); break;
    case 'resume': result = await owner.resumeAttachment(value.attachId); break;
    case 'attachments': result = await owner.attachments(); break;
    case 'read': result = await owner.read(value.workspaceId); break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => {
  console.log(JSON.stringify({ok:false,code:error.code,message:error.message}));
});
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUES=json.dumps(values))
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def node_input(value):
    return dict(workspaceId=value["workspace_id"],
                protectedTsStatePath=value["protected_ts_state_path"],
                protectedTsIntentDbPath=value["protected_ts_intent_db_path"],
                protectedOwnerPkcs8Path=value["protected_owner_pkcs8_path"],
                expectedOwnerActorId=value["expected_owner_actor_id"],
                expectedOwnerKeyId=value["expected_owner_key_id"])


def cli(config_file, verb, extra=None):
    command = [CLI, "secure", verb, str(config_file)]
    if extra is not None:
        command.append(str(extra))
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    value = json.loads(result.stdout if result.returncode == 0 else result.stderr)
    return dict(ok=result.returncode == 0, value=value)


def assert_redacted_failure(value, expected, paths):
    assert value["code"] == expected
    output = json.dumps(value)
    for path in paths:
        assert path not in output
    assert "PRIVATE KEY" not in output and "signed_packet" not in output


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal",
                         PEERWORK_TEST_FIRST_JOURNAL_DELAY_MS="0",
                         PEERWORK_TEST_HISTORICAL_ATTACH="1"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    pending = legacy_source(origin, "pending")
    unknown = legacy_source(origin, "unknown-store")
    malformed = legacy_source(origin, "malformed-store")
    clean = legacy_source(origin, "clean")
    native_root = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native_root), allow_loopback_http=True)
    config = dict(origin=origin, stateDir=str(native_root), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native_root),
                                           allow_loopback_http=True)))
    before_attach = service_counts(origin)["commits"]

    for source in (pending, unknown, malformed):
        selected = input_for(source)
        paths = [source["state_path"], source["pem_path"], source["intent_db_path"]]
        try:
            owner.attach(**selected)
        except peerwork.OwnerWorkspaceError as error:
            assert_redacted_failure(dict(code=error.code, message=str(error)),
                                    "SOURCE_UNRESOLVED", paths)
        else:
            raise AssertionError("unresolved historical source was attached")
        node_error = node_call(config, "attach", input=node_input(selected))
        assert node_error["ok"] is False
        assert_redacted_failure(node_error, "SOURCE_UNRESOLVED", paths)
        input_file = STATE / ("bad-" + source["workspace_id"] + ".json")
        input_file.write_text(json.dumps(selected))
        cli_error = cli(config_file, "owner-attach", input_file)
        assert cli_error["ok"] is False
        assert_redacted_failure(cli_error["value"], "SOURCE_UNRESOLVED", paths)
        assert owner.attachments() == []
        assert service_counts(origin)["commits"] == before_attach

    valid = input_for(clean)
    wrong = dict(valid, expected_owner_actor_id=("A" if valid["expected_owner_actor_id"][0] != "A" else "B") * 43)
    paths = [clean["state_path"], clean["pem_path"], clean["intent_db_path"]]
    try:
        owner.attach(**wrong)
    except peerwork.OwnerWorkspaceError as error:
        assert_redacted_failure(dict(code=error.code, message=str(error)),
                                "IDENTITY_CHANGED", paths)
    else:
        raise AssertionError("wrong Owner pin was accepted")
    node_error = node_call(config, "attach", input=node_input(wrong))
    assert node_error["ok"] is False
    assert_redacted_failure(node_error, "IDENTITY_CHANGED", paths)
    wrong_file = STATE / "wrong-owner.json"
    wrong_file.write_text(json.dumps(wrong))
    cli_error = cli(config_file, "owner-attach", wrong_file)
    assert cli_error["ok"] is False
    assert_redacted_failure(cli_error["value"], "IDENTITY_CHANGED", paths)
    assert owner.attachments() == []
    assert node_call(config, "attachments") == dict(ok=True, value=[])
    assert cli(config_file, "owner-attachments") == dict(ok=True, value=[])
    assert service_counts(origin)["commits"] == before_attach

    # The fixture holds an authenticated journal GET after the native PREPARED
    # row is durable. Cancel the public async caller only after observing it.
    with urllib.request.urlopen(urllib.request.Request(
            origin + "__test/delay-next-journal", data=b"{}", method="POST"), timeout=10) as response:
        assert json.load(response)["enabled"] is True

    async def cancel_prepared_attach():
        task = asyncio.create_task(owner.attach_async(**valid))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with urllib.request.urlopen(origin + "__test/journal-delay-status", timeout=5) as response:
                if json.load(response)["started"] is True:
                    break
            await asyncio.sleep(0.05)
        else:
            task.cancel()
            raise AssertionError("authenticated attach journal GET did not start")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cancelled attach returned a completed result")

    asyncio.run(cancel_prepared_attach())
    prepared = owner.attachments()
    assert len(prepared) == 1 and prepared[0]["status"] == "PREPARED"
    assert prepared[0]["provenance"] == "ATTACHED"
    assert prepared[0]["workspace_id"] == clean["workspace_id"]
    assert prepared[0]["sequence"] is None and prepared[0]["head"] is None
    assert node_call(config, "attachments") == dict(ok=True, value=prepared)
    assert cli(config_file, "owner-attachments") == dict(ok=True, value=prepared)
    assert service_counts(origin)["commits"] == before_attach
    attach_id = prepared[0]["attach_id"]
    attached = node_call(config, "resume", attachId=attach_id)
    assert attached["ok"] is True
    result = attached["value"]
    assert result["provenance"] == "ATTACHED" and result["status"] == "ATTACHED"
    assert result["workspace_id"] == clean["workspace_id"]
    assert result["owner_actor_id"] == clean["owner_actor_id"]
    assert result["owner_key_id"] == clean["owner_key_id"]
    assert result["sequence"] >= clean["sequence"] and result["head"]
    assert service_counts(origin)["commits"] == before_attach
    assert result["attach_id"] == attach_id
    assert owner.attachments() == [result]
    assert owner.resume_attachment(attach_id) == result
    assert node_call(config, "resume", attachId=attach_id) == dict(ok=True, value=result)
    assert cli(config_file, "owner-attach-resume", attach_id) == dict(ok=True, value=result)
    assert service_counts(origin)["commits"] == before_attach

    # Move only this test's exportable source files. Native ATTACHED authority
    # must use its own protected history/profile, not the old source paths.
    Path(clean["state_path"]).parent.rename(STATE / "legacy-clean-archived")
    fresh = peerwork.SecureOwnerWorkspaceClient(origin, str(native_root), allow_loopback_http=True)
    read = fresh.read(clean["workspace_id"])
    assert read["sequence"] == result["sequence"] and read["head"] == result["head"]
    assert node_call(config, "read", workspaceId=clean["workspace_id"])["value"]["head"] == read["head"]
    assert cli(config_file, "owner-read", clean["workspace_id"])["value"]["head"] == read["head"]
    wiki = next(row for row in read["objects"] if row.get("kind") == "instances"
                and row.get("value", {}).get("origin_entrypoint") == "wiki")
    title, body = "Attached Owner wiki", "Encrypted content after legacy source moves"
    action = fresh.private_actions(clean["workspace_id"]).submit("wiki.create", wiki["id"],
        {"title": title, "body": body})
    assert action["status"] == "PENDING"
    accepted = fresh.private_actions(clean["workspace_id"]).retry_saved(action["command_id"])
    assert accepted["status"] == "ACCEPTED" and len(accepted["receipt"]["effects"]) == 1
    assert accepted["receipt"]["actor_id"] == clean["owner_actor_id"]
    record_id = accepted["receipt"]["effects"][0]["record_id"]
    after = fresh.read(clean["workspace_id"])
    assert after["sequence"] == read["sequence"] + 1
    record = next(row for row in after["objects"] if row.get("id") == record_id)
    assert record["value"]["payload"]["title"] == title
    assert record["value"]["payload"]["body"] == body
    assert service_counts(origin)["commits"] == before_attach + 1
    assert fresh.private_actions(clean["workspace_id"]).retry_saved(action["command_id"])["status"] == "ACCEPTED"
    assert service_counts(origin)["commits"] == before_attach + 1

    server.terminate()
    server.wait(timeout=5)
    assert owner.attachments() == node_call(config, "attachments")["value"]
    assert cli(config_file, "owner-attachments")["value"] == owner.attachments()
    print(json.dumps(dict(status="PASS", workspace_id=clean["workspace_id"],
        attach_id=attach_id, provenance="ATTACHED", source_policy_v=1,
        source_unresolved_cases=3, wrong_owner_refused=True,
        prepared_recovered_after_cancellation=True,
        source_files_unavailable_after_attach=True, record_id=record_id,
        final_sequence=after["sequence"])))
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
