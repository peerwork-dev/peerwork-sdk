"""Opt-in installed Python, Node and CLI PUBLIC action/recovery against the pinned service."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

import peerwork


ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
SDK_ROOT = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SDK_ROOT, text=True).strip() == SOURCE_COMMIT


def post(origin, path):
    with urllib.request.urlopen(urllib.request.Request(origin + path, data=b"", method="POST"), timeout=5):
        pass


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=5) as response:
        return json.load(response)


def require_accepted(result, command_id, sequence):
    assert result["status"] == "ACCEPTED" and result["command_id"] == command_id
    assert result["sequence"] == sequence and len(result["commit_hash"]) == 64
    receipt = result["receipt"]
    assert receipt["command_id"] == command_id and receipt["sequence"] == sequence
    assert receipt["commit_hash"] == result["commit_hash"]
    assert len(receipt["effects"]) == 1
    return receipt["effects"][0]["record_id"]


with tempfile.TemporaryDirectory(prefix="peerwork-installed-actions-") as directory:
    state = Path(directory)
    state.chmod(0o700)
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(state), PEERWORK_TEST_PUBLIC_READ="1",
               PEERWORK_TEST_FIRST_POST_MODE="normal")
    server = subprocess.Popen([NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
                              cwd=ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        assert line, f"reference service did not start: {server.stderr.read()[-500:]}"
        ready = json.loads(line)
        origin, fixture = ready["origin"], ready["public_read"]
        identity = state / "owner.state"
        info = peerwork.import_legacy_identity_pem(
            str(identity), str(state / "synthetic-public-read-owner.pem"))
        assert info == {"actor_id": fixture["actor_id"], "key_id": fixture["signing_key"]}
        profile = state / "profile"
        client = peerwork.SecurePublicActionClient(
            origin, str(profile), str(identity), fixture["workspace_id"],
            owner_actor_id=fixture["actor_id"], owner_key_id=fixture["signing_key"],
            allow_loopback_http=True)
        assert client.read()["sequence"] == 1

        first = "q" * 43
        post(origin, "__test/drop-next-post")
        pending = client.submit("discussion.post", fixture["instance_id"],
                                {"message": "Python authored record"}, command_id=first)
        assert pending["status"] == "PENDING" and pending["command_id"] == first
        assert counts(origin)["commits"] == 2

        node_options = dict(origin=origin, stateDir=str(profile), identityPath=str(identity),
                            workspaceId=fixture["workspace_id"], allowLoopbackHttp=True)
        node_env = dict(env, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
                        PEERWORK_TEST_ACTION_OPTIONS=json.dumps(node_options),
                        PEERWORK_TEST_INSTANCE_ID=fixture["instance_id"],
                        PEERWORK_TEST_COMMAND_ID=first)
        node_reconcile = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const session = sdk.openSecurePublicActions(JSON.parse(process.env.PEERWORK_TEST_ACTION_OPTIONS));
  const result = await session.reconcile(process.env.PEERWORK_TEST_COMMAND_ID);
  if (result.status !== 'ACCEPTED' || result.receipt.effects.length !== 1) throw Error('Node reconciliation failed');
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run([NODE, "-e", node_reconcile], env=node_env,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr[-1000:]
        first_record = require_accepted(json.loads(result.stdout), first, 2)

        config_file = state / "action-config.json"
        config_file.write_text(json.dumps({
            "origin": origin, "state_dir": str(profile), "identity_path": str(identity),
            "workspace_id": fixture["workspace_id"], "owner_actor_id": None,
            "owner_key_id": None, "authority": None, "required_features": [],
            "allow_loopback_http": True, "max_replay_artifact_bytes": 64 * 1024 * 1024,
        }), encoding="utf-8")
        cli_retry = subprocess.run([CLI, "secure", "action-retry", str(config_file), first],
                                   capture_output=True, text=True, timeout=60)
        assert cli_retry.returncode == 0, cli_retry.stderr[-1000:]
        require_accepted(json.loads(cli_retry.stdout), first, 2)
        assert counts(origin)["commits"] == 2

        second = "r" * 43
        node_env["PEERWORK_TEST_COMMAND_ID"] = second
        post(origin, "__test/drop-next-post")
        node_submit = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const session = sdk.openSecurePublicActions(JSON.parse(process.env.PEERWORK_TEST_ACTION_OPTIONS));
  const result = await session.submit('discussion.post', process.env.PEERWORK_TEST_INSTANCE_ID,
      {message:'Node authored record'}, {commandId:process.env.PEERWORK_TEST_COMMAND_ID});
  if (result.status !== 'PENDING' || result.receipt !== null) throw Error('Node submit was not pending');
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        node_result = subprocess.run([NODE, "-e", node_submit], env=node_env,
                                     capture_output=True, text=True, timeout=60)
        assert node_result.returncode == 0, node_result.stderr[-1000:]
        assert json.loads(node_result.stdout)["command_id"] == second
        assert counts(origin)["commits"] == 3
        cli_status = subprocess.run([CLI, "secure", "action-status", str(config_file), second],
                                    capture_output=True, text=True, timeout=60)
        assert cli_status.returncode == 0, cli_status.stderr[-1000:]
        second_record = require_accepted(json.loads(cli_status.stdout), second, 3)
        require_accepted(client.retry_saved(second), second, 3)
        assert counts(origin)["commits"] == 3

        third = "s" * 43
        input_file = state / "action-input.json"
        input_file.write_text(json.dumps({
            "action_id": "discussion.post", "instance_id": fixture["instance_id"],
            "body_json": json.dumps({"message": "CLI authored record"}),
            "command_id": third,
        }), encoding="utf-8")
        post(origin, "__test/drop-next-post")
        cli_submit = subprocess.run([CLI, "secure", "action-submit", str(config_file), str(input_file)],
                                    capture_output=True, text=True, timeout=60)
        assert cli_submit.returncode == 0, cli_submit.stderr[-1000:]
        assert json.loads(cli_submit.stdout)["status"] == "PENDING"
        node_env["PEERWORK_TEST_COMMAND_ID"] = third
        node_result = subprocess.run([NODE, "-e", node_reconcile], env=node_env,
                                     capture_output=True, text=True, timeout=60)
        assert node_result.returncode == 0, node_result.stderr[-1000:]
        third_record = require_accepted(json.loads(node_result.stdout), third, 4)
        assert counts(origin)["commits"] == 4
        latest = client.read()
        assert latest["sequence"] == 4
        for record_id in (first_record, second_record, third_record):
            assert any(obj.get("id") == record_id for obj in latest["objects"])
        print(json.dumps({"source_commit": SOURCE_COMMIT,
                          "reference_commit": "f828b6c50a0a58d1e718af90f653b214adcc3328",
                          "result": {"commits": 4, "records": 3, "sequence": latest["sequence"]}}))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
