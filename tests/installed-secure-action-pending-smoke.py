"""Opt-in installed generated-ID cancellation recovery across Python, Node and CLI."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

import peerwork


ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
SDK_ROOT = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SDK_ROOT, text=True).strip() == SOURCE_COMMIT


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=5) as response:
        return json.load(response)


async def await_commit(origin, expected):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        observed = await asyncio.to_thread(counts, origin)
        if observed["commits"] == expected:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"service did not reach {expected} commits")


with tempfile.TemporaryDirectory(prefix="peerwork-pending-discovery-") as directory:
    state = Path(directory)
    state.chmod(0o700)
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(state), PEERWORK_TEST_PUBLIC_READ="1",
               PEERWORK_TEST_FIRST_POST_MODE="delay", PEERWORK_TEST_FIRST_POST_DELAY_MS="6000")
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

        async def cancellation_path():
            before = asyncio.create_task(client.submit_async(
                "discussion.post", fixture["instance_id"], {"message": "never prepared"}))
            before.cancel()
            try:
                await before
                raise AssertionError("pre-persist task was not cancelled")
            except asyncio.CancelledError:
                pass
            assert client.pending() == []
            assert counts(origin)["commits"] == 1

            after = asyncio.create_task(client.submit_async(
                "discussion.post", fixture["instance_id"], {"message": "cancelled after service apply"}))
            await await_commit(origin, 2)
            after.cancel()
            try:
                await after
                raise AssertionError("post-persist task was not cancelled")
            except asyncio.CancelledError:
                pass

        asyncio.run(cancellation_path())

        # The native worker has drained. These fresh sessions recover the
        # generated ID from protected state without fetching the journal.
        before_list = counts(origin)["journal_gets"]
        fresh = peerwork.SecurePublicActionClient(
            origin, str(profile), str(identity), fixture["workspace_id"],
            allow_loopback_http=True)
        python_rows = fresh.pending()
        assert len(python_rows) == 1
        row = python_rows[0]
        assert row["workspace_id"] == fixture["workspace_id"]
        assert row["action_id"] == "discussion.post"
        assert row["actor_id"] == fixture["actor_id"]
        assert row["origin"] == origin
        assert len(row["command_id"]) == 43
        assert len(row["request_sha256"]) == len(row["commit_hash"]) == 64
        assert set(row) == {"command_id", "actor_id", "origin", "workspace_id",
                            "action_id", "request_sha256", "commit_hash"}

        node_options = dict(origin=origin, stateDir=str(profile), identityPath=str(identity),
                            workspaceId=fixture["workspace_id"], allowLoopbackHttp=True)
        node_env = dict(env, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
                        PEERWORK_TEST_ACTION_OPTIONS=json.dumps(node_options))
        node_script = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const session = sdk.openSecurePublicActions(JSON.parse(process.env.PEERWORK_TEST_ACTION_OPTIONS));
  console.log(JSON.stringify(await session.pending()));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        node_result = subprocess.run([NODE, "-e", node_script], env=node_env,
                                     capture_output=True, text=True, timeout=60)
        assert node_result.returncode == 0, node_result.stderr[-1000:]
        assert json.loads(node_result.stdout) == python_rows

        config_file = state / "action-config.json"
        config_file.write_text(json.dumps({
            "origin": origin, "state_dir": str(profile), "identity_path": str(identity),
            "workspace_id": fixture["workspace_id"], "owner_actor_id": None,
            "owner_key_id": None, "authority": None, "required_features": [],
            "allow_loopback_http": True, "max_replay_artifact_bytes": 64 * 1024 * 1024,
        }), encoding="utf-8")
        cli_result = subprocess.run([CLI, "secure", "action-pending", str(config_file)],
                                    capture_output=True, text=True, timeout=60)
        assert cli_result.returncode == 0, cli_result.stderr[-1000:]
        assert json.loads(cli_result.stdout) == python_rows
        assert counts(origin)["journal_gets"] == before_list

        accepted = fresh.reconcile(row["command_id"])
        assert accepted["status"] == "ACCEPTED" and accepted["sequence"] == 2
        assert accepted["command_id"] == row["command_id"]
        assert len(accepted["receipt"]["effects"]) == 1
        assert counts(origin)["commits"] == 2
        assert fresh.pending() == []
        print(json.dumps({"source_commit": SOURCE_COMMIT,
                          "reference_commit": "f828b6c50a0a58d1e718af90f653b214adcc3328",
                          "result": {"pre_cancel_rows": 0, "post_cancel_rows": 1,
                                     "list_journal_get_delta": 0, "accepted_sequence": 2,
                                     "commits": 2}}))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
