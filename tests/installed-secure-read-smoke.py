"""Opt-in installed Python, Node, and CLI PUBLIC read against the pinned service."""

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
REFERENCE = os.environ["PEERWORK_REFERENCE_ROOT"]
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
SDK_ROOT = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SDK_ROOT, text=True).strip() == SOURCE_COMMIT

started = time.monotonic()
stages = []


def mark(name):
    stages.append({"stage": name, "elapsed_ms": round((time.monotonic() - started) * 1000)})


def require_result(result, fixture):
    assert result["workspace_id"] == fixture["workspace_id"]
    assert result["sequence"] == 1
    assert result["head"] == fixture["head"]
    assert len(result["objects"]) >= 1 and len(result["operations"]) == 1
    assert not any(key in result for key in ("keyring", "jws", "private_key", "receipt"))


mark("installed_python_import")
with tempfile.TemporaryDirectory(prefix="peerwork-public-read-") as directory:
    state = Path(directory)
    state.chmod(0o700)
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(state), PEERWORK_TEST_PUBLIC_READ="1",
               PEERWORK_TEST_FIRST_POST_MODE="normal")
    server = subprocess.Popen([NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
                              cwd=ROOT, env=env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        assert line, f"reference service did not start: {server.stderr.read()[-500:]}"
        ready = json.loads(line)
        origin, fixture = ready["origin"], ready["public_read"]
        assert len(fixture["head"]) == 64
        mark("actual_service_public_workspace_ready")

        identity = state / "native-owner.state"
        info = peerwork.import_legacy_identity_pem(
            str(identity), str(state / "synthetic-public-read-owner.pem"))
        assert info == {"actor_id": fixture["actor_id"], "key_id": fixture["signing_key"]}
        common = (origin, str(state / "kernel.sqlite"), str(state / "read.state"),
                  str(state / "lifecycle.state"), str(identity), fixture["workspace_id"],
                  fixture["authority"], fixture["actor_id"], fixture["signing_key"])
        client = peerwork.SecureSnapshotClient(*common, allow_loopback_http=True)
        result = client.read()
        require_result(result, fixture)
        mark("installed_python_first_verified_read")
        require_result(client.read(), fixture)
        mark("installed_python_reopen_read")

        try:
            peerwork.SecureSnapshotClient(*common, allow_loopback_http=True,
                                      max_replay_artifact_bytes=1).read()
        except peerwork.SecureReadError as error:
            assert error.code == "RESOURCE_LIMIT"
        else:
            raise AssertionError("one-byte replay budget was accepted")
        wrong = list(common)
        wrong[-1] = "A" * len(wrong[-1])
        try:
            peerwork.SecureSnapshotClient(*wrong, allow_loopback_http=True).read()
        except peerwork.SecureReadError as error:
            assert error.code == "LIFECYCLE_PIN_CHANGED"
        else:
            raise AssertionError("wrong owner pin was accepted")
        mark("installed_python_budget_and_owner_refusals")

        async def cancelled_read():
            task = asyncio.create_task(client.read_async())
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return
            raise AssertionError("cancelled read completed")

        asyncio.run(cancelled_read())
        require_result(client.read(), fixture)
        mark("installed_python_cancel_reopen")

        node_source = r'''
void (async () => {
const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
const options = JSON.parse(process.env.PEERWORK_TEST_READ_OPTIONS);
const expected = JSON.parse(process.env.PEERWORK_TEST_PUBLIC_FIXTURE);
const value = await sdk.readSecureSnapshot(options);
if (value.workspace_id !== expected.workspace_id || value.head !== expected.head ||
    value.sequence !== 1 || value.objects.length < 1 || value.operations.length !== 1 ||
    ['keyring','jws','private_key','receipt'].some(key => key in value)) throw Error('Node read result mismatch');
try { await sdk.readSecureSnapshot({...options,maxReplayArtifactBytes:1}); throw Error('budget accepted'); }
catch (error) { if (error.code !== 'RESOURCE_LIMIT') throw error; }
const signal = AbortSignal.abort();
try { await sdk.readSecureSnapshot({...options,signal}); throw Error('cancelled read accepted'); }
catch (error) { if (error.code !== 'CANCELLED') throw error; }
console.log(JSON.stringify({workspace_id:value.workspace_id,sequence:value.sequence,objects:value.objects.length,operations:value.operations.length}));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        node_options = dict(origin=origin, kernelJournalPath=common[1], readStatePath=common[2],
                            lifecyclePath=common[3], identityPath=common[4],
                            workspaceId=common[5], authority=common[6],
                            ownerActorId=common[7], ownerKeyId=common[8], allowLoopbackHttp=True)
        node_env = dict(env, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
                        PEERWORK_TEST_READ_OPTIONS=json.dumps(node_options),
                        PEERWORK_TEST_PUBLIC_FIXTURE=json.dumps(fixture))
        node_result = subprocess.run([NODE, "-e", node_source], env=node_env,
                                     capture_output=True, text=True, timeout=45)
        assert node_result.returncode == 0, node_result.stderr[-1000:]
        assert json.loads(node_result.stdout)["workspace_id"] == fixture["workspace_id"]
        mark("installed_node_verified_budget_cancel")

        cli = [CLI, "secure", "snapshot", *common, "--allow-loopback-http"]
        cli_result = subprocess.run(cli, capture_output=True, text=True, timeout=45, check=True)
        require_result(json.loads(cli_result.stdout), fixture)
        limited = subprocess.run(cli + ["--max-replay-artifact-bytes=1"],
                                 capture_output=True, text=True, timeout=45)
        assert limited.returncode != 0 and json.loads(limited.stderr)["code"] == "RESOURCE_LIMIT"
        mark("installed_cli_verified_and_budget_refusal")

        profile_dir = state / "shared-read-profile"
        latest = peerwork.SecureReadClient(origin, str(profile_dir), str(identity),
                                           fixture["workspace_id"],
                                           owner_actor_id=fixture["actor_id"],
                                           owner_key_id=fixture["signing_key"],
                                           allow_loopback_http=True)
        assert latest.read()["sequence"] == 1
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/append-public", data=b"", method="POST"), timeout=5) as response:
            appended = json.load(response)
        assert appended["sequence"] == 2
        reopened_latest = peerwork.SecureReadClient(origin, str(profile_dir), str(identity),
                                                   fixture["workspace_id"],
                                                   allow_loopback_http=True)
        latest_two = reopened_latest.read()
        assert latest_two["sequence"] == 2 and latest_two["head"] == appended["head"]
        mark("installed_python_latest_append_and_reopen")

        latest_node_options = dict(origin=origin, stateDir=str(profile_dir),
                                   identityPath=str(identity), workspaceId=fixture["workspace_id"],
                                   allowLoopbackHttp=True)
        latest_node_source = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const options = JSON.parse(process.env.PEERWORK_TEST_READ_OPTIONS);
  const result = await sdk.readSecureWorkspace(options);
  if (result.sequence !== 2 || result.head !== process.env.PEERWORK_TEST_LATEST_HEAD ||
      'jws' in result || 'keyring' in result) throw Error('latest Node read mismatch');
  console.log(JSON.stringify({sequence:result.sequence,head:result.head}));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        latest_node_env = dict(env, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
                               PEERWORK_TEST_READ_OPTIONS=json.dumps(latest_node_options),
                               PEERWORK_TEST_LATEST_HEAD=appended["head"])
        latest_node = subprocess.run([NODE, "-e", latest_node_source], env=latest_node_env,
                                     capture_output=True, text=True, timeout=45)
        assert latest_node.returncode == 0, latest_node.stderr[-1000:]
        assert json.loads(latest_node.stdout)["sequence"] == 2
        mark("installed_node_latest_shared_profile")

        latest_cli = [CLI, "secure", "read", f"--origin={origin}",
                      f"--state-dir={profile_dir}", f"--identity={identity}",
                      f"--workspace={fixture['workspace_id']}", "--allow-loopback-http"]
        latest_cli_result = subprocess.run(latest_cli, capture_output=True,
                                           text=True, timeout=45, check=True)
        assert json.loads(latest_cli_result.stdout)["head"] == appended["head"]
        mark("installed_cli_latest_shared_profile")

        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/serve-stale-public", data=b"", method="POST"), timeout=5):
            pass
        try:
            reopened_latest.read()
        except peerwork.SecureReadError as error:
            assert error.code == "VERIFICATION_FAILED"
        else:
            raise AssertionError("stale signed checkpoint was accepted as latest")
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/restore-current-public", data=b"", method="POST"), timeout=5):
            pass
        assert reopened_latest.read()["head"] == appended["head"]
        mark("installed_python_rollback_refusal_and_recovery")

        with urllib.request.urlopen(origin + "__test/secure-counts", timeout=3) as response:
            counts = json.load(response)
        assert counts["commits"] == 2 and counts["head_sequence"] == 2
        print(json.dumps({"source_commit": SOURCE_COMMIT,
                          "reference_commit": "f828b6c50a0a58d1e718af90f653b214adcc3328",
                          "result": {"snapshot_sequence": result["sequence"], "latest_sequence": latest_two["sequence"],
                                     "object_count": len(result["objects"]),
                                     "operation_count": len(result["operations"]),
                                     "commit_count": counts["commits"]},
                          "stages": stages}))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
