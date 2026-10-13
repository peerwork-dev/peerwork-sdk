"""Opt-in installed Python/Node/CLI PUBLIC direct install against the pinned service."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

import peerwork


ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SDK_ROOT, text=True).strip() == SOURCE_COMMIT


def post(origin, path):
    with urllib.request.urlopen(urllib.request.Request(origin + path, data=b"", method="POST"), timeout=5):
        pass


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=5) as response:
        return json.load(response)


def start_fixture(state):
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(state), PEERWORK_TEST_PUBLIC_READ="1")
    server = subprocess.Popen([NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
                              cwd=ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    line = server.stdout.readline()
    assert line, f"reference service did not start: {server.stderr.read()[-500:]}"
    return server, json.loads(line)


def stop_fixture(server):
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)


def profile(state, ready):
    fixture = ready["public_read"]
    identity = state / "owner.state"
    info = peerwork.import_legacy_identity_pem(str(identity), str(state / "synthetic-public-read-owner.pem"))
    assert info == {"actor_id": fixture["actor_id"], "key_id": fixture["signing_key"]}
    config = dict(origin=ready["origin"], state_dir=str(state / "profile"), identity_path=str(identity),
                  workspace_id=fixture["workspace_id"], owner_actor_id=fixture["actor_id"],
                  owner_key_id=fixture["signing_key"], authority=fixture["authority"],
                  required_features=[], allow_loopback_http=True,
                  max_replay_artifact_bytes=64 * 1024 * 1024)
    client = peerwork.SecurePublicPackageInstaller(
        config["origin"], config["state_dir"], config["identity_path"], config["workspace_id"],
        owner_actor_id=config["owner_actor_id"], owner_key_id=config["owner_key_id"],
        authority=config["authority"], allow_loopback_http=True)
    assert client.read()["sequence"] == 1
    return client, config


def selection():
    vectors = json.loads((SDK_ROOT / "conformance/public-package-vectors.json").read_text())
    return dict(closure_json=json.dumps(vectors["closure"], separators=(",", ":")),
                expected_package_id="peerwork-proposal-adoption", expected_package_version="1.0.0",
                expected_package_digest=vectors["package_digest"],
                expected_protocol_digest=vectors["protocol_digest"],
                instance_id="z" * 43, entrypoint="proposalAdoption", grants_json="[]")


def node_call(config, operation, begin_id=None, install_selection=None):
    options = dict(origin=config["origin"], stateDir=config["state_dir"],
                   identityPath=config["identity_path"], workspaceId=config["workspace_id"],
                   allowLoopbackHttp=True)
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_INSTALL_OPTIONS=json.dumps(options),
               PEERWORK_TEST_INSTALL_OPERATION=operation,
               PEERWORK_TEST_BEGIN_ID=begin_id or "",
               PEERWORK_TEST_INSTALL_SELECTION=json.dumps(install_selection) if install_selection else "")
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const session = sdk.openSecurePublicPackageInstaller(JSON.parse(process.env.PEERWORK_TEST_INSTALL_OPTIONS));
  const operation = process.env.PEERWORK_TEST_INSTALL_OPERATION;
  const result = operation === 'pending' ? await session.pending()
      : operation === 'begin' ? await session.begin(JSON.parse(process.env.PEERWORK_TEST_INSTALL_SELECTION))
      : await session.continueInstall(process.env.PEERWORK_TEST_BEGIN_ID);
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-1000:]
    return json.loads(result.stdout)


def node_selection(value):
    return dict(closureJson=value["closure_json"], expectedPackageId=value["expected_package_id"],
                expectedPackageVersion=value["expected_package_version"],
                expectedPackageDigest=value["expected_package_digest"],
                expectedProtocolDigest=value["expected_protocol_digest"],
                instanceId=value["instance_id"], entrypoint=value["entrypoint"],
                grantsJson=value["grants_json"])


def cli_call(config_file, operation, begin_id=None):
    args = [CLI, "secure", "install-" + operation, str(config_file)]
    if begin_id is not None:
        args.append(begin_id)
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-1000:]
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="peerwork-installed-install-") as directory:
    base = Path(directory)
    base.chmod(0o700)
    # A generated BEGIN ID is durably recoverable even when the service is gone.
    offline_state = base / "offline"
    offline_state.mkdir(mode=0o700)
    server, ready = start_fixture(offline_state)
    try:
        offline, config = profile(offline_state, ready)
        post(ready["origin"], "__test/reject-next-post-before-apply")
        try:
            offline.begin(**selection())
        except peerwork.PublicInstallError:
            pass
        else:
            raise AssertionError("fixture must reject BEGIN after local persistence")
        assert counts(ready["origin"])["head_sequence"] == 1
    finally:
        stop_fixture(server)
    pending = offline.pending()
    assert len(pending) == 1 and pending[0]["pending_action_id"] == "secure.structure.begin"
    command_id = pending[0]["begin_command_id"]
    config_file = offline_state / "install-config.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    assert node_call(config, "pending") == pending
    assert cli_call(config_file, "pending") == pending

    # A second fresh service exercises real BEGIN/END admission and signed completion.
    online_state = base / "online"
    online_state.mkdir(mode=0o700)
    server, ready = start_fixture(online_state)
    try:
        client, config = profile(online_state, ready)
        config_file = online_state / "install-config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        begin = node_call(config, "begin", install_selection=node_selection(selection()))
        assert begin["status"] == "PENDING"
        assert counts(ready["origin"])["head_sequence"] == 2
        begin_id = begin["command_id"]
        steps = []
        for index in range(5):
            if index % 3 == 0:
                step = node_call(config, "continue", begin_id)
            elif index % 3 == 1:
                step = cli_call(config_file, "continue", begin_id)
            else:
                step = client.continue_install(begin_id)
            assert step["begin_command_id"] == begin_id
            steps.append(step)
            if step["status"] == "ACCEPTED":
                break
        assert steps[-1]["status"] == "ACCEPTED"
        assert counts(ready["origin"])["head_sequence"] == 3
        assert client.pending() == []
        latest = client.read()
        assert latest["sequence"] == 3 and latest["structure_status"] == "ACTIVE"
        print(json.dumps({"source_commit": SOURCE_COMMIT,
                          "reference_commit": "f828b6c50a0a58d1e718af90f653b214adcc3328",
                          "offline_generated_id_recovered": len(command_id) == 43,
                          "offline_interfaces": 3, "begin_status": begin["status"],
                          "step_statuses": [step["status"] for step in steps],
                          "final_sequence": latest["sequence"]}))
    finally:
        stop_fixture(server)

    # CLI BEGIN has its own fresh workspace so the command route is exercised
    # without a duplicate-install conflict in the completed workspace.
    cli_state = base / "cli"
    cli_state.mkdir(mode=0o700)
    server, ready = start_fixture(cli_state)
    try:
        _, config = profile(cli_state, ready)
        config_file = cli_state / "install-config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        input_file = cli_state / "install-input.json"
        input_file.write_text(json.dumps(selection()), encoding="utf-8")
        cli_begin = cli_call(config_file, "begin", str(input_file))
        assert cli_begin["status"] == "PENDING"
        assert counts(ready["origin"])["head_sequence"] == 2
    finally:
        stop_fixture(server)
