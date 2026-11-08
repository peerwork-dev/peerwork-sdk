"""Scripted installed PRIVATE ceiling-two DIRECT install across public interfaces.

The service SQLite query is a test-only signed-policy oracle bound to native
verified read; it is not a public policy getter or independent signature check.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/core/src/public_direct_install.rs", "PEERWORK_TEST_DIRECT_COMPILER_SHA256"),
    ("crates/core/src/prepared_private_install.rs", "PEERWORK_TEST_PRIVATE_PRODUCER_SHA256"),
    ("crates/runtime/src/secure_private_install.rs", "PEERWORK_TEST_RUNTIME_INSTALL_SHA256"),
    ("crates/runtime/src/secure_owner_format_transition.rs", "PEERWORK_TEST_TRANSITION_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_FIXTURE_SHA256"),
    ("conformance/private-direct-format-two.json", "PEERWORK_TEST_VECTOR_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
vector = json.loads((SOURCE / "conformance/private-direct-format-two.json").read_text())
root_digest = vector["root_package_digest"]
protocol_digest = vector["protocol_digest"]
assert root_digest == os.environ["PEERWORK_TEST_ROOT_DIGEST"]
assert protocol_digest == os.environ["PEERWORK_TEST_PROTOCOL_DIGEST"]
source_digest = os.environ["PEERWORK_TEST_SOURCE_DIGEST"]
assert source_digest == "b792d58a1c33218f121d7c742ca85bf63c411ab3aa5733ff88cc8b919f05496a"
closure_json = json.dumps(vector["closure"], separators=(",", ":"))
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, route):
    request = urllib.request.Request(origin + route, data=b"{}", method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def policy_oracle(workspace_id, verified):
    database = f"file:{STATE / 'control.sqlite'}?mode=ro"
    with sqlite3.connect(database, uri=True, timeout=10) as connection:
        policies = connection.execute(
            "SELECT version, policy_hash, effective_sequence, artifact FROM secure_policies "
            "WHERE workspace_id=? AND policy_hash=?",
            (workspace_id, verified["policy_hash"]),
        ).fetchall()
        commits = connection.execute(
            "SELECT commit_hash, policy_hash, artifact FROM secure_commits "
            "WHERE workspace_id=? AND sequence=?",
            (workspace_id, verified["sequence"]),
        ).fetchall()
    assert len(policies) == len(commits) == 1
    commit_hash, commit_policy_hash, commit_wire = commits[0]
    assert commit_hash == verified["head"]
    assert commit_policy_hash == verified["policy_hash"]
    assert hashlib.sha256(commit_wire.encode()).hexdigest() == commit_hash
    commit = json.loads(commit_wire)
    assert commit["signature"] and commit["payload"]["sequence"] == verified["sequence"]
    version, policy_hash, effective_sequence, policy_wire = policies[0]
    assert policy_hash == verified["policy_hash"]
    assert hashlib.sha256(policy_wire.encode()).hexdigest() == policy_hash
    policy = json.loads(policy_wire)
    assert policy["signature"] and policy["payload"]["version"] == version
    assert policy["payload"]["effective_sequence"] == effective_sequence
    return policy["payload"]


def node_call(config, workspace_id, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_CONFIG));
  const workspace = process.env.PEERWORK_TEST_WORKSPACE;
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUE);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'begin':
      result = await owner.privatePackageInstaller(workspace).beginDirect(value.selection);
      result = {status:result.status, step_action_id:result.step_action_id,
        protocol_digest:result.protocol_digest, instance_id:result.instance_id};
      break;
    case 'installs': result = await owner.privatePackageInstaller(workspace).installs(); break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id,
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUE=json.dumps(values))
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    return result


def cli(config_file, verb, workspace_id, argument=None, expect_failure=False):
    command = [CLI, "secure", verb, str(config_file), workspace_id]
    if argument is not None:
        command.append(str(argument))
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if expect_failure:
        assert result.returncode != 0 and not result.stdout
        return json.loads(result.stderr)
    assert result.returncode == 0, (verb, result.stderr[-1000:])
    return json.loads(result.stdout)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal",
                         PEERWORK_TEST_OWNER_FORMAT="1"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    created = owner.create("Installed PRIVATE typed direct", "PRIVATE", structured=True)
    assert created["status"] == "CREATED" and created["visibility"] == "PRIVATE"
    workspace_id = created["workspace_id"]
    initial = owner.read(workspace_id)
    before_policy = policy_oracle(workspace_id, initial)
    assert before_policy["v"] == 3 and before_policy["visibility"] == "PRIVATE"
    assert before_policy["structure_mode"] == "STRUCTURED"
    assert before_policy["protocol_format_ceiling"] == 1
    wiki = next(row["id"] for row in initial["objects"] if row.get("kind") == "instances"
                and row.get("value", {}).get("origin_entrypoint") == "wiki")
    old_action = owner.private_actions(workspace_id).submit("wiki.create", wiki,
        {"title": "Before typed direct", "body": "Encrypted older body"})
    old_accepted = owner.private_actions(workspace_id).retry_saved(old_action["command_id"])
    assert old_accepted["status"] == "ACCEPTED"
    old_record_id = old_accepted["receipt"]["effects"][0]["record_id"]
    prior = owner.read(workspace_id)
    prior_policy = policy_oracle(workspace_id, prior)
    assert prior_policy == before_policy
    owner_actor = prior_policy["owner_id"]
    old_payload = next(row for row in prior["objects"] if row.get("id") == old_record_id)["value"]["payload"]
    assert old_payload["title"] == "Before typed direct"
    assert old_payload["body"] == "Encrypted older body"
    assert post(origin, "__test/activate-protocol-cutover")["phase"] == "ENFORCE"
    config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                           allow_loopback_http=True)))
    instance_id = secrets.token_urlsafe(32)
    assert len(instance_id) == 43
    grants_json = json.dumps([dict(actor_id=owner_actor,
        actions=["lib.replace", "lib.produce"], protocol_roles=[], capabilities=[])],
        separators=(",", ":"))
    selection = dict(closureJson=closure_json,
        expectedRootPackageDigest=root_digest, expectedProtocolDigest=protocol_digest,
        instanceId=instance_id, entrypoint="typedPackage", grantsJson=grants_json)
    before_rejection = counts(origin)["commits"]
    try:
        owner.private_package_installer(workspace_id).begin_direct(
            closure_json, root_digest, protocol_digest, instance_id,
            "typedPackage", grants_json=grants_json)
    except peerwork.PrivatePackageInstallError as error:
        assert error.code == "INSTALL_PLAN_FAILED"
    else:
        raise AssertionError("ceiling-one Python DIRECT accepted format-two")
    node_refusal = node_call(config, workspace_id, "begin", selection=selection)
    assert node_refusal.returncode != 0 and not node_refusal.stdout
    assert node_refusal.stderr.strip() == "INSTALL_PLAN_FAILED"
    input_file = STATE / "typed-direct.json"
    input_file.write_text(json.dumps(dict(closure_json=closure_json,
        expected_root_package_digest=root_digest, expected_protocol_digest=protocol_digest,
        instance_id=instance_id, entrypoint="typedPackage", grants_json=grants_json)))
    assert cli(config_file, "owner-private-install-begin-direct", workspace_id,
               input_file, expect_failure=True)["code"] == "INSTALL_PLAN_FAILED"
    assert owner.private_package_installer(workspace_id).installs() == []
    assert counts(origin)["commits"] == before_rejection

    raised = owner.submit_format_transition(workspace_id, "RAISE_PRIVATE_CEILING_TWO")
    assert raised["transition"] == "RAISE_PRIVATE_CEILING_TWO"
    raise_id = raised["command_id"]
    raised = owner.resume_format_transition(workspace_id, raise_id)
    assert raised["status"] == "ACCEPTED"
    after_raise = owner.read(workspace_id)
    raised_policy = policy_oracle(workspace_id, after_raise)
    assert raised_policy["v"] == 3 and raised_policy["structure_mode"] == "STRUCTURED"
    assert raised_policy["protocol_format_ceiling"] == 2
    for field in ("workspace_id", "owner_id", "signing_key", "epoch", "visibility",
                  "members", "structure"):
        assert raised_policy[field] == prior_policy[field]
    assert raised_policy["version"] == prior_policy["version"] + 1
    assert raised_policy["previous_policy"] == prior["policy_hash"]
    assert raised_policy["effective_sequence"] == after_raise["sequence"]
    assert raised["policy_hash"] == after_raise["policy_hash"]

    assert post(origin, "__test/drop-next-post")["enabled"] is True
    baseline = counts(origin)["commits"]
    withheld = node_call(config, workspace_id, "begin", selection=selection)
    assert withheld.returncode == 0, withheld.stderr[-1000:]
    assert json.loads(withheld.stdout) == dict(status="PENDING",
        step_action_id="secure.structure.begin", protocol_digest=protocol_digest,
        instance_id=instance_id)
    assert counts(origin)["commits"] == baseline + 1
    del owner
    fresh = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    saved = fresh.private_package_installer(workspace_id).installs()
    assert len(saved) == 1 and saved[0]["source_kind"] == "DIRECT"
    assert saved[0]["locally_saved"] is True and "stage_id" not in saved[0]
    assert saved[0]["protocol_digest"] == protocol_digest and saved[0]["instance_id"] == instance_id
    begin_id = saved[0]["begin_command_id"]
    steps = []
    progress = cli(config_file, "owner-private-install-continue", workspace_id, begin_id)
    for _ in range(12):
        assert progress["step_action_id"] in {"secure.structure.page", "secure.structure.end"}
        if not steps or progress["step_command_id"] != steps[-1]["command_id"]:
            assert all(progress["step_command_id"] != item["command_id"] for item in steps)
            steps.append(dict(action_id=progress["step_action_id"],
                              command_id=progress["step_command_id"],
                              commit_hash=progress["commit_hash"]))
        if progress["status"] == "ACCEPTED":
            break
        assert progress["status"] == "PENDING"
        progress = fresh.private_package_installer(workspace_id).continue_install(begin_id)
    assert progress["status"] == "ACCEPTED"
    assert steps and steps[-1]["action_id"] == "secure.structure.end"
    assert any(step["action_id"] == "secure.structure.page" for step in steps)
    assert counts(origin)["commits"] == baseline + 1 + len(steps)
    active = fresh.read(workspace_id)
    assert active["structure_status"] == "ACTIVE"
    active_policy = policy_oracle(workspace_id, active)
    assert active_policy["v"] == 3 and active_policy["protocol_format_ceiling"] == 2
    assert active_policy["structure_mode"] == "STRUCTURED"
    assert active_policy["members"][0]["actor_id"] == owner_actor
    assert any(scope.get("instance_id") == instance_id and scope.get("actions") ==
        ["lib.replace", "lib.produce"] for scope in active_policy["members"][0]["scopes"])
    old_record = next(row for row in active["objects"] if row.get("id") == old_record_id)
    assert old_record["value"]["payload"] == old_payload
    protocol = next(row for row in active["objects"] if row.get("kind") == "protocols"
                    and row.get("id") == protocol_digest)
    assert protocol["value"]["manifest"]["format_version"] == 2
    composition = protocol["value"]["composition"]
    assert composition["v"] == 1 and composition["source_digest"] == source_digest
    assert composition["source_manifest"] == dict(name="Typed imports", display_version="1",
        semantics="peerwork.kernel.v1", dependencies=[
            "907b06da48ee65359c91c9c015b6ed7ee1a0c7e9b5844b7bdf2e091e97b2b99a"],
        protocol_roles=[], capabilities=[], role_conflicts=[], historical_role_conflicts=[],
        constraints={}, record_schemas={}, initial_state={}, actions=[])
    assert len(composition["dependencies"]) == 1
    assert any(row.get("kind") == "instances" and row.get("id") == instance_id
        and row["value"]["protocol_digest"] == protocol_digest for row in active["objects"])
    assert fresh.private_package_stager(workspace_id).stages() == []

    action = fresh.private_actions(workspace_id).submit("lib.replace", instance_id,
        {"value": [{"label": "installed typed direct"}, True]})
    assert action["status"] == "PENDING"
    accepted = fresh.private_actions(workspace_id).retry_saved(action["command_id"])
    assert accepted["status"] == "ACCEPTED"
    after_action = counts(origin)["commits"]
    assert fresh.private_actions(workspace_id).retry_saved(action["command_id"]) == accepted
    assert counts(origin)["commits"] == after_action
    verified = fresh.read(workspace_id)
    instance = next(row for row in reversed(verified["objects"])
                    if row.get("kind") == "instances" and row.get("id") == instance_id)
    assert instance["value"]["state"]["lib"]["data"] == [
        {"label": "installed typed direct"}, True]
    assert next(row for row in verified["objects"] if row.get("id") == old_record_id)["value"]["payload"] == old_payload
    before_retry = counts(origin)["commits"]
    assert cli(config_file, "owner-private-install-continue", workspace_id, begin_id)["status"] == "ACCEPTED"
    assert fresh.private_package_installer(workspace_id).continue_install(begin_id)["status"] == "ACCEPTED"
    assert counts(origin)["commits"] == before_retry
    assert counts(origin)["head_sequence"] == verified["sequence"]

    server.terminate()
    server.wait(timeout=5)
    python_rows = fresh.private_package_installer(workspace_id).installs()
    node_rows = node_call(config, workspace_id, "installs")
    assert node_rows.returncode == 0, node_rows.stderr[-1000:]
    cli_rows = cli(config_file, "owner-private-install-list", workspace_id)
    assert python_rows == json.loads(node_rows.stdout) == cli_rows == saved
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id,
        root_package_digest=root_digest, protocol_digest=protocol_digest,
        composition_source_digest=source_digest, begin_command_id=begin_id,
        instance_id=instance_id, old_record_id=old_record_id,
        source_kind="DIRECT", stage_count=0, steps=steps,
        final_sequence=verified["sequence"], saved_id_recovery=True,
        signed_active=True, typed_action=True, offline_history=True)))
finally:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
