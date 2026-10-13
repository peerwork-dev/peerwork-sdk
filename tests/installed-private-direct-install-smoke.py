"""Installed PRIVATE unstructured-v3 direct install with encrypted prior record.

This is a scripted public-API test. It performs no package stage POST and does
not establish Agent workflow or platform-matrix compliance.
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
SECOND_MODE = os.environ.get("PEERWORK_TEST_PRIVATE_DIRECT_SECOND", "0")
assert SECOND_MODE in {"0", "1"}
SECOND = SECOND_MODE == "1"
for relative, variable in (
    ("crates/runtime/src/secure_private_install.rs", "PEERWORK_TEST_INSTALL_SOURCE_SHA256"),
    ("crates/core/src/secure_replay.rs", "PEERWORK_TEST_REPLAY_SOURCE_SHA256"),
    ("crates/core/src/public_direct_install.rs", "PEERWORK_TEST_DIRECT_COMPILER_SHA256"),
    ("crates/runtime/src/secure_owner_create.rs", "PEERWORK_TEST_OWNER_SOURCE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
vector_path = SOURCE / "conformance/public-package-vectors.json"
assert hashlib.sha256(vector_path.read_bytes()).hexdigest() == os.environ["PEERWORK_TEST_VECTOR_SHA256"]
vector = json.loads(vector_path.read_text())
root_digest = vector["closure"]["root_package_digest"]
protocol_digest = vector["protocol_digest"]
assert root_digest == os.environ["PEERWORK_TEST_ROOT_DIGEST"]
assert protocol_digest == os.environ["PEERWORK_TEST_PROTOCOL_DIGEST"]
assert vector["source_digest"] == os.environ["PEERWORK_TEST_SOURCE_DIGEST"]
# Direct selection takes the raw canonical package closure, unlike staged
# selection's source-part material wrapper.
closure_json = json.dumps(vector["closure"], separators=(",", ":"))
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, route):
    with urllib.request.urlopen(urllib.request.Request(origin + route, data=b"{}", method="POST"),
                                timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def signed_policy(workspace_id, verified_read):
    """Read the pinned service's accepted policy as a test oracle only.

    The public native read supplies the independently verified policy hash and
    journal checkpoint. The service's signed commit row must match that pair.
    This does not expose policy wire or service storage through the SDK, and
    it does not independently verify the service-accepted signature.
    """
    verified_policy_hash = verified_read["policy_hash"]
    database = f"file:{STATE / 'control.sqlite'}?mode=ro"
    with sqlite3.connect(database, uri=True, timeout=10) as connection:
        rows = connection.execute(
            "SELECT version, policy_hash, effective_sequence, artifact "
            "FROM secure_policies WHERE workspace_id=? AND policy_hash=?",
            (workspace_id, verified_policy_hash),
        ).fetchall()
        commits = connection.execute(
            "SELECT commit_hash, policy_hash, artifact FROM secure_commits "
            "WHERE workspace_id=? AND sequence=?",
            (workspace_id, verified_read["sequence"]),
        ).fetchall()
    assert len(rows) == 1
    assert len(commits) == 1
    commit_hash, commit_policy_hash, commit_json = commits[0]
    assert commit_hash == verified_read["head"]
    assert commit_policy_hash == verified_policy_hash
    assert hashlib.sha256(commit_json.encode()).hexdigest() == commit_hash
    commit = json.loads(commit_json)
    assert commit["signature"] and commit["payload"]["workspace_id"] == workspace_id
    assert commit["payload"]["sequence"] == verified_read["sequence"]
    version, policy_hash, effective_sequence, artifact_json = rows[0]
    assert hashlib.sha256(artifact_json.encode()).hexdigest() == policy_hash
    artifact = json.loads(artifact_json)
    assert artifact["signature"] and artifact["payload"]["workspace_id"] == workspace_id
    assert artifact["payload"]["version"] == version
    assert artifact["payload"]["effective_sequence"] == effective_sequence
    return artifact["payload"]


def assert_direct_policy_upgrade(before, after, prior_objects, old_hash,
                                 source_sequence, owner_actor, instance_id,
                                 protocol_digest, requested_scope, source_manifest):
    assert before["visibility"] == after["visibility"] == "PRIVATE"
    assert after["workspace_id"] == before["workspace_id"]
    assert before["v"] == after["v"] == 3
    assert before["structure_mode"] == "NONE" and "structure" not in before
    assert after["structure_mode"] == "STRUCTURED"
    for name in ("owner_id", "signing_key", "epoch", "protocol_format_ceiling"):
        assert after[name] == before[name]
    assert after["owner_id"] == owner_actor
    assert after["version"] == before["version"] + 1
    assert after["previous_policy"] == old_hash
    assert after["effective_sequence"] == source_sequence + 1
    assert len(before["members"]) == len(after["members"]) == 1
    old_member, new_member = before["members"][0], after["members"][0]
    for name in ("actor_id", "certificate", "role"):
        assert old_member[name] == new_member[name]
    assert old_member["actor_id"] == owner_actor
    expected_scope = dict(instance_id=instance_id, **requested_scope)
    assert new_member["scopes"] == old_member["scopes"] + [expected_scope]

    new_structure = after["structure"]
    assert new_structure["v"] == 1
    old_protocols = [row for row in prior_objects if row.get("kind") == "protocols"]
    old_instances = [row for row in prior_objects if row.get("kind") == "instances"]
    assert old_protocols and old_instances
    for old_protocol in old_protocols:
        value = old_protocol["value"]
        digest = value["digest"]
        manifest = value.get("resolved_manifest") or value["manifest"]
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        matches = [row for row in new_structure["protocols"]
                   if row["protocol_digest"] == digest]
        assert len(matches) == 1
        preserved = matches[0]
        assert set(preserved["schemas"]) == set(manifest["record_schemas"])
        for schema, definition in manifest["record_schemas"].items():
            fields = preserved["schemas"][schema]["fields"]
            assert set(fields) == set(definition["fields"])
            for name, source_type in definition["fields"].items():
                assert fields[name] == dict(protection="e2ee", type=source_type)
            disclosures = [row for row in new_structure["disclosure"]
                           if row["protocol_digest"] == digest and row["schema"] == schema]
            assert len(disclosures) == 1 and disclosures[0]["fields"] == []
    for old_instance in old_instances:
        exact = dict(instance_id=old_instance["id"],
                     protocol_digest=old_instance["value"]["protocol_digest"])
        assert new_structure["instances"].count(exact) == 1
    assert len(new_structure["protocols"]) == len(old_protocols) + 1
    assert len(new_structure["instances"]) == len(old_instances) + 1
    matches = [row for row in new_structure["protocols"]
               if row["protocol_digest"] == protocol_digest]
    assert len(matches) == 1
    protocol = matches[0]
    new_instance = dict(instance_id=instance_id, protocol_digest=protocol_digest)
    assert protocol["protocol_digest"] == protocol_digest
    assert new_structure["instances"].count(new_instance) == 1
    disclosures = [row for row in new_structure["disclosure"]
                   if row["protocol_digest"] == protocol_digest]
    assert len(disclosures) == len(protocol["schemas"])
    assert set(protocol["schemas"]) == set(source_manifest["record_schemas"])
    saw_e2ee = False
    for schema, definition in protocol["schemas"].items():
        declared = definition["fields"]
        source_definition = source_manifest["record_schemas"][schema]
        assert set(declared) == set(source_definition["fields"])
        # This pinned proposal source declares no readable fields. Its exact
        # source schema, rather than the resulting policy alone, is the oracle.
        assert "protection" not in source_definition
        for name, source_type in source_definition["fields"].items():
            assert declared[name] == dict(protection="e2ee", type=source_type)
        readable = sorted(name for name, field in declared.items()
                          if field["protection"] == "server_readable")
        e2ee = {name for name, field in declared.items()
                if field["protection"] == "e2ee"}
        saw_e2ee |= bool(e2ee)
        matches = [row for row in disclosures if row["schema"] == schema]
        assert len(matches) == 1 and matches[0]["fields"] == readable
        assert not e2ee.intersection(matches[0]["fields"])
    assert saw_e2ee


def assert_same_protocol_instance_upgrade(before, after, old_hash, source_sequence,
                                          owner_actor, instance_id, protocol_digest,
                                          requested_scope):
    assert before["v"] == after["v"] == 3
    assert before["structure_mode"] == after["structure_mode"] == "STRUCTURED"
    for name in ("workspace_id", "visibility", "owner_id", "signing_key", "epoch",
                 "protocol_format_ceiling"):
        assert before[name] == after[name]
    assert after["visibility"] == "PRIVATE" and after["owner_id"] == owner_actor
    assert after["version"] == before["version"] + 1
    assert after["previous_policy"] == old_hash
    assert after["effective_sequence"] == source_sequence + 1
    assert len(before["members"]) == len(after["members"]) == 1
    old_member, new_member = before["members"][0], after["members"][0]
    for name in ("actor_id", "certificate", "role"):
        assert old_member[name] == new_member[name]
    assert new_member["scopes"] == old_member["scopes"] + [
        dict(instance_id=instance_id, **requested_scope)]
    old_structure, new_structure = before["structure"], after["structure"]
    assert new_structure["protocols"] == old_structure["protocols"]
    assert new_structure["disclosure"] == old_structure["disclosure"]
    for old_instance in old_structure["instances"]:
        assert new_structure["instances"].count(old_instance) == 1
    assert len(new_structure["instances"]) == len(old_structure["instances"]) + 1
    assert new_structure["instances"].count(
        dict(instance_id=instance_id, protocol_digest=protocol_digest)) == 1


def node_call(config, workspace_id, operation, **values):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id,
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUES=json.dumps(values),
               PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const workspace = process.env.PEERWORK_TEST_WORKSPACE;
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'beginWithoutId':
      result = await owner.privatePackageInstaller(workspace).beginDirect(value.selection);
      result = {status: result.status, step_action_id: result.step_action_id,
        protocol_digest: result.protocol_digest, instance_id: result.instance_id};
      break;
    case 'continueInstall':
      result = await owner.privatePackageInstaller(workspace).continueInstall(value.beginId);
      break;
    case 'installs':
      result = await owner.privatePackageInstaller(workspace).installs();
      break;
    case 'propose':
      result = await owner.privateActions(workspace).submit('proposal.propose', value.instanceId,
        {title: value.title, body: value.body});
      break;
    default: throw new Error('unsupported test operation');
  }
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-1600:]
    return json.loads(result.stdout)


def cli(verb, config_file, workspace_id, argument=None):
    command = [CLI, "secure", verb, str(config_file), workspace_id]
    if argument is not None:
        command.append(argument)
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (verb, result.stderr[-1600:])
    return json.loads(result.stdout)


def cli_failure(verb, config_file, workspace_id, argument):
    result = subprocess.run([CLI, "secure", verb, str(config_file), workspace_id, argument],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and not result.stdout
    return json.loads(result.stderr)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    created = owner.create("Installed PRIVATE direct package", "PRIVATE", structured=False)
    assert created["status"] == "CREATED" and created["visibility"] == "PRIVATE"
    workspace_id = created["workspace_id"]
    initial = owner.read(workspace_id)
    assert initial["sequence"] == 1 and initial["structure_status"] == "UNSTRUCTURED"
    initial_policy_hash = initial["policy_hash"]
    owner_actor = peerwork.open_identity(str(owner_dir / "identity.state"))["actor_id"]
    wiki_instances = [row for row in initial["objects"] if row.get("kind") == "instances"]
    assert len(wiki_instances) >= 2
    old_title, old_body = "Before PRIVATE direct install", "Encrypted record survives upgrade"
    old_action = owner.private_actions(workspace_id).submit("wiki.create", wiki_instances[1]["id"],
        {"title": old_title, "body": old_body})
    assert old_action["status"] == "PENDING"
    old_accepted = owner.private_actions(workspace_id).retry_saved(old_action["command_id"])
    assert old_accepted["status"] == "ACCEPTED"
    old_record_id = old_accepted["receipt"]["effects"][0]["record_id"]
    prior = owner.read(workspace_id)
    assert prior["sequence"] == 2 and prior["policy_hash"] == initial_policy_hash
    old_record = next(row for row in prior["objects"] if row.get("id") == old_record_id)
    assert old_record["kind"] == "records"
    assert old_record["value"]["payload"]["title"] == old_title
    assert old_record["value"]["payload"]["body"] == old_body
    old_policy = signed_policy(workspace_id, prior)
    before = counts(origin)["commits"]

    config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    config_file = STATE / "owner.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                           allow_loopback_http=True)))
    assert owner.private_package_stager(workspace_id).stages() == []
    instance_id = secrets.token_urlsafe(32)
    assert len(instance_id) == 43
    requested_scope = dict(actions=["proposal.propose"], protocol_roles=["AUTHOR"],
                           capabilities=["PROPOSE"])
    grants_json = json.dumps([dict(actor_id=owner_actor, **requested_scope)],
                             separators=(",", ":"))
    selection = dict(closureJson=closure_json,
        expectedRootPackageDigest=root_digest,
        expectedProtocolDigest=protocol_digest,
        instanceId=instance_id, entrypoint="proposal", grantsJson=grants_json)
    # Both other entrypoints must reach the explicit direct parser and refuse
    # an invalid closure before persisting a command or committing a POST.
    try:
        owner.private_package_installer(workspace_id).begin_direct("{}", root_digest,
            protocol_digest, instance_id, "proposal", grants_json=grants_json)
    except peerwork.PrivatePackageInstallError as error:
        assert error.code == "INSTALL_PLAN_FAILED"
    else:
        raise AssertionError("Python direct install accepted an invalid closure")
    bad_input = STATE / "invalid-direct.json"
    bad_input.write_text(json.dumps(dict(closure_json="{}",
        expected_root_package_digest=root_digest,
        expected_protocol_digest=protocol_digest,
        instance_id=instance_id, entrypoint="proposal", grants_json=grants_json)))
    assert cli_failure("owner-private-install-begin-direct", config_file,
                       workspace_id, str(bad_input))["code"] == "INSTALL_PLAN_FAILED"
    assert owner.private_package_installer(workspace_id).installs() == []
    assert counts(origin)["commits"] == before
    post(origin, "__test/drop-next-post")
    first = node_call(config, workspace_id, "beginWithoutId", selection=selection)
    assert first == dict(status="PENDING", step_action_id="secure.structure.begin",
                         protocol_digest=protocol_digest, instance_id=instance_id)
    assert counts(origin)["commits"] == before + 1
    del owner
    reopened = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    installs = reopened.private_package_installer(workspace_id).installs()
    assert len(installs) == 1 and installs[0]["locally_saved"] is True
    assert installs[0]["source_kind"] == "DIRECT" and "stage_id" not in installs[0]
    assert installs[0]["workspace_id"] == workspace_id
    assert installs[0]["instance_id"] == instance_id
    assert installs[0]["protocol_digest"] == protocol_digest
    begin_id = installs[0]["begin_command_id"]

    post(origin, "__test/drop-next-post")
    first_step = cli("owner-private-install-continue", config_file, workspace_id, begin_id)
    assert first_step["status"] == "PENDING" and first_step["step_action_id"] == "secure.structure.page"
    assert first_step["begin_command_id"] == begin_id
    assert first_step["step_command_id"] != begin_id and first_step["commit_hash"]
    assert counts(origin)["commits"] == before + 2
    steps = [dict(action_id=first_step["step_action_id"],
                  command_id=first_step["step_command_id"],
                  commit_hash=first_step["commit_hash"])]
    accepted = node_call(config, workspace_id, "continueInstall", beginId=begin_id)
    for _ in range(8):
        if accepted["status"] == "ACCEPTED":
            break
        assert accepted["status"] == "PENDING"
        assert accepted["step_action_id"] in {"secure.structure.page", "secure.structure.end"}
        if accepted["step_command_id"] != steps[-1]["command_id"]:
            assert all(accepted["step_command_id"] != row["command_id"] for row in steps)
            steps.append(dict(action_id=accepted["step_action_id"],
                              command_id=accepted["step_command_id"],
                              commit_hash=accepted["commit_hash"]))
        accepted = node_call(config, workspace_id, "continueInstall", beginId=begin_id)
    assert accepted["status"] == "ACCEPTED" and accepted["step_action_id"] == "secure.structure.end"
    assert steps[-1]["action_id"] == "secure.structure.end"
    assert accepted["step_command_id"] == steps[-1]["command_id"]
    assert counts(origin)["commits"] == before + 1 + len(steps)
    active = reopened.read(workspace_id)
    assert active["structure_status"] == "ACTIVE"
    assert active["policy_hash"] != initial_policy_hash
    new_policy = signed_policy(workspace_id, active)
    assert_direct_policy_upgrade(old_policy, new_policy, prior["objects"], prior["policy_hash"],
                                 prior["sequence"], owner_actor, instance_id,
                                 protocol_digest, requested_scope, vector["compiled_manifest"])
    assert any(row.get("kind") == "instances" and row.get("id") == instance_id
        and row.get("value", {}).get("protocol_digest") == protocol_digest
        for row in active["objects"])
    retained = next(row for row in active["objects"] if row.get("id") == old_record_id)
    assert retained["value"]["payload"]["title"] == old_title
    assert retained["value"]["payload"]["body"] == old_body

    title, body = "Installed direct proposal", "Exact encrypted content after direct install"
    proposed = node_call(config, workspace_id, "propose", instanceId=instance_id,
                         title=title, body=body)
    assert proposed["status"] == "PENDING"
    action_id = proposed["command_id"]
    accepted_action = reopened.private_actions(workspace_id).retry_saved(action_id)
    assert accepted_action["status"] == "ACCEPTED"
    receipt = accepted_action["receipt"]
    assert receipt["actor_id"] == owner_actor and len(receipt["effects"]) == 1
    record_id = receipt["effects"][0]["record_id"]
    read = reopened.read(workspace_id)
    record = next(row for row in read["objects"] if row.get("id") == record_id)
    assert record["kind"] == "records"
    assert record["value"]["payload"]["title"] == title
    assert record["value"]["payload"]["body"] == body
    assert cli("owner-private-action-retry", config_file, workspace_id, action_id)["status"] == "ACCEPTED"
    assert cli("owner-private-install-continue", config_file, workspace_id, begin_id)["status"] == "ACCEPTED"
    assert counts(origin)["commits"] == before + 2 + len(steps)
    assert counts(origin)["head_sequence"] == read["sequence"]
    assert reopened.private_package_stager(workspace_id).stages() == []

    second_result = None
    expected_history = installs
    if SECOND:
        # The next direct source selects the same already installed protocol
        # for a distinct instance. No new protocol/schema is allowed here.
        first_read = read
        first_policy = signed_policy(workspace_id, first_read)
        second_instance = secrets.token_urlsafe(32)
        assert second_instance != instance_id and len(second_instance) == 43
        second_start = counts(origin)["commits"]
        next_begin = reopened.private_package_installer(workspace_id).begin_direct(
            closure_json, root_digest, protocol_digest, second_instance,
            "proposal", grants_json=grants_json)
        assert next_begin["status"] == "PENDING"
        assert next_begin["step_action_id"] == "secure.structure.begin"
        second_begin_id = next_begin["begin_command_id"]
        assert second_begin_id != begin_id
        assert counts(origin)["commits"] == second_start + 1
        expected_history = reopened.private_package_installer(workspace_id).installs()
        history_by_id = {row["begin_command_id"]: row for row in expected_history}
        assert len(history_by_id) == 2 and history_by_id[begin_id] == installs[0]
        assert second_begin_id in history_by_id
        second_row = history_by_id[second_begin_id]
        assert second_row["source_kind"] == "DIRECT" and "stage_id" not in second_row
        assert second_row["instance_id"] == second_instance
        assert second_row["protocol_digest"] == protocol_digest
        second_steps = []
        progress = cli("owner-private-install-continue", config_file, workspace_id,
                       second_begin_id)
        for _ in range(8):
            if progress["status"] == "ACCEPTED":
                break
            assert progress["status"] == "PENDING"
            assert progress["step_action_id"] in {"secure.structure.page", "secure.structure.end"}
            assert progress["begin_command_id"] == second_begin_id
            assert progress["protocol_digest"] == protocol_digest
            assert progress["instance_id"] == second_instance
            if not second_steps or progress["step_command_id"] != second_steps[-1]["command_id"]:
                assert all(progress["step_command_id"] != row["command_id"] for row in second_steps)
                second_steps.append(dict(action_id=progress["step_action_id"],
                    command_id=progress["step_command_id"], commit_hash=progress["commit_hash"]))
            progress = node_call(config, workspace_id, "continueInstall", beginId=second_begin_id)
        assert progress["status"] == "ACCEPTED"
        assert progress["step_action_id"] == "secure.structure.end"
        assert second_steps[-1]["action_id"] == "secure.structure.end"
        assert progress["step_command_id"] == second_steps[-1]["command_id"]
        assert any(row["action_id"] == "secure.structure.page" for row in second_steps)
        assert counts(origin)["commits"] == second_start + 1 + len(second_steps)
        after_second = reopened.read(workspace_id)
        assert after_second["structure_status"] == "ACTIVE"
        after_second_policy = signed_policy(workspace_id, after_second)
        assert_same_protocol_instance_upgrade(first_policy, after_second_policy,
            read["policy_hash"], read["sequence"], owner_actor, second_instance,
            protocol_digest, requested_scope)
        for retained_id, retained_title, retained_body in (
            (old_record_id, old_title, old_body), (record_id, title, body)):
            retained = next(row for row in after_second["objects"] if row.get("id") == retained_id)
            assert retained["value"]["payload"]["title"] == retained_title
            assert retained["value"]["payload"]["body"] == retained_body
        second_title, second_body = "Second direct proposal", "Already installed protocol, new instance"
        next_action = node_call(config, workspace_id, "propose", instanceId=second_instance,
                                title=second_title, body=second_body)
        assert next_action["status"] == "PENDING"
        next_receipt = reopened.private_actions(workspace_id).retry_saved(next_action["command_id"])
        assert next_receipt["status"] == "ACCEPTED"
        assert next_receipt["receipt"]["actor_id"] == owner_actor
        assert len(next_receipt["receipt"]["effects"]) == 1
        second_record_id = next_receipt["receipt"]["effects"][0]["record_id"]
        read = reopened.read(workspace_id)
        before_protocols = [row for row in first_read["objects"] if row.get("kind") == "protocols"]
        after_protocols = [row for row in read["objects"] if row.get("kind") == "protocols"]
        assert len(after_protocols) == len(before_protocols)
        assert {row["id"] for row in after_protocols} == {row["id"] for row in before_protocols}
        second_record = next(row for row in read["objects"] if row.get("id") == second_record_id)
        assert second_record["value"]["payload"]["title"] == second_title
        assert second_record["value"]["payload"]["body"] == second_body
        for retained_id, retained_title, retained_body in (
            (old_record_id, old_title, old_body), (record_id, title, body)):
            retained = next(row for row in read["objects"] if row.get("id") == retained_id)
            assert retained["value"]["payload"]["title"] == retained_title
            assert retained["value"]["payload"]["body"] == retained_body
        assert cli("owner-private-install-continue", config_file, workspace_id,
                   second_begin_id)["status"] == "ACCEPTED"
        assert cli("owner-private-install-continue", config_file, workspace_id,
                   begin_id)["status"] == "ACCEPTED"
        assert counts(origin)["commits"] == second_start + 2 + len(second_steps)
        assert counts(origin)["head_sequence"] == read["sequence"]
        assert reopened.private_package_stager(workspace_id).stages() == []
        second_result = dict(begin_command_id=second_begin_id, instance_id=second_instance,
            record_id=second_record_id, steps=second_steps,
            policy_versions=[first_policy["version"], after_second_policy["version"]])

    server.terminate()
    server.wait(timeout=5)
    rows_python = reopened.private_package_installer(workspace_id).installs()
    rows_node = node_call(config, workspace_id, "installs")
    rows_cli = cli("owner-private-install-list", config_file, workspace_id)
    assert rows_python == rows_node == rows_cli == expected_history
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id,
        begin_command_id=begin_id, source_kind="DIRECT", stage_count=0,
        root_package_digest=root_digest, protocol_digest=protocol_digest,
        source_digest=vector["source_digest"], instance_id=instance_id,
        old_record_id=old_record_id, record_id=record_id,
        install_steps=steps, final_sequence=read["sequence"],
        saved_id_recovery=True, signed_active=True,
        policy_wire_v=old_policy["v"], source_structure_mode=old_policy["structure_mode"],
        installed_structure_mode=new_policy["structure_mode"],
        policy_versions=[old_policy["version"], new_policy["version"]],
        service_policy_oracle_bound=True, second_direct=second_result)))
finally:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
