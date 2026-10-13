"""Installed PUBLIC historical Owner format upgrades through Python, Node, and CLI.

The task-local service policy query is a test oracle bound to native verified
readback. It does not export a signing key or replace native verification.
"""

import hashlib
import json
import os
from pathlib import Path
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
for relative, variable in (
    ("crates/core/src/prepared_owner_format.rs", "PEERWORK_TEST_PREPARE_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_format_transition.rs", "PEERWORK_TEST_TRANSITION_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("crates/runtime/src/secure_owner_create.rs", "PEERWORK_TEST_OWNER_SOURCE_SHA256"),
    ("tests/legacy-owner-source.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
assert subprocess.check_output(["git", "-C", str(LEGACY), "rev-parse", "HEAD"],
                               text=True).strip() == os.environ["PEERWORK_TEST_LEGACY_COMMIT"]
assert subprocess.run(["git", "-C", str(LEGACY), "diff", "--quiet", "HEAD", "--",
                       "src", "package.json", "package-lock.json"], check=False).returncode == 0
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, route):
    with urllib.request.urlopen(urllib.request.Request(origin + route, data=b"{}", method="POST"),
                                timeout=10) as response:
        return json.load(response)


def commit_count(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)["commits"]


def signed_policy(workspace_id, verified):
    with sqlite3.connect(f"file:{STATE / 'control.sqlite'}?mode=ro", uri=True, timeout=10) as db:
        policies = db.execute(
            "SELECT policy_hash, artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?",
            (workspace_id, verified["policy_hash"])).fetchall()
        commits = db.execute(
            "SELECT commit_hash, policy_hash, artifact FROM secure_commits "
            "WHERE workspace_id=? AND sequence=?", (workspace_id, verified["sequence"])).fetchall()
    assert len(policies) == len(commits) == 1
    commit_hash, commit_policy_hash, commit_json = commits[0]
    assert commit_hash == verified["head"] and commit_policy_hash == verified["policy_hash"]
    assert hashlib.sha256(commit_json.encode()).hexdigest() == commit_hash
    commit = json.loads(commit_json)
    assert commit["signature"] and commit["payload"]["sequence"] == verified["sequence"]
    policy_hash, artifact_json = policies[0]
    assert policy_hash == verified["policy_hash"]
    assert hashlib.sha256(artifact_json.encode()).hexdigest() == policy_hash
    artifact = json.loads(artifact_json)
    assert artifact["signature"]
    return artifact["payload"]


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUE);
  const result = process.env.PEERWORK_TEST_OPERATION === 'submit'
    ? await owner.submitFormatTransition(value.input)
    : process.env.PEERWORK_TEST_OPERATION === 'resume'
      ? await owner.resumeFormatTransition(value.workspaceId, value.commandId)
      : await owner.formatTransitions(value.workspaceId);
  // A lost submit result must be recovered from protected history, not this child.
  console.log(JSON.stringify(process.env.PEERWORK_TEST_OPERATION === 'submit'
    ? {status:result.status} : result));
})().catch(error => {
  console.log(JSON.stringify({code:error.code,message:error.message}));
  process.exitCode = 1;
});
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_CONFIG=json.dumps(config),
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUE=json.dumps(values))
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stdout[-800:] + result.stderr[-800:]
    return json.loads(result.stdout)


def cli(config_file, verb, *arguments):
    result = subprocess.run([CLI, "secure", verb, str(config_file),
                             *(str(argument) for argument in arguments)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_OWNER_FORMAT="1", PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    cases = []
    # Both genuine old-client workspaces must be created while cutover is PREPARE.
    for mode, expected_v, expected_structure_mode in (
        ("legacy-public", 1, "NONE"),
        ("legacy-public-structured", 2, "STRUCTURED"),
    ):
        source_dir = STATE / mode
        setup = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
                                origin, str(source_dir), str(LEGACY), mode],
                               cwd=SOURCE, capture_output=True, text=True, timeout=120)
        assert setup.returncode == 0, setup.stderr[-800:]
        source = json.loads(setup.stdout)
        assert source["policy_v"] == expected_v and source["pending_count"] == 0
        root = STATE / (mode + "-native")
        owner = peerwork.SecureOwnerWorkspaceClient(origin, str(root), allow_loopback_http=True)
        workspace_id = source["workspace_id"]
        attached = owner.attach(workspace_id, source["state_path"], source["intent_db_path"],
                                source["pem_path"], source["owner_actor_id"], source["owner_key_id"])
        assert attached["status"] == "ATTACHED" and attached["provenance"] == "HISTORICAL_TS_OWNER"
        before = owner.read(workspace_id)
        policy = signed_policy(workspace_id, before)
        assert policy["v"] == expected_v and policy["visibility"] == "PUBLIC"
        assert policy["epoch"] == 0 and "structure_mode" not in policy
        assert bool(policy.get("structure")) == (expected_v == 2)
        old_record_id = source["prior_record_id"]
        assert old_record_id
        old_record = next(row for row in before["objects"] if row.get("id") == old_record_id)
        assert old_record["value"]["payload"]["title"] == source["prior_record_title"]
        assert old_record["value"]["payload"]["body"] == source["prior_record_body"]
        config = dict(origin=origin, stateDir=str(root), allowLoopbackHttp=True)
        config_file = STATE / (mode + "-config.json")
        config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(root),
                                               allow_loopback_http=True)))
        cases.append((mode, source, owner, before, policy, config, config_file))

    assert post(origin, "__test/activate-protocol-cutover")["phase"] == "ENFORCE"
    results = []
    for mode, source, owner, before, policy, config, config_file in cases:
        workspace_id = source["workspace_id"]
        baseline = commit_count(origin)
        assert post(origin, "__test/drop-next-post")["enabled"] is True
        withheld = node_call(config, "submit", input=dict(workspaceId=workspace_id,
            transition="UPGRADE_WIRE_V3"))
        assert withheld == {"status": "PENDING"}
        fresh = peerwork.SecureOwnerWorkspaceClient(origin, str(STATE / (mode + "-native")),
                                                     allow_loopback_http=True)
        saved = fresh.format_transitions(workspace_id)
        assert len(saved) == 1 and saved[0]["status"] == "PENDING"
        assert saved[0]["workspace_id"] == workspace_id
        command_id = saved[0]["command_id"]
        wrong_workspace = "z" * 43 if workspace_id != "z" * 43 else "y" * 43
        try:
            fresh.resume_format_transition(wrong_workspace, command_id)
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == "NOT_FOUND"
        else:
            raise AssertionError("a different workspace must not resolve the saved command")
        assert commit_count(origin) == baseline + 1
        accepted = cli(config_file, "owner-format-resume", workspace_id, command_id)
        assert accepted["status"] == "ACCEPTED" and accepted["command_id"] == command_id
        assert accepted["transition"] == "UPGRADE_WIRE_V3"
        assert commit_count(origin) == baseline + 1
        after = fresh.read(workspace_id)
        upgraded = signed_policy(workspace_id, after)
        assert after["sequence"] == before["sequence"] + 1
        assert upgraded["v"] == 3 and upgraded["protocol_format_ceiling"] == 1
        assert upgraded["visibility"] == "PUBLIC" and upgraded["epoch"] == 0
        assert upgraded["workspace_id"] == workspace_id
        assert upgraded["structure_mode"] == policy["structure_mode"]
        assert upgraded.get("structure") == policy.get("structure")
        for field in ("owner_id", "signing_key", "members"):
            assert upgraded[field] == policy[field], field
        assert upgraded["version"] == policy["version"] + 1
        assert upgraded["previous_policy"] == before["policy_hash"]
        assert upgraded["effective_sequence"] == after["sequence"]
        assert accepted["sequence"] == after["sequence"]
        assert accepted["policy_hash"] == after["policy_hash"]
        old_record = next(row for row in after["objects"] if row.get("id") == source["prior_record_id"])
        assert old_record["value"]["payload"]["title"] == source["prior_record_title"]
        assert old_record["value"]["payload"]["body"] == source["prior_record_body"]
        assert fresh.resume_format_transition(workspace_id, command_id) == accepted
        assert node_call(config, "resume", workspaceId=workspace_id,
                         commandId=command_id) == accepted
        assert commit_count(origin) == baseline + 1
        try:
            fresh.submit_format_transition(workspace_id, "RAISE_PRIVATE_CEILING_TWO")
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == "INPUT_INVALID"
        else:
            raise AssertionError("PUBLIC ceiling raise must be refused")
        assert commit_count(origin) == baseline + 1
        assert fresh.read(workspace_id)["sequence"] == after["sequence"]
        wiki_instance = next(row["id"] for row in after["objects"]
                             if row.get("kind") == "instances"
                             and row.get("value", {}).get("origin_entrypoint") == "wiki")
        title = "After PUBLIC upgrade " + mode
        body = "Native authored effect remains readable"
        submitted = fresh.public_actions(workspace_id).submit(
            "wiki.create", wiki_instance, {"title": title, "body": body})
        action_id = submitted["command_id"]
        action = fresh.public_actions(workspace_id).reconcile(action_id)
        assert action["status"] == "ACCEPTED"
        assert action["receipt"]["effects"] and action["sequence"] == after["sequence"] + 1
        new_record_id = action["receipt"]["effects"][0]["record_id"]
        used = fresh.read(workspace_id)
        assert used["sequence"] == after["sequence"] + 1
        assert signed_policy(workspace_id, used) == upgraded
        new_record = next(row for row in used["objects"] if row.get("id") == new_record_id)
        assert new_record["value"]["payload"]["title"] == title
        assert new_record["value"]["payload"]["body"] == body
        assert fresh.public_actions(workspace_id).retry_saved(action_id) == action
        assert commit_count(origin) == baseline + 2
        assert fresh.read(workspace_id)["sequence"] == used["sequence"]
        results.append((workspace_id, command_id, after["sequence"], config, config_file, fresh,
                        source["prior_record_id"], new_record_id))

    server.terminate()
    server.wait(timeout=5)
    for workspace_id, command_id, sequence, config, config_file, owner, _, _ in results:
        expected = owner.format_transitions(workspace_id)
        assert len(expected) == 1 and expected[0]["command_id"] == command_id
        assert expected[0]["status"] == "ACCEPTED" and expected[0]["sequence"] == sequence
        assert node_call(config, "history", workspaceId=workspace_id) == expected
        assert cli(config_file, "owner-format-history", workspace_id) == expected
    print(json.dumps(dict(status="PASS", sources=[
        dict(workspace_id=workspace_id, command_id=command_id, upgrade_sequence=sequence,
             prior_record_id=old_record_id, new_record_id=new_record_id)
        for workspace_id, command_id, sequence, _, _, _, old_record_id, new_record_id in results])))
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
