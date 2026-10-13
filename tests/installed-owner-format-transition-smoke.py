"""Scripted installed Owner format transitions through public SDK interfaces.

The pinned service SQLite policy query below is a test-only oracle, bound to
native verified read; it is not a public SDK policy export or signature verifier.
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


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)["commits"]


def policy_oracle(workspace_id, verified):
    database = f"file:{STATE / 'control.sqlite'}?mode=ro"
    with sqlite3.connect(database, uri=True, timeout=10) as connection:
        rows = connection.execute(
            "SELECT version, policy_hash, effective_sequence, artifact FROM secure_policies "
            "WHERE workspace_id=? AND policy_hash=?",
            (workspace_id, verified["policy_hash"]),
        ).fetchall()
        commits = connection.execute(
            "SELECT commit_hash, policy_hash, artifact FROM secure_commits "
            "WHERE workspace_id=? AND sequence=?",
            (workspace_id, verified["sequence"]),
        ).fetchall()
    assert len(rows) == len(commits) == 1
    commit_hash, commit_policy_hash, commit_json = commits[0]
    assert commit_hash == verified["head"]
    assert commit_policy_hash == verified["policy_hash"]
    assert hashlib.sha256(commit_json.encode()).hexdigest() == commit_hash
    commit = json.loads(commit_json)
    assert commit["signature"] and commit["payload"]["sequence"] == verified["sequence"]
    version, policy_hash, effective_sequence, artifact_json = rows[0]
    assert policy_hash == verified["policy_hash"]
    assert hashlib.sha256(artifact_json.encode()).hexdigest() == policy_hash
    artifact = json.loads(artifact_json)
    assert artifact["signature"] and artifact["payload"]["version"] == version
    assert artifact["payload"]["effective_sequence"] == effective_sequence
    return artifact["payload"]


def node_call(config, operation, **values):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_CONFIG));
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUE);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'submit': result = await owner.submitFormatTransition(value.input); break;
    case 'resume': result = await owner.resumeFormatTransition(value.commandId); break;
    case 'history': result = await owner.formatTransitions(); break;
    default: throw new Error('unsupported format transition test operation');
  }
  // The submit child intentionally withholds its generated ID from its caller.
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


def cli(config_file, verb, argument=None):
    command = [CLI, "secure", verb, str(config_file)]
    if argument is not None:
        command.append(str(argument))
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    source_dir = STATE / "legacy-source"
    setup = subprocess.run([NODE, str(SOURCE / "tests/legacy-owner-source.mjs"),
                            origin, str(source_dir), str(LEGACY), "clean"],
                           cwd=SOURCE, capture_output=True, text=True, timeout=120)
    assert setup.returncode == 0, setup.stderr[-800:]
    source = json.loads(setup.stdout)
    assert source["policy_v"] == 1 and source["pending_count"] == 0
    workspace_id = source["workspace_id"]
    root = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(root), allow_loopback_http=True)
    config = dict(origin=origin, stateDir=str(root), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(root),
                                           allow_loopback_http=True)))
    attached = owner.attach(workspace_id, source["state_path"], source["intent_db_path"],
                            source["pem_path"], source["owner_actor_id"], source["owner_key_id"])
    assert attached["status"] == "ATTACHED" and attached["provenance"] == "HISTORICAL_TS_OWNER"
    before = owner.read(workspace_id)
    before_policy = policy_oracle(workspace_id, before)
    assert before_policy["v"] == 1 and before_policy["visibility"] == "PRIVATE"

    wiki = next(row["id"] for row in before["objects"] if row.get("kind") == "instances"
                and row.get("value", {}).get("origin_entrypoint") == "wiki")
    title, body = "Before ENFORCE", "Encrypted legacy content survives both transitions"
    submitted = owner.private_actions(workspace_id).submit("wiki.create", wiki,
        {"title": title, "body": body})
    accepted = owner.private_actions(workspace_id).retry_saved(submitted["command_id"])
    assert accepted["status"] == "ACCEPTED" and len(accepted["receipt"]["effects"]) == 1
    record_id = accepted["receipt"]["effects"][0]["record_id"]
    prior = owner.read(workspace_id)
    assert prior["sequence"] == before["sequence"] + 1
    prior_policy = policy_oracle(workspace_id, prior)
    assert prior_policy == before_policy
    baseline_commits = counts(origin)

    assert post(origin, "__test/drop-next-post")["enabled"] is True
    withheld = node_call(config, "submit", input=dict(workspaceId=workspace_id,
        transition="UPGRADE_WIRE_V3"))
    assert withheld == {"status": "PENDING"}
    fresh = peerwork.SecureOwnerWorkspaceClient(origin, str(root), allow_loopback_http=True)
    saved = fresh.format_transitions()
    assert len(saved) == 1 and saved[0]["transition"] == "UPGRADE_WIRE_V3"
    assert saved[0]["status"] == "PENDING" and saved[0]["workspace_id"] == workspace_id
    first_id = saved[0]["command_id"]
    first = cli(config_file, "owner-format-resume", first_id)
    assert first["command_id"] == first_id and first["status"] == "ACCEPTED"
    assert first["transition"] == "UPGRADE_WIRE_V3"
    assert counts(origin) == baseline_commits + 1
    first_read = fresh.read(workspace_id)
    first_policy = policy_oracle(workspace_id, first_read)
    assert first_read["sequence"] == prior["sequence"] + 1
    assert first_policy["v"] == 3 and first_policy["protocol_format_ceiling"] == 1
    assert first_policy["visibility"] == before_policy["visibility"] == "PRIVATE"
    assert first_policy["workspace_id"] == before_policy["workspace_id"] == workspace_id
    assert first_policy["structure_mode"] == "NONE" and "structure" not in first_policy
    for key in ("owner_id", "signing_key", "epoch", "members"):
        assert first_policy[key] == prior_policy[key], key
    assert first_policy["version"] == prior_policy["version"] + 1
    assert first_policy["previous_policy"] == prior["policy_hash"]
    assert first_policy["effective_sequence"] == first_read["sequence"]
    assert first["sequence"] == first_read["sequence"] and first["policy_hash"] == first_read["policy_hash"]
    assert fresh.resume_format_transition(first_id) == first
    assert counts(origin) == baseline_commits + 1

    second = fresh.submit_format_transition(workspace_id, "RAISE_PRIVATE_CEILING_TWO")
    assert second["transition"] == "RAISE_PRIVATE_CEILING_TWO"
    second_id = second["command_id"]
    assert second_id != first_id
    if second["status"] == "PENDING":
        second = node_call(config, "resume", commandId=second_id)
    assert second["status"] == "ACCEPTED" and second["command_id"] == second_id
    assert counts(origin) == baseline_commits + 2
    final = fresh.read(workspace_id)
    final_policy = policy_oracle(workspace_id, final)
    assert final["sequence"] == first_read["sequence"] + 1
    assert final_policy["v"] == 3 and final_policy["protocol_format_ceiling"] == 2
    assert final_policy["visibility"] == first_policy["visibility"] == "PRIVATE"
    assert final_policy["workspace_id"] == workspace_id
    for key in ("owner_id", "signing_key", "epoch", "members", "structure_mode"):
        assert final_policy[key] == first_policy[key], key
    assert final_policy.get("structure") == first_policy.get("structure")
    assert final_policy["version"] == first_policy["version"] + 1
    assert final_policy["previous_policy"] == first_read["policy_hash"]
    assert final_policy["effective_sequence"] == final["sequence"]
    assert second["sequence"] == final["sequence"] and second["policy_hash"] == final["policy_hash"]
    record = next(row for row in final["objects"] if row.get("id") == record_id)
    assert record["value"]["payload"]["title"] == title
    assert record["value"]["payload"]["body"] == body
    assert node_call(config, "resume", commandId=second_id) == second
    assert fresh.resume_format_transition(first_id) == first
    assert counts(origin) == baseline_commits + 2

    server.terminate()
    server.wait(timeout=5)
    expected = fresh.format_transitions()
    assert len(expected) == 2 and {row["command_id"] for row in expected} == {first_id, second_id}
    assert all(row["status"] == "ACCEPTED" for row in expected)
    assert node_call(config, "history") == expected
    assert cli(config_file, "owner-format-history") == expected
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id, source_policy_v=1,
        first_command_id=first_id, second_command_id=second_id,
        record_id=record_id, final_sequence=final["sequence"])))
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=5)
