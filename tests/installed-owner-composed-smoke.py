"""Installed native Owner create, composed install, and proposal action against the pinned service."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
EXPECTED_HASH = os.environ["PEERWORK_TEST_OWNER_SOURCE_SHA256"]
actual_hash = hashlib.sha256((SOURCE / "crates/runtime/src/secure_owner_create.rs").read_bytes()).hexdigest()
assert actual_hash == EXPECTED_HASH, "immutable Owner runtime source mismatch"
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, path):
    request = urllib.request.Request(origin + path, data=b"{}", method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def node_call(config, kind, workspace_id, operation, command_id):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_KIND=kind,
               PEERWORK_TEST_OPERATION=operation, PEERWORK_TEST_COMMAND_ID=command_id)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const root = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const workspace = process.env.PEERWORK_TEST_WORKSPACE;
  const id = process.env.PEERWORK_TEST_COMMAND_ID;
  const value = process.env.PEERWORK_TEST_KIND === 'install'
    ? await root.publicInstaller(workspace).continueInstall(id)
    : await root.publicActions(workspace).reconcile(id);
  console.log(JSON.stringify(value));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-1800:]
    return json.loads(result.stdout)


server_env = dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                  PEERWORK_TEST_FIRST_POST_MODE="normal")
server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
                          cwd=SOURCE, env=server_env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    ready = json.loads(line)
    origin = ready["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    prepared = owner.prepare("Native composed proposal workspace", "PUBLIC", structured=True)
    assert prepared["status"] == "PENDING"
    before = counts(origin)
    post(origin, "__test/drop-next-post")
    uncertain = owner.resume(prepared["command_id"])
    assert uncertain["status"] == "PENDING"
    after_apply = counts(origin)
    assert after_apply["commits"] == before["commits"] + 1
    del prepared
    reopened = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    rows = reopened.operations()
    assert len(rows) == 1 and rows[0]["status"] == "PENDING"
    command_id, workspace_id = rows[0]["command_id"], rows[0]["workspace_id"]
    created = reopened.resume(command_id)
    assert created["status"] == "CREATED" and created["sequence"] == 1
    assert counts(origin)["commits"] == after_apply["commits"]
    assert reopened.operations()[0]["status"] == "CREATED_LOCAL"
    initial = reopened.read(workspace_id)
    assert initial["sequence"] == 1
    identity = peerwork.open_identity(str(owner_dir / "identity.state"))
    actor_id = identity["actor_id"]
    instances = [row for row in initial["objects"] if row.get("kind") == "instances"]
    assert len(instances) >= 2
    wiki_instance = instances[1]["id"]
    wiki = reopened.public_actions(workspace_id).submit(
        "wiki.create", wiki_instance, {"title": "Before composed install", "body": "Preserved by PAGE"})
    assert wiki["status"] == "PENDING"
    wiki_accepted = reopened.public_actions(workspace_id).reconcile(wiki["command_id"])
    assert wiki_accepted["status"] == "ACCEPTED" and wiki_accepted["sequence"] == 2
    wiki_record_id = wiki_accepted["receipt"]["effects"][0]["record_id"]

    vector = json.loads((SOURCE / "conformance/official-proposal-task-composition.json").read_text())
    instance_id = "z" * 43
    grants = [dict(actor_id=actor_id,
                   actions=["proposal.proposal.propose", "tasks.task.create_from_proposal"],
                   protocol_roles=["proposal.AUTHOR", "tasks.MANAGER"],
                   capabilities=["proposal.PROPOSE", "tasks.MANAGE"], expires_at=None)]
    selection = dict(closure_json=json.dumps(vector["closure"], separators=(",", ":")),
                     expected_package_id="peerwork-tasks-proposal-adoption",
                     expected_package_version="2.0.0",
                     expected_package_digest=vector["root_package_digest"],
                     expected_protocol_digest=vector["protocol_digest"],
                     instance_id=instance_id, entrypoint="proposalTasks",
                     grants_json=json.dumps(grants, separators=(",", ":")))
    installer = reopened.public_installer(workspace_id)
    begin = installer.begin(**selection)
    assert begin["status"] == "PENDING"
    node_config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    progress = node_call(node_config, "install", workspace_id, "continue", begin["command_id"])
    steps = [progress["step_action_id"]]
    for _ in range(8):
        if progress["status"] == "ACCEPTED":
            break
        progress = installer.continue_install(begin["command_id"])
        steps.append(progress["step_action_id"])
    assert progress["status"] == "ACCEPTED", progress
    assert "secure.structure.page" in steps and "secure.structure.end" in steps, steps
    active = reopened.read(workspace_id)
    assert active["structure_status"] == "ACTIVE"
    assert any(row.get("id") == wiki_record_id for row in active["objects"])

    proposal_id = "p" * 43
    submitted = reopened.public_actions(workspace_id).submit(
        "proposal.proposal.propose", instance_id,
        {"title": "Native Owner proposal", "body": "Composed package authority"},
        command_id=proposal_id)
    assert submitted["status"] == "PENDING"
    accepted = node_call(node_config, "action", workspace_id, "reconcile", proposal_id)
    assert accepted["status"] == "ACCEPTED" and len(accepted["receipt"]["effects"]) == 1
    candidate_id = accepted["receipt"]["effects"][0]["record_id"]
    final = reopened.read(workspace_id)
    candidate = next(row for row in final["objects"] if row.get("id") == candidate_id)
    assert candidate["value"]["schema_ref"] == "proposal.proposal.candidate"
    assert candidate["value"]["payload"]["author"] == actor_id
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                         allow_loopback_http=True,
                                         max_replay_artifact_bytes=64 * 1024 * 1024)))
    retry = subprocess.run([CLI, "secure", "owner-action-retry", str(config_file), workspace_id, proposal_id],
                           capture_output=True, text=True, timeout=120)
    assert retry.returncode == 0, retry.stderr[-1800:]
    assert json.loads(retry.stdout)["status"] == "ACCEPTED"
    assert counts(origin)["head_sequence"] == final["sequence"]
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id, owner_actor_id=actor_id,
                          wiki_record_id=wiki_record_id, candidate_id=candidate_id,
                          install_steps=steps, final_sequence=final["sequence"],
                          source_sha256=actual_hash)))
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
