"""Installed native Owner and recipient complete the official composed workflow.

The tracked TypeScript service provides HTTP and verification only. Both actors,
membership admission, package install, and business actions use installed APIs.
"""

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
EXPECTED_OWNER_HASH = "ef796c041f7321f1ed479bd5ab8676ff3389758d1b7318cd8422243a460164cd"
assert hashlib.sha256((SOURCE / "crates/runtime/src/secure_owner_create.rs").read_bytes()).hexdigest() == EXPECTED_OWNER_HASH
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, path):
    with urllib.request.urlopen(urllib.request.Request(origin + path, data=b"{}", method="POST"), timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def node_call(config, kind, workspace_id, command_id):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_KIND=kind,
               PEERWORK_TEST_COMMAND_ID=command_id, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE)
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


def cli(*args):
    result = subprocess.run([CLI, "secure", *args], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (args, result.stderr[-1800:])
    return json.loads(result.stdout)


server_env = dict(os.environ, PEERWORK_TEST_STATE=str(STATE), PEERWORK_TEST_FIRST_POST_MODE="normal")
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
    prepared = owner.prepare("Native proposal adoption task", "PUBLIC", structured=True)
    assert prepared["status"] == "PENDING"
    before = counts(origin)
    post(origin, "__test/drop-next-post")
    assert owner.resume(prepared["command_id"])["status"] == "PENDING"
    after_apply = counts(origin)
    assert after_apply["commits"] == before["commits"] + 1
    del prepared
    reopened = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    rows = reopened.operations()
    assert len(rows) == 1 and rows[0]["status"] == "PENDING"
    command_id, workspace_id = rows[0]["command_id"], rows[0]["workspace_id"]
    assert reopened.resume(command_id)["status"] == "CREATED"
    assert counts(origin)["commits"] == after_apply["commits"]
    owner_identity = peerwork.open_identity(str(owner_dir / "identity.state"))
    owner_actor, owner_key = owner_identity["actor_id"], owner_identity["key_id"]
    assert reopened.read(workspace_id)["sequence"] == 1

    # Prepare exact compiled closure, retain one existing record through PAGE.
    initial_instances = [obj for obj in reopened.read(workspace_id)["objects"] if obj.get("kind") == "instances"]
    wiki = reopened.public_actions(workspace_id).submit("wiki.create", initial_instances[1]["id"],
        {"title": "Before package", "body": "Survives composed PAGE"})
    wiki_result = reopened.public_actions(workspace_id).reconcile(wiki["command_id"])
    assert wiki_result["status"] == "ACCEPTED" and wiki_result["sequence"] == 2
    wiki_id = wiki_result["receipt"]["effects"][0]["record_id"]
    vector = json.loads((SOURCE / "conformance/official-proposal-task-composition.json").read_text())
    instance_id = "z" * 43
    owner_grants = [dict(actor_id=owner_actor,
        actions=["proposal.proposal.propose", "tasks.task.create_from_proposal"],
        protocol_roles=["proposal.AUTHOR", "tasks.MANAGER"],
        capabilities=["proposal.PROPOSE", "tasks.MANAGE"], expires_at=None)]
    selection = dict(closure_json=json.dumps(vector["closure"], separators=(",", ":")),
        expected_package_id="peerwork-tasks-proposal-adoption", expected_package_version="2.0.0",
        expected_package_digest=vector["root_package_digest"],
        expected_protocol_digest=vector["protocol_digest"], instance_id=instance_id,
        entrypoint="proposalTasks", grants_json=json.dumps(owner_grants, separators=(",", ":")))
    installer = reopened.public_installer(workspace_id)
    begin = installer.begin(**selection)
    assert begin["status"] == "PENDING"
    assert begin["package_digest"] == vector["root_package_digest"]
    assert begin["protocol_digest"] == vector["protocol_digest"]
    owner_config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    progress = node_call(owner_config, "install", workspace_id, begin["command_id"])
    steps = [progress["step_action_id"]]
    for _ in range(8):
        if progress["status"] == "ACCEPTED":
            break
        progress = installer.continue_install(begin["command_id"])
        steps.append(progress["step_action_id"])
    assert progress["status"] == "ACCEPTED", progress
    assert progress["package_digest"] == vector["root_package_digest"]
    assert progress["protocol_digest"] == vector["protocol_digest"]
    assert "secure.structure.page" in steps and "secure.structure.end" in steps
    installed = reopened.read(workspace_id)
    wiki_record = next(obj for obj in installed["objects"] if obj.get("id") == wiki_id)
    assert wiki_record["value"]["payload"]["title"] == "Before package"
    assert wiki_record["value"]["payload"]["body"] == "Survives composed PAGE"

    # Recipient creation/publication and Owner's certificate lookup are native.
    recipient_dir = STATE / "native-recipient"
    recipient = peerwork.SecureRecipientEnrollmentClient(origin, str(recipient_dir), allow_loopback_http=True)
    local = recipient.create_local()
    assert local["status"] == "LOCAL" and local["actor_id"] != owner_actor
    publication = recipient.publish()
    for _ in range(3):
        if publication["status"] == "PUBLISHED":
            break
        publication = recipient.publish()
    assert publication["status"] == "PUBLISHED", publication
    directory = peerwork.SecureIdentityDirectoryClient(origin, str(owner_dir), allow_loopback_http=True)
    certificate = directory.lookup(local["actor_id"], local["signing_key_id"])
    assert certificate["certificate_json"] == recipient.certificate_json()
    scopes = [dict(instance_id=instance_id, actions=["proposal.proposal.adopt"],
        protocol_roles=["proposal.ADOPTER"], capabilities=["proposal.ADOPT"], expires_at=None)]
    admission = reopened.public_admission(workspace_id)
    offer = admission.offer(certificate["certificate_json"], json.dumps(scopes), message="Adopt the proposal")
    assert offer["status"] == "PENDING"
    invitation = peerwork.SecureInvitationClient(origin, str(recipient_dir), workspace_id,
        owner_actor, owner_key, allow_loopback_http=True)
    consent = invitation.decide(offer["invite_id"], "ACCEPT")
    assert consent["status"] == "PENDING"
    assert invitation.retry_decision(offer["invite_id"])["decision_hash"] == consent["decision_hash"]
    delivery = admission.deliver(offer["invite_id"])
    assert delivery["status"] in ("PENDING", "AUTHORIZED")
    if delivery["status"] == "PENDING":
        delivery = admission.retry_delivery(delivery["grant_id"])
    assert delivery["status"] == "AUTHORIZED", delivery
    received = invitation.receive(offer["invite_id"])
    if received["status"] == "PENDING":
        received = invitation.retry_receive(offer["invite_id"])
    assert received["status"] == "READY", received

    proposal_id = "p" * 43
    proposal = reopened.public_actions(workspace_id).submit("proposal.proposal.propose", instance_id,
        {"title": "Native proposal", "body": "Decision becomes task"}, command_id=proposal_id)
    assert proposal["status"] == "PENDING"
    accepted = node_call(owner_config, "action", workspace_id, proposal_id)
    assert accepted["status"] == "ACCEPTED"
    assert len(accepted["receipt"]["effects"]) == 1
    assert accepted["receipt"]["actor_id"] == owner_actor
    candidate_id = accepted["receipt"]["effects"][0]["record_id"]
    exact_candidate = {"record_id": candidate_id, "revision": 1}
    candidate = next(obj for obj in reopened.read(workspace_id)["objects"] if obj.get("id") == candidate_id)
    assert candidate["value"]["payload"]["title"] == "Native proposal"
    assert candidate["value"]["payload"]["body"] == "Decision becomes task"
    assert candidate["value"]["payload"]["author"] == owner_actor

    member_profile = STATE / "recipient-workspace-profile"
    member = peerwork.SecurePublicActionClient(origin, str(member_profile),
        str(recipient_dir / "identity.state"), workspace_id,
        owner_actor_id=owner_actor, owner_key_id=owner_key,
        allow_loopback_http=True)
    assert member.read()["sequence"] == accepted["sequence"]
    adopt_id = "a" * 43
    adopt = member.submit("proposal.proposal.adopt", instance_id,
        {"candidate_ref": exact_candidate}, exact_input_refs=[exact_candidate], command_id=adopt_id)
    assert adopt["status"] == "PENDING"
    adopted = member.reconcile(adopt_id)
    assert adopted["status"] == "ACCEPTED" and adopted["receipt"]["actor_id"] == local["actor_id"]
    adopted_read = member.read()
    instance_versions = [obj for obj in adopted_read["objects"] if obj.get("kind") == "instances" and obj.get("id") == instance_id]
    current = max(instance_versions, key=lambda obj: obj["revision"])
    assert current["value"]["state"]["proposal"]["adopted"] is True
    assert current["value"]["state"]["proposal"]["adopted_ref"] == exact_candidate
    adoption_operation = next(op for op in adopted_read["operations"] if op.get("kind") == "ACTION"
        and op.get("input", {}).get("action_id") == "proposal.proposal.adopt")
    assert adoption_operation["input"]["exact_input_refs"] == [exact_candidate]
    member_config_file = STATE / "member-action.json"
    member_config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(member_profile),
        identity_path=str(recipient_dir / "identity.state"), workspace_id=workspace_id,
        owner_actor_id=owner_actor, owner_key_id=owner_key, allow_loopback_http=True)))
    assert cli("action-retry", str(member_config_file), adopt_id)["status"] == "ACCEPTED"
    assert counts(origin)["head_sequence"] == adopted_read["sequence"]

    task_id = "t" * 43
    task = reopened.public_actions(workspace_id).submit("tasks.task.create_from_proposal", instance_id,
        {"title": "Execute native proposal", "description": "Implement accepted decision",
         "assignee": local["actor_id"], "proposal_ref": exact_candidate},
        exact_input_refs=[exact_candidate], command_id=task_id)
    assert task["status"] == "PENDING"
    task_result = node_call(owner_config, "action", workspace_id, task_id)
    assert task_result["status"] == "ACCEPTED" and len(task_result["receipt"]["effects"]) == 1
    assert task_result["receipt"]["actor_id"] == owner_actor
    task_record_id = task_result["receipt"]["effects"][0]["record_id"]
    final = reopened.read(workspace_id)
    task_record = next(obj for obj in final["objects"] if obj.get("id") == task_record_id)
    assert task_record["value"]["schema_ref"] == "tasks.task.revision"
    assert task_record["value"]["payload"]["title"] == "Execute native proposal"
    assert task_record["value"]["payload"]["author"] == owner_actor
    relation = next(obj for obj in final["objects"] if obj.get("kind") == "record_relations"
        and obj.get("value", {}).get("record_id") == task_record_id)
    assert relation["value"]["kind"] == "tasks.based_on_candidate"
    assert relation["value"]["target_record"] == candidate_id
    assert relation["value"]["target_revision"] == 1
    head = next(obj for obj in final["objects"] if obj.get("kind") == "entity_heads"
        and obj.get("value", {}).get("record_id") == task_record_id)
    assert head["value"]["revision"] == 1
    owner_config_file = STATE / "owner.json"
    owner_config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir), allow_loopback_http=True)))
    assert cli("owner-action-retry", str(owner_config_file), workspace_id, task_id)["status"] == "ACCEPTED"
    assert counts(origin)["head_sequence"] == final["sequence"]
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id, owner_actor_id=owner_actor,
        recipient_actor_id=local["actor_id"], candidate_id=candidate_id,
        task_record_id=task_record_id, final_sequence=final["sequence"], install_steps=steps)))
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
