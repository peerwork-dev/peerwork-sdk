"""Installed Python PRIVATE member action after an encrypted recipient grant."""

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
expected_owner_hash = os.environ["PEERWORK_TEST_OWNER_SOURCE_SHA256"]
assert hashlib.sha256((SOURCE / "crates/runtime/src/secure_owner_create.rs").read_bytes()).hexdigest() == expected_owner_hash
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, path):
    with urllib.request.urlopen(urllib.request.Request(origin + path, data=b"{}", method="POST"), timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def node_call(config, workspace_id, operation, **values):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
        PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_OPERATION=operation,
        PEERWORK_TEST_VALUES=json.dumps(values), PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const root = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const workspace = process.env.PEERWORK_TEST_WORKSPACE;
  const values = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  const op = process.env.PEERWORK_TEST_OPERATION;
  let result;
  if(op==='offer') result=await root.privateAdmission(workspace).offer(values.certificate,values.scopes,{message:values.message});
  else if(op==='pendingDelivery') result=await root.privateAdmission(workspace).pendingDeliveries();
  else throw Error('unknown installed test operation');
  console.log(JSON.stringify(result));
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
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    prepared = owner.prepare("Python PRIVATE member action", "PRIVATE")
    assert prepared["status"] == "PENDING"
    created = owner.resume(prepared["command_id"])
    assert created["status"] == "CREATED" and created["visibility"] == "PRIVATE"
    workspace_id = created["workspace_id"]
    owner_pins = peerwork.open_identity(str(owner_dir / "identity.state"))
    owner_view = owner.read(workspace_id)
    assert owner_view["sequence"] == 1
    wiki_instance = next(row["id"] for row in owner_view["objects"]
        if row.get("kind") == "instances" and row.get("value", {}).get("origin_entrypoint") == "wiki")

    recipient_dir = STATE / "native-recipient"
    recipient = peerwork.SecureRecipientEnrollmentClient(origin, str(recipient_dir), allow_loopback_http=True)
    local = recipient.create_local()
    assert local["status"] == "LOCAL" and local["actor_id"] != owner_pins["actor_id"]
    publication = recipient.publish()
    for _ in range(3):
        if publication["status"] == "PUBLISHED":
            break
        publication = recipient.publish()
    assert publication["status"] == "PUBLISHED", publication
    directory = peerwork.SecureIdentityDirectoryClient(origin, str(owner_dir), allow_loopback_http=True)
    verified = directory.lookup(local["actor_id"], local["signing_key_id"])
    assert verified["certificate_json"] == recipient.certificate_json()
    owner_config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    exact_scope = [dict(instance_id=wiki_instance, actions=["wiki.create"],
                        protocol_roles=["EDITOR"], capabilities=["EDIT"])]
    offer = node_call(owner_config, workspace_id, "offer", certificate=verified["certificate_json"],
        scopes=exact_scope, message="Python PRIVATE member action")
    assert offer["status"] == "PENDING"
    admission = owner.private_admission(workspace_id)
    assert offer["invite_id"] in {row["invite_id"] for row in admission.pending_offers()}
    assert admission.retry_offer(offer["invite_id"])["offer_hash"] == offer["offer_hash"]

    invitation = peerwork.SecureInvitationClient(origin, str(recipient_dir), workspace_id,
        owner_pins["actor_id"], owner_pins["key_id"], allow_loopback_http=True)
    consent = invitation.decide(offer["invite_id"], "ACCEPT")
    assert consent["status"] == "PENDING"
    assert invitation.retry_decision(offer["invite_id"])["decision_hash"] == consent["decision_hash"]
    before_delivery = counts(origin)
    post(origin, "__test/drop-next-post")
    dropped = admission.deliver(offer["invite_id"])
    assert dropped["status"] == "PENDING" and dropped["invite_id"] == offer["invite_id"]
    after_apply = counts(origin)
    assert after_apply["commits"] == before_delivery["commits"] + 1
    assert after_apply["head_sequence"] == 2
    pending = node_call(owner_config, workspace_id, "pendingDelivery")
    assert len(pending) == 1 and pending[0]["grant_id"] == dropped["grant_id"]
    owner_config_file = STATE / "owner.json"
    owner_config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir), allow_loopback_http=True)))
    authorized = cli("owner-private-admit-retry-delivery", str(owner_config_file), workspace_id, dropped["grant_id"])
    assert authorized["status"] == "AUTHORIZED" and authorized["grant_hash"] == dropped["grant_hash"]
    assert counts(origin)["commits"] == after_apply["commits"]
    received = invitation.receive(offer["invite_id"])
    if received["status"] == "PENDING":
        received = invitation.retry_receive(offer["invite_id"])
    assert received["status"] == "READY", received
    assert owner.private_admission(workspace_id).retry_delivery(dropped["grant_id"])["status"] == "AUTHORIZED"

    del owner
    del admission
    member = peerwork.SecurePrivateActionClient(origin, str(recipient_dir), str(recipient_dir / "identity.state"),
        workspace_id, owner_actor_id=owner_pins["actor_id"], owner_key_id=owner_pins["key_id"],
        allow_loopback_http=True)
    command_id = "z" * 43
    operation_id = "o" * 43
    before_action = counts(origin)
    post(origin, "__test/drop-next-post")
    submitted = member.submit("wiki.create", wiki_instance,
        {"title": "Python PRIVATE member readback", "body": "Encrypted after member grant"},
        command_id=command_id, operation_id=operation_id)
    assert submitted["status"] == "PENDING" and submitted["command_id"] == command_id
    accepted = member.reconcile(command_id)
    assert accepted["status"] == "ACCEPTED" and accepted["sequence"] == 3
    assert accepted["receipt"]["actor_id"] == local["actor_id"]
    record_id = accepted["receipt"]["effects"][0]["record_id"]
    retried = member.retry_saved(command_id)
    assert retried["status"] == "ACCEPTED" and retried["commit_hash"] == accepted["commit_hash"]
    readback = peerwork.SecureReadClient(origin, str(recipient_dir), str(recipient_dir / "identity.state"),
        workspace_id, owner_actor_id=owner_pins["actor_id"], owner_key_id=owner_pins["key_id"],
        allow_loopback_http=True).read_private()
    record = next(row for row in readback["objects"] if row.get("id") == record_id)
    assert readback["sequence"] == 3 and record["kind"] == "records"
    assert record["value"]["payload"]["title"] == "Python PRIVATE member readback"
    assert record["value"]["payload"]["body"] == "Encrypted after member grant"
    assert counts(origin)["head_sequence"] == before_action["head_sequence"] + 1
    if os.environ.get("PEERWORK_TEST_BROWSER_APPROVAL") == "1":
        import runpy
        runpy.run_path(str(SOURCE / "tests/installed-browser-approval.py"))["run"](
            source=SOURCE, state=STATE, origin=origin, workspace_id=workspace_id,
            recipient_dir=recipient_dir, actor_id=local["actor_id"], owner_pins=owner_pins,
            instance_id=wiki_instance, node=NODE, post=post)
    if os.environ.get("PEERWORK_TEST_AGENT_CONTEXT") == "1":
        import runpy
        runpy.run_path(str(SOURCE / "tests/installed-agent-context.py"))["run"](
            state=STATE, origin=origin, workspace_id=workspace_id, recipient_dir=recipient_dir,
            actor_id=local["actor_id"], owner_pins=owner_pins, instance_id=wiki_instance,
            counts=counts, post=post, node=NODE, node_package=NODE_PACKAGE, cli=CLI)
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id,
        owner_actor_id=owner_pins["actor_id"], recipient_actor_id=local["actor_id"],
        invite_id=offer["invite_id"], command_id=command_id, operation_id=operation_id,
        record_id=record_id, final_sequence=readback["sequence"],
        encrypted_private_member_action=True, exact_retry=True)))
    if os.environ.get("PEERWORK_TEST_AGENT_TRIAL_HOLD") == "1":
        import runpy
        runpy.run_path(str(SOURCE / "tests/agent-trial/context-runtime-fixture.py"))["hold"](
            state=STATE, origin=origin, workspace_id=workspace_id, recipient_dir=recipient_dir,
            actor_id=local["actor_id"], owner_pins=owner_pins, instance_id=wiki_instance,
            post=post, source=SOURCE, cli=CLI, node=NODE, node_package=NODE_PACKAGE)
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
