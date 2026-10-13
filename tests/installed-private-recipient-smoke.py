"""Installed PRIVATE recipient admission and verified encrypted-read smoke.

The tracked TypeScript fixture owns the workspace and signs owner invite,
delivery and rotation. Both recipient identities, decisions and receipts use
installed native SDK entrypoints; no Agent workflow behavior is inferred.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_SOURCE"])
INSTALL = Path(os.environ["PEERWORK_TEST_INSTALL"])
NODE = os.environ["PEERWORK_TEST_NODE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
TEMP_ROOT = Path(os.environ["PEERWORK_TEST_ARTIFACT_DIR"])


def test_post(origin, operation, **fields):
    wire = json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/private-owner-" + operation, data=wire,
                headers={"content-type": "application/json"}, method="POST"), timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise AssertionError((operation, error.code, error.read().decode()[:500])) from error


def node_call(operation, config, **fields):
    program = r"""
const sdk=require('@peerwork/agent-sdk');
const fs=require('node:fs');
const arg=JSON.parse(fs.readFileSync(0,'utf8'));
(async()=>{
  let result;
  if(arg.operation==='read') result=await sdk.readSecurePrivateWorkspace(arg.config);
  else if(arg.operation==='decide') result=await sdk.openSecureInvitation(arg.config).decide(arg.fields.inviteId,'ACCEPT');
  else if(arg.operation==='receive') result=await sdk.openSecureInvitation(arg.config).receive(arg.fields.inviteId);
  else throw Error('unsupported private smoke operation');
  process.stdout.write(JSON.stringify(result));
})().catch(error=>{process.stderr.write(JSON.stringify({code:error.code,message:error.message}));process.exitCode=1});
"""
    result = subprocess.run([NODE, "-e", program], input=json.dumps(dict(
        operation=operation, config=config, fields=fields)), cwd=INSTALL,
        text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, (operation, result.stderr[-500:])
    return json.loads(result.stdout)


def cli_private_read(origin, state_dir, workspace):
    result = subprocess.run([CLI, "secure", "private-read", f"--origin={origin}",
        f"--state-dir={state_dir}", f"--identity={state_dir / 'identity.state'}",
        f"--workspace={workspace['workspace_id']}",
        f"--owner-actor={workspace['owner_actor_id']}",
        f"--owner-key={workspace['owner_key_id']}", "--allow-loopback-http"],
        text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr[-500:]
    return json.loads(result.stdout)


def native_recipient(origin, state_dir):
    recipient = peerwork.SecureRecipientEnrollmentClient(origin, str(state_dir),
        allow_loopback_http=True)
    local = recipient.create_local()
    published = recipient.publish()
    if published["status"] != "PUBLISHED":
        published = recipient.publish()
    assert published["status"] == "PUBLISHED"
    return recipient, local


def invitation_client(origin, state_dir, workspace):
    return peerwork.SecureInvitationClient(origin, str(state_dir),
        workspace["workspace_id"], workspace["owner_actor_id"],
        workspace["owner_key_id"], allow_loopback_http=True)


def read_client(origin, state_dir, workspace):
    return peerwork.SecureReadClient(origin, str(state_dir), str(state_dir / "identity.state"),
        workspace["workspace_id"], owner_actor_id=workspace["owner_actor_id"],
        owner_key_id=workspace["owner_key_id"], allow_loopback_http=True)


def contains_record(readback, record_id, title):
    return any(row.get("kind") == "records" and row.get("id") == record_id and
        row.get("value", {}).get("payload", {}).get("title") == title
        for row in readback["objects"])


def protected_current_generation(state_dir):
    """Observe protected current-slot custody; the staged slot may change."""
    prefix = b"PEERWORK-NATIVE-SECURE-STATE\n1\n"
    profile_wire = (state_dir / "read.profile").read_bytes()
    assert profile_wire.startswith(prefix)
    profile = json.loads(profile_wire[len(prefix):])
    assert profile["current"] in (0, 1) and profile["floor"] is not None
    current_path = state_dir / f"read-{profile['current']}.state"
    return (profile["current"], profile["floor"],
        hashlib.sha256(current_path.read_bytes()).hexdigest())


def exact_record(readback, record_id):
    matches = [row for row in readback["objects"]
               if row.get("kind") == "records" and row.get("id") == record_id]
    assert len(matches) == 1
    return matches[0]


with tempfile.TemporaryDirectory(prefix="peerwork-native-private-", dir=TEMP_ROOT) as temporary:
    state = Path(temporary)
    state.chmod(0o700)
    service_state = state / "service"
    service_state.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(service_state), PEERWORK_TEST_PRIVATE_NATIVE_ADMISSION="1")
    server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
        cwd=SOURCE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    try:
        ready_line = server.stdout.readline()
        assert ready_line, server.stderr.read()[-500:]
        ready = json.loads(ready_line)
        origin = ready["origin"]
        workspace = ready["private_native_admission"]
        recipient_dir = state / "recipient"
        recipient, local = native_recipient(origin, recipient_dir)
        offer = test_post(origin, "invite", certificate_json=recipient.certificate_json())
        assert offer["workspace_id"] == workspace["workspace_id"]
        invitation = invitation_client(origin, recipient_dir, workspace)
        consent = invitation.decide(offer["invite_id"], "ACCEPT")
        assert consent["invite_id"] == offer["invite_id"]
        delivered = test_post(origin, "deliver", invite_id=offer["invite_id"])
        assert delivered["invite_id"] == offer["invite_id"]
        received = invitation.receive(offer["invite_id"])
        if received["status"] == "PENDING":
            received = invitation.retry_receive(offer["invite_id"])
        assert received["status"] == "READY"
        reader = read_client(origin, recipient_dir, workspace)
        initial = reader.read()
        assert initial["workspace_id"] == workspace["workspace_id"]
        assert initial["sequence"] > workspace["sequence"]
        authority = hashlib.sha256(local["actor_id"].encode()).hexdigest()
        saved = peerwork.SecureSnapshotClient(origin, str(recipient_dir / "kernel.sqlite"),
            str(recipient_dir / "read-0.state"), str(recipient_dir / "lifecycle.state"),
            str(recipient_dir / "identity.state"), workspace["workspace_id"], authority,
            workspace["owner_actor_id"], workspace["owner_key_id"], allow_loopback_http=True)
        assert saved.read()["sequence"] == initial["sequence"]
        initial_checkpoint = (initial["sequence"], initial["head"], initial["policy_hash"])
        protected_before_failure = protected_current_generation(recipient_dir)
        assert protected_before_failure[1]["sequence"] == initial_checkpoint[0]
        assert protected_before_failure[1]["head"] == initial_checkpoint[1]
        assert protected_before_failure[1]["policy_hash"] == initial_checkpoint[2]
        advanced = test_post(origin, "rotate")
        assert advanced["epoch"] > 1
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/tamper-next-private-grant", data=b"", method="POST"), timeout=5):
            pass
        try:
            reader.read_private()
        except peerwork.SecureReadError as error:
            assert error.code in ("VERIFICATION_FAILED", "GRANT_INVALID")
        else:
            raise AssertionError("altered signed direct grant authorized PRIVATE read")
        # Compare custody before any restorative service read. A fresh snapshot
        # fetch here could mask a damaged current slot by refilling it.
        assert protected_current_generation(recipient_dir) == protected_before_failure
        latest = reader.read_private()
        assert latest["sequence"] == advanced["sequence"]
        assert contains_record(latest, advanced["record_id"], "Native private admission readback")
        assert exact_record(latest, advanced["record_id"])["value"]["payload"]["body"] == \
            "Encrypted record after owner epoch advance"
        assert reader.read()["sequence"] == latest["sequence"]
        node_read = node_call("read", dict(origin=origin, stateDir=str(recipient_dir),
            identityPath=str(recipient_dir / "identity.state"),
            workspaceId=workspace["workspace_id"], ownerActorId=workspace["owner_actor_id"],
            ownerKeyId=workspace["owner_key_id"], allowLoopbackHttp=True))
        assert node_read["sequence"] == latest["sequence"]
        assert cli_private_read(origin, recipient_dir, workspace)["sequence"] == latest["sequence"]
        assert saved.read()["sequence"] == initial["sequence"]

        # PRIVATE historical recipient key: owner delivers a grant encrypted
        # to v1 before the recipient rotates, then native receipt decrypts it
        # using retained protected v1 key material while workspace epoch stays.
        historical_dir = state / "historical-recipient"
        historical, historical_local = native_recipient(origin, historical_dir)
        old_offer = test_post(origin, "invite", certificate_json=historical.certificate_json())
        historical_invitation = invitation_client(origin, historical_dir, workspace)
        historical_config = dict(origin=origin, stateDir=str(historical_dir),
            workspaceId=workspace["workspace_id"], ownerActorId=workspace["owner_actor_id"],
            ownerKeyId=workspace["owner_key_id"], allowLoopbackHttp=True)
        old_consent = node_call("decide", historical_config, inviteId=old_offer["invite_id"])
        assert old_consent["invite_id"] == old_offer["invite_id"]
        old_delivery = test_post(origin, "deliver", invite_id=old_offer["invite_id"])
        assert old_delivery["invite_id"] == old_offer["invite_id"]
        old_digest = historical_local["certificate_digest"]
        rotated = historical.update_key("ROTATE", old_digest)
        if rotated["status"] == "PENDING":
            rotated = historical.retry_key_update(rotated["update_id"])
        assert rotated["status"] == "PUBLISHED"
        renewed = historical.update_key("RENEW", rotated["certificate_digest"])
        if renewed["status"] == "PENDING":
            renewed = historical.retry_key_update(renewed["update_id"])
        assert renewed["status"] == "PUBLISHED"
        old_received = historical_invitation.receive(old_offer["invite_id"])
        if old_received["status"] == "PENDING":
            old_received = historical_invitation.retry_receive(old_offer["invite_id"])
        assert old_received["status"] == "READY"
        historical_read = read_client(origin, historical_dir, workspace).read_private()
        assert contains_record(historical_read, advanced["record_id"],
            "Native private admission readback")
        assert exact_record(historical_read, advanced["record_id"])["value"]["payload"]["body"] == \
            "Encrypted record after owner epoch advance"
        print(json.dumps(dict(source="installed", visibility="PRIVATE",
            native_decision=consent["status"], native_receipt=received["status"],
            direct_grant_sequence=latest["sequence"], historical_receipt=old_received["status"],
            historical_record=advanced["record_id"])))
    finally:
        server.stdin.close()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(timeout=5)
        if sys.exc_info()[0] is not None:
            print("tracked service stderr:", server.stderr.read()[-1200:], file=sys.stderr)
