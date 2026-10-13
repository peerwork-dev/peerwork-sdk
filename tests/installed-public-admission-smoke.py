"""Installed three-interface PUBLIC recipient enrollment and admission smoke.

The tracked TypeScript fixture creates only the owner workspace. Recipient key
creation, publication, offer, consent, delivery and receipt use native SDK APIs.
"""

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_SOURCE"])
INSTALL = Path(os.environ["PEERWORK_TEST_INSTALL"])
NODE = os.environ["PEERWORK_TEST_NODE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
REFERENCE = os.environ["PEERWORK_REFERENCE_ROOT"]
TEMP_ROOT = Path(os.environ["PEERWORK_TEST_ARTIFACT_DIR"])


def node_call(role, operation, config, **values):
    script = r"""
const sdk=require('@peerwork/agent-sdk');
const fs=require('node:fs');
const arg=JSON.parse(fs.readFileSync(0,'utf8'));
const session=arg.role==='owner' ? sdk.openSecurePublicAdmission(arg.config)
  : arg.role==='directory' ? sdk.openSecureIdentityDirectory(arg.config)
  : sdk.openSecurePublicDecision(arg.config);
(async()=>{
  let value;
  if(arg.role==='owner' && arg.operation==='offer') value=await session.offer(arg.values.certificate,arg.values.scopes,{message:arg.values.message});
  else if(arg.role==='owner' && arg.operation==='retryOffer') value=await session.retryOffer(arg.values.inviteId);
  else if(arg.role==='owner' && arg.operation==='pendingOffers') value=await session.pendingOffers();
  else if(arg.role==='recipient' && arg.operation==='retryDecision') value=await session.retryDecision(arg.values.inviteId);
  else if(arg.role==='recipient' && arg.operation==='retryReceive') value=await session.retryReceive(arg.values.inviteId);
  else if(arg.role==='recipient' && arg.operation==='pendingReceipts') value=await session.pendingReceipts();
  else if(arg.role==='directory' && arg.operation==='lookup') value=await session.lookup(arg.values.actorId,arg.values.keyId);
  else throw Error('unsupported test operation');
  process.stdout.write(JSON.stringify(value));
})().catch(error=>{process.stderr.write(JSON.stringify({code:error.code,message:error.message}));process.exitCode=1});
"""
    result = subprocess.run([NODE, "-e", script], input=json.dumps(dict(role=role, operation=operation,
        config=config, values=values), ensure_ascii=True), cwd=INSTALL, text=True,
        capture_output=True, timeout=60)
    assert result.returncode == 0, (operation, result.stderr[-500:])
    return json.loads(result.stdout)


def cli(*args):
    result = subprocess.run([CLI, "secure", *args], text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, (args, result.stderr[-500:])
    return json.loads(result.stdout)


def stored_offer(database, invite_id):
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT offer_hash,offer FROM secure_invitations WHERE invite_id=?", (invite_id,)).fetchone()
    assert row is not None, invite_id
    signed = json.loads(row[1])
    assert isinstance(signed["payload"]["message"], dict)  # encrypted to the native recipient
    return row[0], signed["payload"]["recipient"]["payload"]["actor_id"]


async def cancel_before_persist(origin, owner, certificate, database):
    with urllib.request.urlopen(urllib.request.Request(
            origin + "__test/delay-next-journal", data=b"", method="POST"), timeout=5):
        pass
    task = asyncio.create_task(owner.offer_async(certificate, "[]", message="cancel before persist"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with urllib.request.urlopen(origin + "__test/journal-delay-status", timeout=5) as response:
            if json.load(response)["started"]:
                break
        await asyncio.sleep(0.05)
    else:
        raise AssertionError("owner offer did not start the pre-submit journal read")
    task.cancel()
    task.cancel()  # repeated cancellation must drain the native worker
    try:
        await task
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("in-flight cancellation was not observed")
    assert owner.pending_offers() == []
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM secure_invitations").fetchone()[0] == 0


async def cancel_after_persist(origin, owner, reopen_kwargs, certificate, database, recipient_actor):
    before_ids = {row["invite_id"] for row in owner.pending_offers()}
    with sqlite3.connect(database) as connection:
        before_count = connection.execute("SELECT count(*) FROM secure_invitations").fetchone()[0]
    with urllib.request.urlopen(urllib.request.Request(
            origin + "__test/delay-next-post", data=b"", method="POST"), timeout=5):
        pass
    task = asyncio.create_task(owner.offer_async(certificate, "[]", message="applied before cancel"))
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with urllib.request.urlopen(origin + "__test/post-delay-status", timeout=5) as response:
            if json.load(response)["started"]:
                break
        await asyncio.sleep(0.05)
    else:
        raise AssertionError("POST was not observed after tracked service application")
    task.cancel()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("post-persist cancellation was not observed")
    reopened = peerwork.SecurePublicAdmissionClient(**reopen_kwargs)
    after = {row["invite_id"]: row for row in reopened.pending_offers()}
    new_ids = set(after) - before_ids
    assert len(new_ids) == 1, (before_ids, after)
    invite_id = next(iter(new_ids))
    assert stored_offer(database, invite_id) == (after[invite_id]["offer_hash"], recipient_actor)
    retried = reopened.retry_offer(invite_id)
    assert retried["invite_id"] == invite_id and retried["offer_hash"] == after[invite_id]["offer_hash"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM secure_invitations").fetchone()[0] == before_count + 1


with tempfile.TemporaryDirectory(prefix="peerwork-native-admission-", dir=TEMP_ROOT) as temporary:
    state = Path(temporary)
    state.chmod(0o700)
    service_state = state / "service"
    service_state.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(PEERWORK_TEST_STATE=str(service_state), PEERWORK_TEST_PUBLIC_READ="1")
    server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
        cwd=SOURCE, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        assert line, server.stderr.read()[-500:]
        ready = json.loads(line)
        origin, workspace = ready["origin"], ready["public_read"]
        owner_dir = state / "owner"
        owner_dir.mkdir(mode=0o700)
        owner_identity = owner_dir / "identity.state"
        imported = peerwork.import_legacy_identity_pem(
            str(owner_identity), str(service_state / "synthetic-public-read-owner.pem"))
        assert imported == {"actor_id": workspace["actor_id"], "key_id": workspace["signing_key"]}
        owner = peerwork.SecurePublicAdmissionClient(origin, str(owner_dir), str(owner_identity),
            workspace["workspace_id"], owner_actor_id=workspace["actor_id"],
            owner_key_id=workspace["signing_key"], authority=workspace["authority"],
            allow_loopback_http=True)
        owner_reopen_kwargs = dict(origin=origin, state_dir=str(owner_dir),
            identity_path=str(owner_identity), workspace_id=workspace["workspace_id"],
            owner_actor_id=workspace["actor_id"], owner_key_id=workspace["signing_key"],
            authority=workspace["authority"], allow_loopback_http=True)
        assert owner.read()["sequence"] == 1

        recipient_dir = state / "recipient"
        recipient = peerwork.SecureRecipientEnrollmentClient(origin, str(recipient_dir),
            allow_loopback_http=True)
        local = recipient.create_local()
        assert local["status"] == "LOCAL" and local["actor_id"] != workspace["actor_id"]
        publication = recipient.publish()
        assert publication["status"] in ("REGISTRATION_PENDING", "PUBLICATION_PENDING", "PUBLISHED")
        for _ in range(3):
            if publication["status"] == "PUBLISHED":
                break
            publication = recipient.publish()
        assert publication["status"] == "PUBLISHED", publication
        assert recipient.pending()["actor_id"] == local["actor_id"]
        local_certificate = recipient.certificate_json()
        assert json.loads(local_certificate)["payload"]["actor_id"] == local["actor_id"]
        directory = peerwork.SecureIdentityDirectoryClient(origin, str(owner_dir),
            str(owner_identity), allow_loopback_http=True)
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/tamper-next-identity-directory", data=b"", method="POST"), timeout=5):
            pass
        try:
            directory.lookup(local["actor_id"], local["signing_key_id"])
        except peerwork.IdentityDirectoryError as error:
            assert error.code == "DIRECTORY_INVALID", error.code
        else:
            raise AssertionError("altered signed directory entry was accepted")
        verified = directory.lookup(local["actor_id"], local["signing_key_id"])
        assert verified["actor_id"] == local["actor_id"]
        assert verified["signing_key_id"] == local["signing_key_id"]
        assert verified["directory_version"] == 1
        assert verified["certificate_json"] == local_certificate
        from_cli = cli("directory-lookup", f"--origin={origin}", f"--state-dir={owner_dir}",
            f"--identity={owner_identity}", f"--actor={local['actor_id']}",
            f"--key={local['signing_key_id']}", "--allow-loopback-http")
        assert from_cli == verified
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/serve-stale-identity-directory", data=b"", method="POST"), timeout=5):
            pass
        try:
            directory.lookup(local["actor_id"], local["signing_key_id"])
        except peerwork.IdentityDirectoryError as error:
            assert error.code == "DIRECTORY_CONTINUITY", error.code
        else:
            raise AssertionError("signed directory rollback was accepted")
        with urllib.request.urlopen(urllib.request.Request(
                origin + "__test/restore-identity-directory", data=b"", method="POST"), timeout=5):
            pass
        from_node = node_call("directory", "lookup", dict(origin=origin,
            stateDir=str(owner_dir), identityPath=str(owner_identity), allowLoopbackHttp=True),
            actorId=local["actor_id"], keyId=local["signing_key_id"])
        assert from_node == verified
        certificate = from_node["certificate_json"]  # consumed by signed owner offer below

        asyncio.run(cancel_before_persist(origin, owner, certificate, service_state / "control.sqlite"))

        owner_config = dict(origin=origin, stateDir=str(owner_dir), identityPath=str(owner_identity),
            workspaceId=workspace["workspace_id"], ownerActorId=workspace["actor_id"],
            ownerKeyId=workspace["signing_key"], authority=workspace["authority"],
            allowLoopbackHttp=True)
        high = node_call("owner", "offer", owner_config, certificate=certificate, scopes=[], message="\ud800")
        assert high["status"] == "PENDING" and stored_offer(service_state / "control.sqlite", high["invite_id"]) == (high["offer_hash"], local["actor_id"])
        low = owner.offer(certificate, "[]", message="\udc00")
        assert low["status"] == "PENDING" and stored_offer(service_state / "control.sqlite", low["invite_id"]) == (low["offer_hash"], local["actor_id"])
        ordinary = owner.offer(certificate, "[]", message="A\U0001f642B")
        assert ordinary["status"] == "PENDING" and stored_offer(service_state / "control.sqlite", ordinary["invite_id"]) == (ordinary["offer_hash"], local["actor_id"])
        assert high["invite_id"] in {row["invite_id"] for row in node_call("owner", "pendingOffers", owner_config)}
        assert node_call("owner", "retryOffer", owner_config, inviteId=high["invite_id"])["offer_hash"] == high["offer_hash"]
        asyncio.run(cancel_after_persist(origin, owner, owner_reopen_kwargs, certificate,
            service_state / "control.sqlite", local["actor_id"]))

        recipient_config = dict(origin=origin, state_dir=str(recipient_dir),
            workspace_id=workspace["workspace_id"], owner_actor_id=workspace["actor_id"],
            owner_key_id=workspace["signing_key"],
            allow_loopback_http=True)
        recipient_config_file = state / "recipient-config.json"
        recipient_config_file.write_text(json.dumps(recipient_config))
        empty_authority_file = state / "recipient-empty-authority.json"
        empty_authority_file.write_text(json.dumps(dict(recipient_config, authority="")))
        invalid = subprocess.run([CLI, "secure", "consent", str(empty_authority_file),
            high["invite_id"], "ACCEPT"], text=True, capture_output=True, timeout=10)
        assert invalid.returncode != 0 and json.loads(invalid.stderr)["code"] == "CONFIG_INVALID"
        consent = cli("consent", str(recipient_config_file), high["invite_id"], "ACCEPT")
        assert consent["status"] == "PENDING" and consent["invite_id"] == high["invite_id"]
        native_recipient = peerwork.SecurePublicDecisionClient(origin, str(recipient_dir),
            workspace["workspace_id"], workspace["actor_id"], workspace["signing_key"],
            allow_loopback_http=True)
        assert native_recipient.retry_decision(high["invite_id"])["decision_hash"] == consent["decision_hash"]
        owner_config_file = state / "owner-config.json"
        owner_config_file.write_text(json.dumps(owner._config))
        delivery = cli("admit-deliver", str(owner_config_file), high["invite_id"])
        assert delivery["invite_id"] == high["invite_id"]
        received = native_recipient.receive(high["invite_id"])
        assert received["status"] in ("PENDING", "READY")
        if received["status"] == "PENDING":
            received = native_recipient.retry_receive(high["invite_id"])
        assert received["status"] == "READY", received
        node_recipient_config = dict(origin=origin, stateDir=str(recipient_dir),
            workspaceId=workspace["workspace_id"], ownerActorId=workspace["actor_id"],
            ownerKeyId=workspace["signing_key"],
            allowLoopbackHttp=True)
        assert node_call("recipient", "retryReceive", node_recipient_config,
            inviteId=high["invite_id"])["receipt_hash"] == received["receipt_hash"]
        authorized = owner.retry_delivery(delivery["grant_id"])
        assert authorized["status"] == "AUTHORIZED" and authorized["grant_hash"] == delivery["grant_hash"]
        recipient_read = peerwork.SecureReadClient(origin, str(recipient_dir),
            str(recipient_dir / "identity.state"), workspace["workspace_id"],
            owner_actor_id=workspace["actor_id"], owner_key_id=workspace["signing_key"],
            allow_loopback_http=True)
        assert recipient_read.read()["workspace_id"] == workspace["workspace_id"]
        print(json.dumps(dict(source="installed", recipient_actor=local["actor_id"],
            owner_actor=workspace["actor_id"], offers=4, accepted_invite=high["invite_id"],
            delivery_status=delivery["status"], recipient_status=received["status"])))
    finally:
        server.stdin.close()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.terminate()
            server.wait(timeout=5)
