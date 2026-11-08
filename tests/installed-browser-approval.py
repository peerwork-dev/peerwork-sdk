"""Installed native approval + real pinned browser-wire peer (not a UI trial).

Invoked by the existing real admitted-member fixture. No TypeScript approval
helper is called. One-time codes are passed only via protected files/pipes and
are never printed, included in assertion messages, or returned in the report.
"""
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import urllib.request

import peerwork


def verify_binding_parity(*, profile, actor_id, workspace_id, operation_id,
                          expected_code_hash, node, node_package, cli):
    """Recover the same approval through installed Node/CLI; return no credential."""
    env = dict(os.environ, PW_PARITY_PROFILE=str(profile), PW_PARITY_ACTOR=actor_id,
        PW_PARITY_WORKSPACE=workspace_id, PW_PARITY_OPERATION=operation_id,
        PEERWORK_TEST_NODE_PACKAGE=node_package)
    node_code = r'''(async()=>{
const sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE);
const {createHash}=require('node:crypto');
const ctx=await sdk.openContext({profilePath:process.env.PW_PARITY_PROFILE,
 expectedActor:process.env.PW_PARITY_ACTOR,expectedService:'installed-browser-test'});
const r=await ctx.recover(process.env.PW_PARITY_WORKSPACE,{operationId:process.env.PW_PARITY_OPERATION});
if(r.status!=='verified'||r.result?.status!=='ACCEPTED'||r.result?.verification!=='verified'||typeof r.result?.approval_code!=='string')throw Error('PARITY_RESULT');
console.log(JSON.stringify({verified:true,code_sha256:createHash('sha256').update(r.result.approval_code).digest('hex')}));
})().catch(()=>{console.error('NATIVE_BROWSER_RECOVERY_PARITY_FAILED');process.exitCode=1});'''
    node_result = subprocess.run([node, "-e", node_code], env=env,
        capture_output=True, text=True, timeout=120)
    assert node_result.returncode == 0, "installed Node browser recovery failed"
    value = json.loads(node_result.stdout)
    assert value["verified"] is True and value["code_sha256"] == expected_code_hash
    request_path = Path(profile).parent / "browser-parity-recover.json"
    with request_path.open("x", encoding="utf-8") as stream:
        request_path.chmod(0o600)
        json.dump(dict(workspace_id=workspace_id, operation_id=operation_id), stream)
    try:
        cli_result = subprocess.run([cli, "context", "recover", str(profile), actor_id,
            "installed-browser-test", str(request_path)], capture_output=True, text=True, timeout=120)
        assert cli_result.returncode == 0, "installed CLI browser recovery failed"
        envelope = json.loads(cli_result.stdout)
        assert envelope["ok"] is True and envelope["value"]["status"] == "verified"
        result = envelope["value"]["result"]
        assert result["status"] == "ACCEPTED" and result["verification"] == "verified"
        assert hashlib.sha256(result["approval_code"].encode()).hexdigest() == expected_code_hash
    finally:
        request_path.unlink(missing_ok=True)
    return {"node_browser_recover": True, "cli_browser_recover": True}


def run(*, source, state, origin, workspace_id, recipient_dir, actor_id,
        owner_pins, instance_id, node, post):
    def write_private(path, value):
        with path.open("x", encoding="utf-8") as stream:
            path.chmod(0o600)
            json.dump(value, stream)
        return path

    profile = state / "browser-agent-context.json"
    member_profile = write_private(state / "browser-member-profile.json", dict(
        origin=origin, state_dir=str(recipient_dir), identity_path=str(recipient_dir / "identity.state"),
        workspace_id=workspace_id, owner_actor_id=owner_pins["actor_id"],
        owner_key_id=owner_pins["key_id"], allow_loopback_http=True))
    ctx = peerwork.bind_context(profile=profile, expected_actor=actor_id,
        expected_service="installed-browser-test", workspace_profiles=[member_profile])
    env = dict(os.environ, PEERWORK_BROWSER_TEST_ORIGIN=origin,
        PEERWORK_BROWSER_TEST_WORKSPACE=workspace_id, PEERWORK_BROWSER_TEST_ACTOR=actor_id,
        PEERWORK_BROWSER_TEST_OWNER=json.dumps(dict(actorId=owner_pins["actor_id"], key=owner_pins["key_id"])))
    peer = subprocess.Popen([node, str(source / "tests/installed-browser-peer.mjs")],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    selector = selectors.DefaultSelector()
    selector.register(peer.stdout, selectors.EVENT_READ)

    def call(operation, **values):
        peer.stdin.write(json.dumps(dict(operation=operation, **values)) + "\n")
        peer.stdin.flush()
        assert selector.select(timeout=30), "browser test peer timed out"
        line = peer.stdout.readline()
        assert line, "browser test peer stopped"
        result = json.loads(line)
        assert result.get("ok") is True, "browser test peer failed: " + result.get("stage", result.get("code", "unknown"))
        return result["result"]

    def command_count():
        with urllib.request.urlopen(origin + "__test/counts", timeout=10) as response:
            return json.load(response)["commands"]

    def intent(reference, approve_writes=False):
        return dict(kind="browser.approve", reference=reference, approve_writes=approve_writes)

    def refused(reference, operation_id, expected_code):
        before = command_count()
        try:
            ctx.operate(workspace_id, intent(reference), operation_id)
        except peerwork.AgentContextError as error:
            assert error.code == expected_code and error.layer, "approval refusal code mismatch"
        else:
            raise AssertionError("invalid approval accepted")
        assert command_count() == before, "refused approval submitted a command"

    try:
        request = call("create")
        reference = request["reference"]
        # Existing protocol intent IDs cannot be repurposed for platform approval.
        before_kind_conflict = command_count()
        try:
            ctx.operate(workspace_id, intent(reference), "o" * 43)
        except peerwork.AgentContextError as error:
            assert error.code == "INTENT_CONFLICT"
        else:
            raise AssertionError("operation ID crossed intent families")
        assert command_count() == before_kind_conflict
        # Same locator, wrong exact binding digest.
        bad_reference = reference[:-1] + ("0" if reference[-1] != "0" else "1")
        refused(bad_reference, "browser-wrong-reference", "BROWSER_APPROVAL_BINDING")
        assert call("status", request_id=request["request_id"])["state"] == "PENDING"
        before = command_count()
        try:
            peerwork.open_context(profile=profile, expected_actor=actor_id, expected_service="wrong-service")
        except peerwork.AgentContextError as error:
            assert error.code == "CONTEXT_SERVICE"
        else:
            raise AssertionError("wrong service accepted")
        assert command_count() == before
        inspected = ctx.inspect(workspace_id)["result"]["state"]
        instance = next(row for row in inspected["objects"] if row.get("kind") == "instances" and row.get("id") == instance_id)
        protocol_digest = instance["value"]["protocol_digest"]
        writes = call("create", writes=[dict(instance_id=instance_id,
            protocol_digest=protocol_digest, actions=["wiki.create"])])
        refused(writes["reference"], "browser-writes-without-consent", "BROWSER_APPROVAL_WRITE_CONSENT")
        assert call("status", request_id=writes["request_id"])["state"] == "PENDING"
        expired = call("create", ttl_ms=300)
        time.sleep(max(0, expired["expires_at"] / 1000 - time.time()) + 0.03)
        refused(expired["reference"], "browser-expired", "BROWSER_APPROVAL_EXPIRED")

        operation_id = "installed-browser-lost-reply"
        before = command_count()
        post(origin, "__test/drop-next-post")
        submitted = ctx.operate(workspace_id, intent(reference), operation_id)
        assert submitted["status"] == "pending", "lost reply must remain unresolved"
        assert "peerwork-secure-code:v1:" not in json.dumps(submitted), "unverified response exposed code"
        assert command_count() == before + 1
        # Resume in an independent Python interpreter. Sensitive result stays in
        # an exclusively created protected file, never subprocess stdout.
        recovered_file = state / "browser-recovered-result.json"
        recovery_env = dict(os.environ, PW_TEST_CONTEXT=str(profile), PW_TEST_ACTOR=actor_id,
            PW_TEST_WORKSPACE=workspace_id, PW_TEST_OPERATION=operation_id, PW_TEST_RESULT=str(recovered_file))
        code = '''import json,os,peerwork
from pathlib import Path
ctx=peerwork.open_context(profile=os.environ["PW_TEST_CONTEXT"],expected_actor=os.environ["PW_TEST_ACTOR"],expected_service="installed-browser-test")
r=ctx.recover(os.environ["PW_TEST_WORKSPACE"],operation_id=os.environ["PW_TEST_OPERATION"])
p=Path(os.environ["PW_TEST_RESULT"])
with p.open("x") as f:
 p.chmod(0o600)
 json.dump(r,f)
'''
        child = subprocess.run([sys.executable, "-c", code], env=recovery_env, capture_output=True, text=True, timeout=120)
        assert child.returncode == 0, "native browser recovery process failed"
        assert not child.stdout, "recovery must not print sensitive result"
        recovered = json.loads(recovered_file.read_text())
        recovered_file.unlink()
        assert recovered["status"] == "verified", "recovery lacks verified acceptance"
        assert recovered["result"]["status"] == "ACCEPTED"
        assert recovered["result"]["verification"] == "verified"
        assert recovered["result"]["kind"] == "browser.approve"
        assert command_count() == before + 1, "recovery duplicated command"
        # Exact result schema is frozen with the native producer before execution.
        one_time_code = recovered["result"]["approval_code"]
        assert isinstance(one_time_code, str) and one_time_code.startswith("peerwork-secure-code:v1:")
        parity = verify_binding_parity(profile=profile, actor_id=actor_id,
            workspace_id=workspace_id, operation_id=operation_id,
            expected_code_hash=hashlib.sha256(one_time_code.encode()).hexdigest(),
            node=node, node_package=os.environ["PEERWORK_TEST_NODE_PACKAGE"],
            cli=os.environ["PEERWORK_TEST_CLI"])
        assert command_count() == before + 1, "binding recovery duplicated command"
        outcome = call("redeem", request_id=request["request_id"], code=one_time_code)
        del one_time_code, recovered
        assert outcome["redeemed"] and outcome["decrypted"] and outcome["no_write_scope"]
        assert outcome["member_author"] == actor_id
        assert command_count() == before + 1
        report = dict(status="PASS", installed_native_browser_approval=True,
            signed_recovery_code_release=True, **parity, wrong_reference_scope_expiry_service_refused=True,
            lost_reply_single_command=True, browser_protocol_redemption=True,
            browser_grant_decryption=True, member_authorship=True,
            chromium_ui_acceptance=False, source="pinned-f828-browser-wire-peer")
        print(json.dumps(report))
        return report
    finally:
        selector.close()
        if peer.stdin:
            peer.stdin.close()
        try:
            peer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait(timeout=5)
