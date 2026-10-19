"""Real installed context acceptance, called with the admitted-member fixture.

No synthetic state or mocked native/runtime modules. The caller owns fixture
startup/cleanup and retains its original source hash guard.
"""
import asyncio
import time
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import urllib.request
import sys

import peerwork


def run(*, state, origin, workspace_id, recipient_dir, actor_id, owner_pins,
        instance_id, counts, post, node, node_package, cli):
    def protected_json(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    workspace_profile = protected_json(state / "context-member-profile.json", dict(
        origin=origin, state_dir=str(recipient_dir), identity_path=str(recipient_dir / "identity.state"),
        workspace_id=workspace_id, owner_actor_id=owner_pins["actor_id"],
        owner_key_id=owner_pins["key_id"], allow_loopback_http=True))
    service = "installed-context-fixture"
    profile = state / "agent-context.json"
    identity_before_bind = (recipient_dir / "identity.state").read_bytes()
    try:
        peerwork.bind_context(profile=profile, expected_actor=owner_pins["actor_id"],
            expected_service=service, workspace_profiles=[workspace_profile])
    except peerwork.AgentContextError as error:
        assert error.code == "CONTEXT_ACTOR" and not profile.exists(), error.envelope
    else:
        raise AssertionError("bind accepted wrong actor")
    peerwork.bind_context(profile=profile, expected_actor=actor_id,
        expected_service=service, workspace_profiles=[workspace_profile])
    assert (recipient_dir / "identity.state").read_bytes() == identity_before_bind
    bound_bytes = profile.read_bytes()
    try:
        peerwork.bind_context(profile=profile, expected_actor=actor_id,
            expected_service=service, workspace_profiles=[workspace_profile])
    except peerwork.AgentContextError:
        assert profile.read_bytes() == bound_bytes
    else:
        raise AssertionError("bind overwrote existing context")


    def snapshot():
        return {str(p.relative_to(state)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in state.rglob("*") if p.is_file()}

    before = snapshot()
    before_counts = counts(origin)
    ctx = peerwork.open_context(profile=profile, expected_actor=actor_id, expected_service=service)
    assert snapshot() == before, "opening context wrote local files"
    assert counts(origin) == before_counts, "opening context changed service state"
    assert ctx.descriptor["actor_id"] == actor_id
    assert str(state) not in json.dumps(ctx.descriptor)
    for actor, selected_service, code in [(owner_pins["actor_id"], service, "CONTEXT_ACTOR"),
                                         (actor_id, "wrong-service", "CONTEXT_SERVICE")]:
        try:
            peerwork.open_context(profile=profile, expected_actor=actor, expected_service=selected_service)
        except peerwork.AgentContextError as error:
            assert error.code == code and error.effect_certainty == "not_sent", error.envelope
        else:
            raise AssertionError("wrong context pins accepted")
    assert snapshot() == before and counts(origin) == before_counts
    discovered = ctx.discover(workspace_id)["result"]
    assert "objects" not in discovered
    selected = next(row for row in discovered["instances"] if row["origin_entrypoint"] == "wiki")
    assert selected["instance_id"] == instance_id  # independent fixture oracle
    selected_action = next(action for action in selected["actions"] if action["action_id"] == "wiki.create")
    assert selected_action["scope_permitted"] is True
    assert selected_action["execution"] == "not_evaluated"
    instance_id = selected["instance_id"]
    action_id = selected_action["action_id"]
    described = ctx.describe(workspace_id, instance_id, action_id=action_id)["result"]
    assert described["refs"]["protocol_digest"] == selected["protocol_digest"]
    assert described["instance"]["id"] == instance_id
    assert described["protocol"]["ref"]
    assert described["protocol"]["manifest"] and described["protocol"]["resolved_manifest"]
    assert described["action"] and described["schemas"]
    assert described["authority"]["scope_permitted"] is True
    assert described["authority"]["execution"] == "not_evaluated"
    assert ctx.operations(workspace_id)["result"] == []

    def journal_probes():
        with urllib.request.urlopen(origin + "__test/journal-probes", timeout=10) as response:
            return json.load(response)["requests"]

    initialized = ctx.events_sync(workspace_id)["result"]
    assert initialized["enqueued"] == 1
    baseline_sequence = counts(origin)["head_sequence"]
    idle_start = len(journal_probes())
    idle = ctx.events_sync(workspace_id)["result"]
    assert idle["changed"] is False and idle["enqueued"] == 0
    assert idle["sync_path"] == "checkpoint_probe" and idle["probe"] == "unchanged"
    idle_probes = journal_probes()[idle_start:]
    assert idle_probes and all(row["status"] == 200 and row["after"] == str(baseline_sequence)
        and row["returned_commits"] == 0 for row in idle_probes), idle_probes

    try:
        ctx.operate(workspace_id, {"kind": "platform.future.unsupported"}, "u" * 43)
    except peerwork.AgentContextError as error:
        assert error.code == "UNSUPPORTED_PRODUCER" and error.effect_certainty == "not_sent"
    else:
        raise AssertionError("unsupported producer accepted")

    operation_id = "c" * 43
    intent = dict(kind="protocol.action", instance_id=instance_id, action_id=action_id,
                  values={"title": "Installed context action", "body": "Exact recovered member intent"}, refs=[])
    before_action = counts(origin)
    post(origin, "__test/drop-next-post")
    submitted = ctx.operate(workspace_id, intent, operation_id)
    assert submitted["status"] == "pending", submitted
    command_id = submitted["result"]["command_id"]
    assert counts(origin)["commits"] == before_action["commits"] + 1
    # A distinct interpreter must resolve the stable operation ID from real saved state.
    env = dict(os.environ, PEERWORK_CONTEXT_PROFILE=str(profile), PEERWORK_CONTEXT_ACTOR=actor_id,
               PEERWORK_CONTEXT_SERVICE=service, PEERWORK_CONTEXT_WORKSPACE=workspace_id,
               PEERWORK_CONTEXT_OPERATION=operation_id, PEERWORK_TEST_NODE_PACKAGE=node_package)
    python_code = '''import json,os,peerwork
c=peerwork.open_context(profile=os.environ["PEERWORK_CONTEXT_PROFILE"],expected_actor=os.environ["PEERWORK_CONTEXT_ACTOR"],expected_service=os.environ["PEERWORK_CONTEXT_SERVICE"])
print(json.dumps(c.recover(os.environ["PEERWORK_CONTEXT_WORKSPACE"],operation_id=os.environ["PEERWORK_CONTEXT_OPERATION"])))
'''
    recovered_process = subprocess.run([sys.executable, "-c", python_code], env=env,
        capture_output=True, text=True, timeout=120)
    assert recovered_process.returncode == 0, recovered_process.stderr[-1800:]
    recovered = json.loads(recovered_process.stdout)
    assert recovered["status"] == "verified" and recovered["result"]["command_id"] == command_id
    assert recovered["receipt"]["actor_id"] == actor_id
    # Object key order does not change semantic intent or manufacture a second effect.
    reordered = dict(refs=[], values={"body": intent["values"]["body"], "title": intent["values"]["title"]},
                     action_id="wiki.create", instance_id=instance_id, kind="protocol.action")
    repeated = ctx.operate(workspace_id, reordered, operation_id)
    assert repeated["status"] == "verified" and repeated["result"]["command_id"] == command_id
    try:
        ctx.operate(workspace_id, dict(intent, values={"title": "Changed intent", "body": "must refuse"}), operation_id)
    except peerwork.AgentContextError as error:
        assert error.code == "INTENT_CONFLICT", error.envelope
    else:
        raise AssertionError("same stable ID accepted changed intent")

    node_code = '''(async()=>{
const sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE);
const c=await sdk.openContext({profilePath:process.env.PEERWORK_CONTEXT_PROFILE,expectedActor:process.env.PEERWORK_CONTEXT_ACTOR,expectedService:process.env.PEERWORK_CONTEXT_SERVICE});
const d=(await c.discover(process.env.PEERWORK_CONTEXT_WORKSPACE)).result;
const instance=d.instances.find(x=>x.origin_entrypoint==='wiki');
const described=(await c.describe(process.env.PEERWORK_CONTEXT_WORKSPACE,{instanceId:instance.instance_id,actionId:'wiki.create'})).result;
const r=await c.recover(process.env.PEERWORK_CONTEXT_WORKSPACE,{operationId:process.env.PEERWORK_CONTEXT_OPERATION});
console.log(JSON.stringify({descriptor:c.descriptor,result:r,discovery:{instance_id:instance.instance_id,protocol_digest:described.refs.protocol_digest,execution:described.authority.execution}}));
})().catch(e=>{console.error(e);process.exitCode=1});'''
    node_result = subprocess.run([node, "-e", node_code], env=env, capture_output=True, text=True, timeout=120)
    assert node_result.returncode == 0, node_result.stderr[-1800:]
    node_value = json.loads(node_result.stdout)
    assert node_value["descriptor"] == ctx.descriptor
    assert node_value["discovery"] == dict(instance_id=instance_id,
        protocol_digest=selected["protocol_digest"], execution="not_evaluated")
    assert node_value["result"]["status"] == "verified"
    assert node_value["result"]["result"]["command_id"] == command_id
    request = protected_json(state / "context-recover.json", dict(workspace_id=workspace_id, operation_id=operation_id))
    for verb, extra in [("open", []), ("recover", [str(request)])]:
        proc = subprocess.run([cli, "context", verb, str(profile), actor_id, service, *extra],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, (proc.stdout[-1800:], proc.stderr[-1800:])
        result = json.loads(proc.stdout)
        assert result["ok"] is True and result["value"]["context"] == ctx.descriptor
        if verb == "recover":
            assert result["value"]["status"] == "verified"
            assert result["value"]["result"]["command_id"] == command_id
    discovery_request = protected_json(state / "context-discover.json", dict(workspace_id=workspace_id,
        expected_fingerprint=ctx.descriptor["fingerprint"], query=dict(limit=128)))
    cli_discovered = subprocess.run([cli, "context", "discover", str(profile), actor_id, service, str(discovery_request)],
        capture_output=True, text=True, timeout=120)
    assert cli_discovered.returncode == 0, "installed CLI discover failed"
    cli_discovery = json.loads(cli_discovered.stdout)
    assert cli_discovery["ok"] is True
    assert any(row["instance_id"] == instance_id and row["protocol_digest"] == selected["protocol_digest"]
        for row in cli_discovery["value"]["result"]["instances"])
    describe_request = protected_json(state / "context-describe.json", dict(workspace_id=workspace_id,
        expected_fingerprint=ctx.descriptor["fingerprint"], query=dict(instance_id=instance_id, action_id=action_id)))
    cli_described = subprocess.run([cli, "context", "describe", str(profile), actor_id, service, str(describe_request)],
        capture_output=True, text=True, timeout=120)
    assert cli_described.returncode == 0, "installed CLI describe failed"
    cli_description = json.loads(cli_described.stdout)
    assert cli_description["ok"] is True
    assert cli_description["value"]["result"]["refs"]["protocol_digest"] == selected["protocol_digest"]
    # Same actor/service but changed selected workspace set must invalidate the
    # previously opened handle before a request can run in the changed context.
    original_profile = profile.read_text()
    edited_profile = json.loads(original_profile)
    edited_profile["workspaces"] = {}
    protected_json(profile, edited_profile)
    before_rebind = counts(origin)
    try:
        ctx.operate(workspace_id, intent, "f" * 43)
    except peerwork.AgentContextError as error:
        assert error.code == "CONTEXT_CHANGED" and error.effect_certainty == "not_sent", error.envelope
    else:
        raise AssertionError("opened context accepted changed profile fingerprint")
    finally:
        profile.write_text(original_profile)
    assert counts(origin) == before_rebind
    final = ctx.inspect(workspace_id)["result"]["state"]
    record_id = recovered["refs"][0]["record_id"]
    record = next(row for row in final["objects"] if row.get("id") == record_id)
    assert record["value"]["payload"] == dict(intent["values"], author=actor_id, parent=None)
    exact_record = ctx.describe(workspace_id, record_id=record_id, revision=record["revision"])["result"]
    assert exact_record["object"] == record

    assert counts(origin)["commits"] == before_action["commits"] + 1
    assert final["sequence"] == before_action["head_sequence"] + 1
    # Actual signed action receipts, never synthetic event injection.
    changed_start = len(journal_probes())
    synced = ctx.events_sync(workspace_id)["result"]
    assert synced["sync_path"] == "full_history_replay"
    changed_probes = journal_probes()[changed_start:]
    assert any(row["after"] == "0" and row["returned_commits"] > 0 for row in changed_probes), changed_probes
    assert synced["semantics"]["reader"] == "checkpoint_probe_then_full_history_replay"
    assert synced["semantics"]["coverage"] == "action_receipts_only"
    assert synced["semantics"]["incremental"] is False
    assert synced["enqueued"] == 1, synced
    consumer, version = "installed-python", "all-v1"
    first = ctx.events_receive(workspace_id, consumer, filter_version=version,
                               lease_ms=30000, wait_ms=0)["result"]["delivery"]
    assert first is not None
    first_receipt = first["receipt"]
    assert first_receipt == json.loads(first["receipt_canonical_json"])
    assert first_receipt["command_id"] != command_id
    ctx.events_ack(workspace_id, consumer, first["ack_token"], filter_version=version)
    delivered = ctx.events_receive(workspace_id, consumer, filter_version=version,
                                   lease_ms=1, wait_ms=0)["result"]["delivery"]
    receipt = delivered["receipt"]
    assert receipt == json.loads(delivered["receipt_canonical_json"])
    assert receipt["command_id"] == command_id and receipt["actor_id"] == actor_id
    assert receipt["effects"] == recovered["refs"]
    assert receipt["commit_hash"] == recovered["receipt"]["commit_hash"]
    # Independent consumer has its own first event; it cannot acknowledge ours.
    independent = ctx.events_receive(workspace_id, "independent", filter_version=version,
                                     lease_ms=30000, wait_ms=0)["result"]["delivery"]
    assert independent["event_id"] == first["event_id"]
    try:
        ctx.events_ack(workspace_id, consumer, independent["ack_token"], filter_version=version)
    except peerwork.AgentContextError as error:
        assert error.code == "STALE_LEASE", error.envelope
    else:
        raise AssertionError("cross-consumer acknowledgement accepted")
    post(origin, "__test/block-api")
    try:
        offline_status = ctx.events_status(workspace_id)["result"]
        time.sleep(0.01)  # Expire the explicitly one-millisecond test lease.
        event_node = r'''(async()=>{
    const sdk=require(process.env.PEERWORK_TEST_NODE_PACKAGE);
    const c=await sdk.openContext({profilePath:process.env.PEERWORK_CONTEXT_PROFILE,expectedActor:process.env.PEERWORK_CONTEXT_ACTOR,expectedService:process.env.PEERWORK_CONTEXT_SERVICE});
    const r=await c.eventsReceive(process.env.PEERWORK_CONTEXT_WORKSPACE,'installed-python',{filterVersion:'all-v1',leaseMs:30000,waitMs:5000});
    console.log(JSON.stringify(r));
    })().catch(e=>{console.error(e);process.exitCode=1});'''
        child = subprocess.run([node, "-e", event_node], env=env, capture_output=True, text=True, timeout=120)
        assert child.returncode == 0, child.stderr[-1800:]
        redelivered = json.loads(child.stdout)["result"]["delivery"]
        assert redelivered["event_id"] == delivered["event_id"]
        assert redelivered["ack_token"] != delivered["ack_token"]
        assert redelivered["receipt"] == receipt
        assert json.loads(redelivered["receipt_canonical_json"]) == receipt
        try:
            ctx.events_ack(workspace_id, consumer, delivered["ack_token"], filter_version=version)
        except peerwork.AgentContextError as error:
            assert error.code == "STALE_LEASE", error.envelope
        else:
            raise AssertionError("expired acknowledgement accepted")
        event_request = protected_json(state / "context-event-ack.json", dict(workspace_id=workspace_id,
            expected_fingerprint=ctx.descriptor["fingerprint"], consumer_id=consumer,
            filter_version=version, ack_token=redelivered["ack_token"]))
        acked = subprocess.run([cli, "context", "event-ack", str(profile), actor_id, service, str(event_request)],
                                capture_output=True, text=True, timeout=120)
        assert acked.returncode == 0, (acked.stdout[-1800:], acked.stderr[-1800:])
        assert json.loads(acked.stdout)["ok"] is True
        empty = ctx.events_receive(workspace_id, consumer, filter_version=version, wait_ms=0)["result"]
        assert empty["delivery"] is None and empty["consumer"]["pending_events"] == 0
        assert ctx.events_status(workspace_id)["result"] == offline_status
        with urllib.request.urlopen(origin + "__test/api-block-status", timeout=10) as response:
            outage = json.load(response)
        assert outage == {"blocked": True, "blocked_api_attempts": 0}, outage
    finally:
        post(origin, "__test/unblock-api")
    unchanged = ctx.events_sync(workspace_id)["result"]
    assert unchanged["changed"] is False and unchanged["enqueued"] == 0
    status_before_cancel = ctx.events_status(workspace_id)["result"]

    async def cancel_wait():
        task = asyncio.create_task(ctx.events_receive_async(workspace_id, consumer,
            filter_version=version, wait_ms=5000))
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=3)
        except asyncio.CancelledError:
            return
        raise AssertionError("native event wait did not cancel")
    asyncio.run(cancel_wait())
    assert ctx.events_status(workspace_id)["result"] == status_before_cancel
    after_cancel = ctx.events_receive(workspace_id, consumer, filter_version=version, wait_ms=0)["result"]
    assert after_cancel["delivery"] is None and after_cancel["consumer"] == empty["consumer"]
    deadline = ctx.events_receive(workspace_id, consumer, filter_version=version, wait_ms=1)["result"]
    assert deadline["delivery"] is None and deadline["wait_status"] == "deadline"
    assert counts(origin)["commits"] == before_action["commits"] + 1
    # Local checkpoint fault injection only: this does not emulate external
    # source retention. The real signed replay must refuse an unknown floor.
    inbox_path = recipient_dir / "agent-events.sqlite"
    assert inbox_path.is_file()
    with sqlite3.connect(inbox_path) as db:
        cursor_wire, original_gap = db.execute("SELECT cursor,gap FROM inbox_meta WHERE id=1").fetchone()
        assert original_gap == 0
        cursor = json.loads(cursor_wire)
        head = cursor["head"]
        assert isinstance(head, str) and head
        cursor["head"] = ("0" if head[0] != "0" else "1") + head[1:]
        fault_cursor = json.dumps(cursor, separators=(",", ":"))
        before_events = db.execute("SELECT * FROM inbox_events ORDER BY position").fetchall()
        before_consumers = db.execute("SELECT * FROM inbox_consumers ORDER BY consumer,filter_version").fetchall()
        db.execute("UPDATE inbox_meta SET cursor=? WHERE id=1", (fault_cursor,))
    try:
        ctx.events_sync(workspace_id)
    except peerwork.AgentContextError as error:
        assert error.code == "SOURCE_GAP", error.envelope
    else:
        raise AssertionError("signed sync accepted an unknown checkpoint")
    for refused in [
        lambda: ctx.events_receive(workspace_id, consumer, filter_version=version, wait_ms=0),
        lambda: ctx.events_ack(workspace_id, consumer, redelivered["ack_token"], filter_version=version),
    ]:
        try:
            refused()
        except peerwork.AgentContextError as error:
            assert error.code == "SOURCE_GAP", error.envelope
        else:
            raise AssertionError("gap allowed delivery or acknowledgement")
    with sqlite3.connect(inbox_path) as db:
        assert db.execute("SELECT cursor,gap FROM inbox_meta WHERE id=1").fetchone() == (fault_cursor, 1)
        assert db.execute("SELECT * FROM inbox_events ORDER BY position").fetchall() == before_events
        assert db.execute("SELECT * FROM inbox_consumers ORDER BY consumer,filter_version").fetchall() == before_consumers
    result = dict(status="PASS", installed_agent_context=True, python_operate_recover=True,
                  verified_discover_describe=True, exact_record_read=True,
                  idle_probe_zero_history_transfer=True, changed_source_full_replay=True,
                  node_cli_open_recover=True, exact_single_effect=True, context_bind=True,
                  verified_action_receipt_delivery=True, independent_consumers=True,
                  offline_status_receive_ack_no_requests=True, offline_positive_wait_queued=True,
                  local_checkpoint_fault_gap_refusal=True,
                  lease_restart_redelivery=True, stale_ack_refused=True, bounded_cancel_wait=True, command_id=command_id,
                  operation_id=operation_id, final_sequence=final["sequence"])
    print(json.dumps(result))
    return result
