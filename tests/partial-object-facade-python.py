"""Public Python marshalling and cancellation ownership; stub native boundary only."""
import asyncio
import json
import sys
import threading
import types
from pathlib import Path

calls = []
started, release, finished = threading.Event(), threading.Event(), threading.Event()
block = False
native = types.ModuleType("peerwork._peerwork_native")

class CancelHandle:
    cancelled = False
    def cancel(self):
        self.cancelled = True

def owner_call(operation, config, input_json, command_id, workspace_id, cancel_handle):
    calls.append((operation, json.loads(config), None if input_json is None else json.loads(input_json),
                  command_id, workspace_id, cancel_handle))
    if block:
        started.set()
        assert release.wait(5), "test worker release timeout"
        finished.set()
    return json.dumps({"ok": True, "value": {"status": "ATTACHED_RESTRICTED",
        "pending_object_stage_command_id": "s" * 43,
        "pending_object_stage_native_begin_command_id": "n" * 43}})

native.KernelCancelHandle = CancelHandle
native.secure_owner_create_json = owner_call
for name in (
    "acquisition_observations_json", "capabilities_json", "identity_create_json", "identity_open_json",
    "identity_import_seed_json", "identity_import_pkcs8_pem_json", "identity_import_owner_pem_json", "kernel_json",
    "secure_read_json", "secure_read_profile_json", "secure_private_read_json",
    "secure_public_action_json", "secure_public_install_json", "secure_owner_consumer_json",
    "public_catalog_json", "secure_recipient_enrollment_json", "secure_identity_directory_json",
    "secure_public_admission_json", "secure_public_decision_json", "version",
):
    setattr(native, name, lambda *args: None)
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings/python"))
import peerwork  # noqa: E402

client = peerwork.SecureOwnerWorkspaceClient("https://control.example", "/protected/root")
args = ("w" * 43, "/protected/source/state", "/protected/source/intents.sqlite",
        "/protected/source/owner.pem", "a" * 43, "k" * 43, "s" * 43,
        '{ "instance_id": "chosen", "label": "雪" }', '{ "closure": {} }')
digest, attach_id = "d" * 64, "t" * 43
client.inspect_pending_object_stage(*args)
request = calls[-1][2]
assert calls[-1][0] == "object_stage_inspect"
assert set(request) == {"attachment_input", "selected_command_id", "expected_ts_state_digest", "options_json", "material_json"}
assert request["selected_command_id"] == args[6] and request["expected_ts_state_digest"] is None
assert (request["options_json"], request["material_json"]) == args[7:]
assert request["attachment_input"]["protected_ts_state_path"] == args[1]
client.attach_pending_object_stage(*args[:7], digest, *args[7:])
assert calls[-1][0] == "object_stage_attach" and calls[-1][2]["expected_ts_state_digest"] == digest
result = client.recover_pending_object_stage(attach_id, args[6])
assert calls[-1][0] == "object_stage_recover" and calls[-1][3:5] == (args[6], attach_id)
assert result["pending_object_stage_native_begin_command_id"] != result["pending_object_stage_command_id"]
assert "HistoricalObjectStagePendingInventory" in peerwork.__all__
before = len(calls)
for invalid in (
    lambda: client.inspect_pending_object_stage(*args[:6], "", *args[7:]),
    lambda: client.inspect_pending_object_stage(*args[:7], "", args[8]),
    lambda: client.inspect_pending_object_stage(*args[:8], ""),
    lambda: client.attach_pending_object_stage(*args[:7], "", *args[7:]),
):
    try:
        invalid()
    except (TypeError, ValueError):
        pass
    else:
        raise AssertionError("invalid selection crossed native boundary")
assert len(calls) == before

async def check_async():
    global block
    await client.inspect_pending_object_stage_async(*args)
    await client.attach_pending_object_stage_async(*args[:7], digest, *args[7:])
    await client.recover_pending_object_stage_async(attach_id, args[6])
    assert [row[0] for row in calls[-3:]] == ["object_stage_inspect", "object_stage_attach", "object_stage_recover"]
    assert all(isinstance(row[-1], CancelHandle) for row in calls[-3:])
    block = True
    task = asyncio.create_task(client.recover_pending_object_stage_async(attach_id, args[6]))
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done(), "cancelled caller must wait for the owned worker"
    assert calls[-1][-1].cancelled
    release.set()
    try:
        await task
    except asyncio.CancelledError:
        assert finished.is_set()
    else:
        raise AssertionError("cancel must propagate after drain")

asyncio.run(check_async())
print("Python partial object sync/async routing, exact strings, source IDs, and cancellation drain PASS (stub boundary)")
