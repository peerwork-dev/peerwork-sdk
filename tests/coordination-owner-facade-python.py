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
error_mode = False
native = types.ModuleType("peerwork._peerwork_native")

class CancelHandle:
    cancelled = False
    def cancel(self):
        self.cancelled = True

def owner_call(operation, config, input_json, command_id, workspace_id, cancel_handle):
    calls.append((operation, json.loads(config), None if input_json is None else json.loads(input_json),
                  command_id, workspace_id, cancel_handle))
    if error_mode:
        return json.dumps({"ok":False,"code":"COORDINATION_CONFLICT","message":"selected operation conflicts"})
    if block:
        started.set()
        assert release.wait(5), "test worker release timeout"
        finished.set()
    return json.dumps({"ok": True, "value": [] if operation == "coordination_operations" else {
        "status":"PENDING", "workspace_id":workspace_id, "version":2,
        "protocol_digest":"d" * 64, "instance_id":"i" * 43,
        "begin_command_id":"b" * 43, "step_command_id":"e" * 43,
        "step_action_id":"secure.structure.begin", "sequence":None,
        "head":None, "policy_hash":None}})

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
workspace, begin = "w" * 43, "b" * 43
client.enable_coordination(workspace)
assert calls[-1][0] == "coordination_enable" and calls[-1][2] == {"version":None,"participants":None}
assert calls[-1][3:5] == (None, workspace)
value = client.enable_coordination(workspace, version=2, participants=[])
assert calls[-1][2] == {"version":2,"participants":[]}
assert value["begin_command_id"] == begin and value["sequence"] is None
client.enable_coordination(workspace, version=1, participants=["a" * 43])
assert calls[-1][2]["participants"] == ["a" * 43]
client.resume_coordination(workspace, begin)
assert calls[-1][0] == "coordination_resume" and calls[-1][2] is None
assert calls[-1][3:5] == (begin, workspace)
assert client.coordination_operations(workspace) == []
assert calls[-1][0] == "coordination_operations" and calls[-1][4] == workspace
assert "OwnerCoordinationProgress" in peerwork.__all__
before = len(calls)
for kwargs in [{"version":True}, {"version":3}, {"version":"2"},
               {"participants":"actor"}, {"participants":[""]}, {"participants":[1]},
               {"material":{}}, {"grants":[]}]:
    try: client.enable_coordination(workspace, **kwargs)
    except TypeError: pass
    else: raise AssertionError("invalid input crossed native boundary")
assert len(calls) == before
error_mode = True
try: client.resume_coordination(workspace, begin)
except peerwork.OwnerWorkspaceError as error:
    assert error.code == "COORDINATION_CONFLICT" and str(error) == "selected operation conflicts"
else: raise AssertionError("native error was not forwarded")
error_mode = False

async def check_async():
    global block
    await client.enable_coordination_async(workspace, version=2, participants=[])
    await client.resume_coordination_async(workspace, begin)
    await client.coordination_operations_async(workspace)
    assert [row[0] for row in calls[-3:]] == ["coordination_enable", "coordination_resume", "coordination_operations"]
    assert calls[-3][2] == {"version":2,"participants":[]}
    assert all(isinstance(row[-1], CancelHandle) for row in calls[-3:])
    block = True
    task = asyncio.create_task(client.enable_coordination_async(workspace, version=2))
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done(), "cancelled caller must wait for owned worker"
    assert calls[-1][-1].cancelled
    release.set()
    try: await task
    except asyncio.CancelledError: assert finished.is_set()
    else: raise AssertionError("cancel must propagate after drain")

asyncio.run(check_async())
print("Python coordination sync/async input, original BEGIN, local history and cancellation drain PASS (stub boundary)")
