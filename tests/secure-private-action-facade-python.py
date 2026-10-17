"""PRIVATE action facade binds every call to its explicit protected profile."""
import asyncio
import json
import sys
import types
from pathlib import Path

calls = []
actions = {}
native = types.ModuleType("peerwork._peerwork_native")


class CancelHandle:
    def cancel(self):
        pass


def private_action(operation, config_json, input_json, command_id, operation_id, cancel_handle):
    config = json.loads(config_json)
    value = None if input_json is None else json.loads(input_json)
    calls.append((operation, config, value, command_id, operation_id, cancel_handle))
    if operation == "pending":
        return json.dumps({"ok": True, "value": [{"command_id": "c" * 43, "workspace_id": config["workspace_id"]}]})
    if operation in {"reconcile", "retry"} and command_id == "bad":
        return json.dumps({"ok": False, "code": "INTENT_NOT_FOUND", "message": "saved intent not found"})
    if operation == "submit":
        actions[command_id or "c" * 43] = value["action_id"]
    result = {"status": "PENDING", "command_id": command_id or "c" * 43,
              "workspace_id": config["workspace_id"], "action_id": value["action_id"] if value is not None else actions[command_id],
              "sequence": None, "commit_hash": None, "receipt_canonical_json": None}
    wire = json.dumps({"ok": True, "value": result})
    return wire


native.KernelCancelHandle = CancelHandle
for name in (
    "acquisition_observations_json", "capabilities_json", "identity_create_json", "identity_open_json",
    "identity_import_seed_json", "identity_import_pkcs8_pem_json", "identity_import_owner_pem_json",
    "kernel_json", "secure_read_json", "secure_read_profile_json", "secure_private_read_json",
    "secure_public_action_json", "secure_private_action_json", "secure_public_install_json",
    "secure_owner_create_json", "secure_owner_consumer_json", "public_catalog_json",
    "secure_recipient_enrollment_json", "secure_identity_directory_json", "secure_public_admission_json",
    "secure_public_decision_json", "version",
):
    setattr(native, name, lambda *args: None)
native.secure_private_action_json = private_action
native.load_config_json = lambda path=None: json.dumps({"ok": True, "value": {"origin": "https://control.example", "state_dir": "/profile-a"}})
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings/python"))
import peerwork  # noqa: E402

first = peerwork.SecurePrivateActionClient("https://control.example", "/actors/alice/state", "/actors/alice/id.pem", "workspace-a",
                                           owner_actor_id="owner-a", owner_key_id="owner-key-a")
second = peerwork.SecurePrivateActionClient("https://control.example", "/actors/bob/state", "/actors/bob/id.pem", "workspace-a",
                                            owner_actor_id="owner-a", owner_key_id="owner-key-a")
pending = first.submit("discussion.post", "instance-a", {"message": "private"}, operation_id="alice-op-1")
assert pending["status"] == "PENDING" and pending["workspace_id"] == "workspace-a"
operation, config, value, command_id, operation_id, cancel = calls[-1]
assert operation == "submit" and operation_id == "alice-op-1" and command_id is None and cancel is None
assert config["state_dir"] == "/actors/alice/state" and config["identity_path"] == "/actors/alice/id.pem"
assert config["workspace_id"] == "workspace-a" and config["owner_actor_id"] == "owner-a"
assert value["body_json"] == '{"message":"private"}' and value["action_id"] == "discussion.post"

# A second actor/context selects its own explicit protected state; it never
# inherits the first profile or mutates process-global selection.
second.submit("discussion.post", "instance-a", {"message": "separate"}, operation_id="bob-op-1")
assert calls[-1][1]["state_dir"] == "/actors/bob/state"

assert first.reconcile(pending["command_id"])["status"] == "PENDING"
assert first.resume(pending["command_id"])["command_id"] == pending["command_id"]
assert first.retry_saved(pending["command_id"])["command_id"] == pending["command_id"]
assert first.pending()[0]["command_id"] == "c" * 43
assert [row[0] for row in calls[-4:]] == ["reconcile", "reconcile", "retry", "pending"]

try:
    first.reconcile("bad")
except peerwork.SecureActionError as error:
    assert error.code == "INTENT_NOT_FOUND"
else:
    raise AssertionError("native intent refusal was not surfaced")

try:
    first.submit("discussion.post", "instance-a", {"bad": float("nan")})
except ValueError:
    pass
else:
    raise AssertionError("non-finite JSON crossed the native boundary")


async def check_async():
    result = await first.submit_async("discussion.post", "instance-a", {"message": "async"}, operation_id="alice-op-2")
    assert result["status"] == "PENDING" and isinstance(calls[-1][-1], CancelHandle)
    command = result["command_id"]
    assert (await first.reconcile_async(command))["command_id"] == command
    assert (await first.resume_async(command))["command_id"] == command
    assert (await first.retry_saved_async(command))["command_id"] == command
    assert (await first.pending_async())[0]["workspace_id"] == "workspace-a"


asyncio.run(check_async())
assert "SecurePrivateActionClient" in peerwork.__all__
print("PRIVATE action facade explicit-profile marshalling and sync/async recovery methods PASS (real executor, stub native boundary)")
