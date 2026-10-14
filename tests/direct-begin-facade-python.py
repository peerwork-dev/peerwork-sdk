"""Source-only Python public routing and preflight, without native service calls."""
import asyncio
import json
import sys
import types
from pathlib import Path

calls = []
native = types.ModuleType("peerwork._peerwork_native")
class CancelHandle:
    def cancel(self):
        pass

def owner_call(operation, config, input_json, command_id, workspace_id, cancel_handle):
    calls.append((operation, json.loads(config), None if input_json is None else json.loads(input_json),
                  command_id, workspace_id, cancel_handle))
    return json.dumps({"ok": True, "value": {"status": "PENDING_UNRESOLVED"}})

native.KernelCancelHandle = CancelHandle
native.secure_owner_create_json = owner_call
for name in (
    "capabilities_json", "identity_create_json", "identity_open_json",
    "identity_import_seed_json", "identity_import_pkcs8_pem_json", "kernel_json",
    "secure_read_json", "secure_read_profile_json", "secure_private_read_json",
    "secure_public_action_json", "secure_public_install_json", "secure_owner_consumer_json",
    "public_catalog_json", "secure_recipient_enrollment_json", "secure_identity_directory_json",
    "secure_public_admission_json", "secure_public_decision_json", "version",
):
    setattr(native, name, lambda *args: None)
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings" / "python"))
import peerwork  # noqa: E402
from peerwork import SecureOwnerWorkspaceClient  # noqa: E402

client = SecureOwnerWorkspaceClient("https://control.example", "/protected/root")
args = ("w" * 43, "/protected/legacy/state", "/protected/legacy/intents.sqlite",
        "/protected/legacy/owner.pem", "a" * 43, "k" * 43,
        "c" * 43, '{"visibility":"PRIVATE"}', '{"v":1}')
digest = "d" * 64
client.inspect_pending_direct_install_begin(*args)
assert calls[-1][0] == "direct_begin_inspect"
assert calls[-1][2]["selected_command_id"] == args[6]
assert calls[-1][2]["expected_ts_state_digest"] is None
assert calls[-1][2]["options_json"] == args[7]
assert calls[-1][2]["material_json"] == args[8]
client.attach_pending_direct_install_begin(*args[:7], digest, *args[7:])
assert calls[-1][0] == "direct_begin_attach"
assert calls[-1][2]["expected_ts_state_digest"] == digest
client.recover_pending_direct_install_begin("t" * 43, args[6])
assert calls[-1][0] == "direct_begin_recover"
assert calls[-1][3:5] == (args[6], "t" * 43)
before = len(calls)
for operation in (
    lambda: client.attach_pending_direct_install_begin(*args[:7], "", *args[7:]),
    lambda: client.inspect_pending_direct_install_begin(*args[:7], "", args[8]),
):
    try:
        operation()
    except (TypeError, ValueError):
        pass
    else:
        raise AssertionError("invalid direct BEGIN input accepted")
assert len(calls) == before
async def check_async():
    async def invoke(method, operation, **kwargs):
        return method(operation, **kwargs)
    peerwork._run_cancelled_async = invoke
    await client.inspect_pending_direct_install_begin_async(*args)
    await client.attach_pending_direct_install_begin_async(*args[:7], digest, *args[7:])
    await client.recover_pending_direct_install_begin_async("t" * 43, args[6])
asyncio.run(check_async())
assert [row[0] for row in calls[-3:]] == ["direct_begin_inspect", "direct_begin_attach", "direct_begin_recover"]
print("Python direct BEGIN facade sync, async and preflight PASS")
