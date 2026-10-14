"""Source-only Python facade routing and preflight; no native service call."""

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
    calls.append((operation, json.loads(config), json.loads(input_json), command_id,
                  workspace_id, cancel_handle))
    return json.dumps({"ok": True, "value": {"status": "ORPHAN_NO_PACKET"}})


native.KernelCancelHandle = CancelHandle
native.secure_owner_create_json = owner_call
for name in (
    "capabilities_json", "identity_create_json", "identity_open_json",
    "identity_import_seed_json", "identity_import_pkcs8_pem_json", "kernel_json",
    "secure_read_json", "secure_read_profile_json", "secure_private_read_json",
    "secure_public_action_json", "secure_public_install_json", "secure_owner_consumer_json",
    "public_catalog_json", "secure_recipient_enrollment_json",
    "secure_identity_directory_json", "secure_public_admission_json",
    "secure_public_decision_json", "version",
):
    setattr(native, name, lambda *args: None)
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings" / "python"))
import peerwork  # noqa: E402
from peerwork import SecureOwnerWorkspaceClient  # noqa: E402


client = SecureOwnerWorkspaceClient("https://control.example", "/protected/root")
args = ("w" * 43, "/protected/legacy/state", "/protected/legacy/intents.sqlite",
        "/protected/legacy/owner.pem", "a" * 43, "k" * 43, '{"v":1}')
selected = "c" * 43
digest = "d" * 64

assert client.inspect_multipart_orphan_package_stage(*args)["status"] == "ORPHAN_NO_PACKET"
op, _, envelope, _, _, _ = calls[-1]
assert op == "orphan_multipart_inspect"
assert envelope["material_json"] == args[-1]
assert envelope["attachment_input"]["selected_orphan_package_stage_command_id"] is None

client.attach_multipart_orphan_package_stage(*args,
    selected_orphan_package_stage_command_id=selected, expected_ts_state_digest=digest)
op, _, envelope, _, _, _ = calls[-1]
assert op == "orphan_multipart_attach"
assert envelope["attachment_input"]["selected_orphan_package_stage_command_id"] == selected
assert envelope["attachment_input"]["expected_ts_state_digest"] == digest

before = len(calls)
for kwargs, error in (
    ({"selected_orphan_package_stage_command_id": selected,
      "expected_ts_state_digest": None}, ValueError),
    ({"selected_orphan_package_stage_command_id": "",
      "expected_ts_state_digest": digest}, TypeError),
):
    try:
        client.attach_multipart_orphan_package_stage(*args, **kwargs)
    except error:
        pass
    else:
        raise AssertionError(f"expected {error.__name__}")
try:
    client.inspect_multipart_orphan_package_stage(*args[:-1], "")
except TypeError:
    pass
else:
    raise AssertionError("empty material accepted")
assert len(calls) == before


async def check_async():
    # Exercise wrapper routing without starting a native worker in this source test.
    async def invoke(method, operation, **kwargs):
        return method(operation, **kwargs)
    peerwork._run_cancelled_async = invoke
    assert (await client.inspect_multipart_orphan_package_stage_async(*args))["status"] == "ORPHAN_NO_PACKET"
    await client.attach_multipart_orphan_package_stage_async(*args,
        selected_orphan_package_stage_command_id=selected, expected_ts_state_digest=digest)


asyncio.run(check_async())
assert [row[0] for row in calls[-2:]] == ["orphan_multipart_inspect", "orphan_multipart_attach"]
print("Python orphan multipart facade: sync, async and preflight PASS")
