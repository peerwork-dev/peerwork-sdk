"""Python JSON mapping/validation for the restored signed-commit budget."""
import asyncio
import json
import sys
import types
from pathlib import Path

seen = []
native = types.ModuleType("peerwork._peerwork_native")


class CancelHandle:
    def cancel(self):
        pass


def response(method):
    def call(*args):
        config_json = args[0] if method in ("snapshot", "read", "owner", "invitation") else args[1]
        seen.append((method, json.loads(config_json)))
        return json.dumps({"ok": True, "value": [] if method in ("owner", "invitation") else {
            "origin": "https://control.example", "workspace_id": "w" * 43,
            "sequence": 0, "head": None, "policy_hash": "p" * 64,
            "structure_status": "ACTIVE", "objects": [], "operations": [], "recoveries": []}})
    return call


native.KernelCancelHandle = CancelHandle
native.secure_read_json = response("snapshot")
native.secure_read_profile_json = response("read")
native.secure_owner_create_json = lambda operation, config, *_: (
    seen.append(("owner", json.loads(config))) or json.dumps({"ok": True, "value": []}))
native.secure_public_decision_json = lambda operation, config, *_: (
    seen.append(("invitation", json.loads(config))) or json.dumps({"ok": True, "value": []}))
for name in (
    "acquisition_observations_json", "capabilities_json", "load_config_json", "identity_create_json",
    "identity_open_json", "identity_import_seed_json", "identity_import_pkcs8_pem_json",
    "identity_import_owner_pem_json", "kernel_json", "secure_private_read_json", "secure_public_action_json",
    "secure_public_install_json", "secure_owner_consumer_json", "public_catalog_json",
    "secure_recipient_enrollment_json", "secure_identity_directory_json", "secure_public_admission_json", "version",
):
    setattr(native, name, lambda *args: None)
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings/python"))
import peerwork  # noqa: E402

base = ("https://control.example", "/protected/state")
snapshot_args = (*base[:1], "/protected/journal", "/protected/read", "/protected/lifecycle",
                 "/protected/identity", "w" * 43, "a" * 43, "o" * 43, "k" * 43)
for cls, invoke, args in (
    (peerwork.SecureSnapshotClient, lambda c: c.read(), snapshot_args),
    (peerwork.SecureReadClient, lambda c: c.read(), (*base[:1], base[1], "/protected/identity", "w" * 43)),
    (peerwork.SecureOwnerWorkspaceClient, lambda c: c.operations(), base),
    (peerwork.SecureInvitationClient, lambda c: c.pending_decisions(),
     (*base, "w" * 43, "a" * 43, "k" * 43)),
):
    default_client = cls(*args)
    invoke(default_client)
    assert seen[-1][1]["max_replay_commits"] == 102400, (cls.__name__, seen[-1])
    assert seen[-1][1]["max_replay_artifact_bytes"] == 64 * 1024 * 1024
    explicit_client = cls(*args, max_replay_artifact_bytes=4096, max_replay_commits=27)
    invoke(explicit_client)
    assert seen[-1][1]["max_replay_commits"] == 27, (cls.__name__, seen[-1])
    assert seen[-1][1]["max_replay_artifact_bytes"] == 4096
    for invalid in (True, False, 0, -1, 1.5, "27", 2**64):
        before = len(seen)
        try:
            cls(*args, max_replay_commits=invalid)
        except ValueError as error:
            assert "positive u64" in str(error)
        else:
            raise AssertionError(f"{cls.__name__} accepted invalid max_replay_commits={invalid!r}")
        assert len(seen) == before, "invalid limit crossed native boundary"


async_client = peerwork.SecureReadClient(*base[:1], base[1], "/protected/identity", "w" * 43,
                                         max_replay_artifact_bytes=8192, max_replay_commits=31)


async def inline_to_thread(function, /, *args, **kwargs):
    # Exercise the async wrapper's config path without a worker-thread runtime claim.
    return function(*args, **kwargs)


peerwork.asyncio.to_thread = inline_to_thread
asyncio.run(async_client.read_async())
assert seen[-1][0] == "read" and seen[-1][1]["max_replay_commits"] == 31
assert seen[-1][1]["max_replay_artifact_bytes"] == 8192
print("Python four-constructor mapping plus inline-stub async config PASS (stub native boundary)")
