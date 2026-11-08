"""Explicit transport option marshalling; native boundary is stubbed."""
import json
import sys
import types
from pathlib import Path

calls = []
native = types.ModuleType("peerwork._peerwork_native")
class CancelHandle:
    def cancel(self): pass
native.KernelCancelHandle = CancelHandle

def stub(name):
    def call(*args):
        calls.append((name, args))
        value = {"listing_canonical_json": "{}"} if name == "public_catalog_json" else {}
        return json.dumps({"ok": True, "value": value})
    return call
for name in ("acquisition_observations_json", "capabilities_json", "identity_create_json", "identity_open_json",
             "identity_import_seed_json", "identity_import_pkcs8_pem_json", "identity_import_owner_pem_json",
             "kernel_json", "secure_read_json", "secure_read_profile_json", "secure_private_read_json",
             "secure_public_action_json", "secure_public_install_json", "secure_owner_create_json",
             "secure_owner_consumer_json", "public_catalog_json", "secure_recipient_enrollment_json",
             "secure_identity_directory_json", "secure_public_admission_json", "secure_public_decision_json", "version"):
    setattr(native, name, stub(name))
native.load_config_json = stub("load_config_json")
native.load_config_json = lambda path=None: json.dumps({"ok": True, "value": {
    "origin": "https://example", "state_dir": "/state", "transport": {
        "request_timeout_ms": 2345, "additional_root_pem_files": ["root-a.pem"]}}})
sys.modules[native.__name__] = native
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings/python"))
import peerwork

explicit = peerwork.TransportOptions(2345, ["root-a.pem", "root-b.pem"])
assert explicit.additional_root_pem_files == ("root-a.pem", "root-b.pem")
expected = {"request_timeout_ms": 2345, "additional_root_pem_files": ["root-a.pem", "root-b.pem"]}
loaded = peerwork.load_config()
assert loaded["transport"] == peerwork.TransportOptions(2345, ("root-a.pem",))
peerwork.SecureReadClient("https://example", "/s", "/id", "w", transport=loaded["transport"]).read()
assert json.loads(calls[-1][1][0])["transport"] == {
    "request_timeout_ms": 2345, "additional_root_pem_files": ["root-a.pem"]}
# All JSON-config profiles share one strict nested representation.
read = peerwork.SecureReadClient("https://example", "/s", "/id", "w", transport=explicit)
read.read()
assert json.loads([args[0] for name, args in calls if name == "secure_read_profile_json"][-1])["transport"] == expected
snap = peerwork.SecureSnapshotClient("https://example", "/j", "/r", "/l", "/id", "w", "a", "o", "k", transport=explicit)
snap.read()
assert json.loads(next(args[0] for name, args in calls if name == "secure_read_json"))["transport"] == expected
owner = peerwork.SecureOwnerWorkspaceClient("https://example", "/s", transport=explicit)
owner.coordination_operations("w")
assert json.loads(next(args[1] for name, args in calls if name == "secure_owner_create_json"))["transport"] == expected
catalog = peerwork.PublicCatalogClient("https://example", transport=explicit)
catalog.search("x")
assert json.loads(next(args[1] for name, args in calls if name == "public_catalog_json"))["transport"] == expected
invite = peerwork.SecureInvitationClient("https://example", "/s", "w", "a", "k", transport=explicit)
invite.pending_decisions()
assert json.loads(next(args[1] for name, args in calls if name == "secure_public_decision_json"))["transport"] == expected
# Dedicated positional bridges append their wire value without changing earlier arguments.
enrollment = peerwork.SecureRecipientEnrollmentClient("https://example", "/s", transport=explicit)
enrollment.pending()
assert calls[-1][0] == "secure_recipient_enrollment_json" and json.loads(calls[-1][1][-1]) == expected
directory = peerwork.SecureIdentityDirectoryClient("https://example", "/s", transport=explicit)
directory.lookup("actor", "key")
assert calls[-1][0] == "secure_identity_directory_json" and json.loads(calls[-1][1][-1]) == expected
kernel = peerwork.KernelClient("https://example", "/j", "/id", transport=explicit)
kernel._call("open")
assert calls[-1][0] == "kernel_json" and json.loads(calls[-1][1][-1]) == expected
# Omission preserves the previous JSON shape and final bridge argument.
before = len(calls)
peerwork.SecureReadClient("https://example", "/s", "/id", "w").read()
config = json.loads(calls[-1][1][0])
assert "transport" not in config
peerwork.SecureRecipientEnrollmentClient("https://example", "/s").pending()
assert calls[-1][1][-1] is None
# No client opens or reads CA paths; invalid data is rejected at facade boundary.
for value in (True, 0, -1, 2**64, 1.5):
    try: peerwork.TransportOptions(request_timeout_ms=value)
    except ValueError: pass
    else: raise AssertionError("invalid timeout accepted")
for paths in ([""], [1], ["x"] * 17, "root.pem"):
    try: peerwork.TransportOptions(additional_root_pem_files=paths)
    except ValueError: pass
    else: raise AssertionError("invalid CA path list accepted")
try: peerwork.SecureReadClient("https://example", "/s", "/id", "w", transport={})
except TypeError: pass
else: raise AssertionError("untyped transport accepted")
assert len(calls) > before
assert "TransportOptions" in peerwork.__all__
print("Python explicit/omitted transport marshalling and validation PASS (stub boundary)")
