#!/usr/bin/env python3
"""The Owner config-aware import must feed the next public Owner command."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile


binary = Path(sys.argv[1]).resolve()
assert binary.is_file()


def call(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary), *args], cwd=root,
                          capture_output=True, text=True, check=False)


der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(1, 33))
pem = ("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(der).decode() +
       "\n-----END PRIVATE KEY-----\n")

with tempfile.TemporaryDirectory(prefix="peerwork-owner-identity-") as temporary:
    root = Path(temporary).resolve()
    root.chmod(0o700)
    source = root / "source"
    state = root / "state"
    source.mkdir(mode=0o700)
    protected_pem = source / "owner.pem"
    protected_pem.write_text(pem)
    protected_pem.chmod(0o600)
    config = root / "owner.json"
    config.write_text(json.dumps({"origin": "http://127.0.0.1:1/",
                                  "state_dir": str(state), "allow_loopback_http": True}))
    config.chmod(0o600)

    # Both absence of the configured directory and absence of its identity
    # must give actionable public guidance without creating either one.
    for args in (("secure", "owner-operations", "owner.json"),
                 ("secure", "owner-read", "owner.json", "selected-workspace")):
        absent = call(root, *args)
        error = json.loads(absent.stderr)
        assert absent.returncode != 0 and error["code"] == "IDENTITY_MISSING", error
        assert "identity import-legacy-owner-pem" in error["message"]
        assert str(root) not in error["message"]
        assert not state.exists()
    state.mkdir(mode=0o700)

    # The prior generic command may import a valid actor/key to a different
    # native file; the Owner profile must still reject that wrong placement.
    wrong = call(root, "identity", "import-legacy-pem", "state/other.identity", "source/owner.pem")
    assert wrong.returncode == 0, wrong.stderr
    before = call(root, "secure", "owner-operations", "owner.json")
    assert before.returncode != 0 and json.loads(before.stderr)["code"] == "IDENTITY_MISSING"
    assert not (state / "identity.state").exists()

    imported = call(root, "identity", "import-legacy-owner-pem", "owner.json", "source/owner.pem")
    assert imported.returncode == 0, imported.stderr
    public_ids = json.loads(imported.stdout)
    assert set(public_ids) == {"actor_id", "key_id"}
    native_identity = state / "identity.state"
    assert native_identity.is_file()
    info = call(root, "identity", "info", "state/identity.state")
    assert info.returncode == 0 and json.loads(info.stdout) == public_ids
    after = call(root, "secure", "owner-operations", "owner.json")
    assert after.returncode == 0 and json.loads(after.stdout) == []

    # Existing malformed, loose and symlinked identities retain the prior
    # changed-identity refusal and are never relabeled as absent or rewritten.
    original_identity = native_identity.read_bytes()
    native_identity.write_bytes(b"corrupt")
    corrupt = call(root, "secure", "owner-operations", "owner.json")
    assert corrupt.returncode != 0 and json.loads(corrupt.stderr)["code"] == "IDENTITY_CHANGED"
    assert native_identity.read_bytes() == b"corrupt"
    native_identity.write_bytes(original_identity)
    native_identity.chmod(0o644)
    unprotected = call(root, "secure", "owner-operations", "owner.json")
    assert unprotected.returncode != 0 and json.loads(unprotected.stderr)["code"] == "IDENTITY_CHANGED"
    native_identity.chmod(0o600)
    native_identity.rename(state / "saved.identity")
    native_identity.symlink_to(state / "saved.identity")
    linked_identity = call(root, "secure", "owner-operations", "owner.json")
    assert linked_identity.returncode != 0 and json.loads(linked_identity.stderr)["code"] == "IDENTITY_CHANGED"
    native_identity.unlink()
    (state / "saved.identity").rename(native_identity)

    # A missing configured directory beneath a loose parent remains the
    # existing protection refusal, including when no identity can be opened.
    loose_parent = root / "loose-parent"
    loose_parent.mkdir(mode=0o755)
    loose_config = root / "loose-owner.json"
    loose_config.write_text(json.dumps({"origin": "http://127.0.0.1:1/",
        "state_dir": str(loose_parent / "absent"), "allow_loopback_http": True}))
    unsafe = call(root, "secure", "owner-operations", "loose-owner.json")
    assert unsafe.returncode != 0 and json.loads(unsafe.stderr)["code"] == "IDENTITY_CHANGED"
    assert not (loose_parent / "absent").exists()

    # The new command must preserve strict private-source rejection, and no
    # output may include source PEM/seed bytes.
    for result in (wrong, before, imported, info, after, corrupt, unprotected, linked_identity, unsafe):
        assert "BEGIN PRIVATE KEY" not in result.stdout + result.stderr
        assert base64.b64encode(der).decode() not in result.stdout + result.stderr
    other_state = root / "other-state"
    other_state.mkdir(mode=0o700)
    other_config = root / "other-owner.json"
    other_config.write_text(json.dumps({"origin": "http://127.0.0.1:1/",
                                        "state_dir": str(other_state), "allow_loopback_http": True}))
    other_config.chmod(0o600)
    protected_pem.chmod(0o644)
    loose = call(root, "identity", "import-legacy-owner-pem", "other-owner.json", "source/owner.pem")
    assert loose.returncode != 0 and json.loads(loose.stderr)["code"] == "IDENTITY_STATE"
    assert not (other_state / "identity.state").exists()
    protected_pem.chmod(0o600)
    (source / "linked.pem").symlink_to(protected_pem)
    linked = call(root, "identity", "import-legacy-owner-pem", "other-owner.json", "source/linked.pem")
    assert linked.returncode != 0 and json.loads(linked.stderr)["code"] == "IDENTITY_STATE"
    assert not (other_state / "identity.state").exists()

    help_result = call(root, "help")
    assert help_result.returncode == 0
    assert "identity import-legacy-owner-pem OWNER_CONFIG_JSON_FILE PROTECTED_PEM_FILE" in json.loads(help_result.stdout)["usage"]
print("PASS Owner config identity path, next public command, strict source refusal")
