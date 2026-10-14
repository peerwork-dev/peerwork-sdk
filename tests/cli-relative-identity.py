#!/usr/bin/env python3
"""Focused CLI identity path and protected-source regression (Unix)."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile


binary = Path(sys.argv[1]).resolve()
assert binary.is_file()
help_result = subprocess.run([str(binary), "help"], capture_output=True, text=True, check=False)
assert help_result.returncode == 0
usage = json.loads(help_result.stdout)["usage"]
assert "identity info IDENTITY_STATE_FILE" in usage
assert "identity import-legacy-pem IDENTITY_STATE_FILE PROTECTED_PEM_FILE" in usage


def call(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary), "identity", *args], cwd=root,
                          capture_output=True, text=True, check=False)


def protected_dir(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


# A fixed test-only Ed25519 seed, encoded as RFC 8410 PKCS#8. It is not a
# production key; the CLI must never echo even these test PEM bytes.
der = bytes.fromhex("302e020100300506032b657004220420") + bytes(range(1, 33))
pem = ("-----BEGIN PRIVATE KEY-----\n" +
       base64.b64encode(der).decode() +
       "\n-----END PRIVATE KEY-----\n")

with tempfile.TemporaryDirectory(prefix="peerwork-cli-identity-") as temporary:
    root = Path(temporary).resolve()
    root.chmod(0o700)
    source = root / "source"
    state = root / "state"
    protected_dir(source)
    protected_dir(state)
    pem_file = source / "owner.pem"
    pem_file.write_text(pem)
    pem_file.chmod(0o600)

    imported = call(root, "import-legacy-pem", "./state/owner.identity", "./source/owner.pem")
    assert imported.returncode == 0, imported.stderr
    imported_info = json.loads(imported.stdout)
    assert set(imported_info) == {"actor_id", "key_id"}
    assert len(imported_info["actor_id"]) == len(imported_info["key_id"]) == 43
    reopened = call(root, "info", "./state/owner.identity")
    assert reopened.returncode == 0 and json.loads(reopened.stdout) == imported_info
    assert (state / "owner.identity").is_file()

    created = call(root, "create", "state/new.identity")
    assert created.returncode == 0
    assert json.loads(call(root, "info", "state/new.identity").stdout) == json.loads(created.stdout)

    for output in (imported.stdout, imported.stderr, reopened.stdout, reopened.stderr,
                   created.stdout, created.stderr):
        assert "BEGIN PRIVATE KEY" not in output
        assert base64.b64encode(der).decode() not in output
        assert '"seed"' not in output

    # Resolving a relative path must not turn a loose source or symlink into
    # accepted private input. The destination must remain absent.
    pem_file.chmod(0o644)
    loose = call(root, "import-legacy-pem", "state/loose.identity", "source/owner.pem")
    assert loose.returncode != 0 and json.loads(loose.stderr)["code"] == "IDENTITY_STATE"
    assert not (state / "loose.identity").exists()
    pem_file.chmod(0o600)

    (source / "link.pem").symlink_to(pem_file)
    linked = call(root, "import-legacy-pem", "state/link.identity", "source/link.pem")
    assert linked.returncode != 0 and json.loads(linked.stderr)["code"] == "IDENTITY_STATE"
    assert not (state / "link.identity").exists()

    source.chmod(0o755)
    loose_parent = call(root, "import-legacy-pem", "state/parent.identity", "source/owner.pem")
    assert loose_parent.returncode != 0 and json.loads(loose_parent.stderr)["code"] == "IDENTITY_STATE"
    assert not (state / "parent.identity").exists()

    source.chmod(0o700)
    dotdot = call(root, "import-legacy-pem", "state/dotdot.identity", "source/../source/owner.pem")
    assert dotdot.returncode != 0 and json.loads(dotdot.stderr)["code"] == "IDENTITY_STATE"
    assert not (state / "dotdot.identity").exists()

    for result in (loose, linked, loose_parent, dotdot):
        assert "BEGIN PRIVATE KEY" not in result.stdout + result.stderr
        assert base64.b64encode(der).decode() not in result.stdout + result.stderr
        assert '"seed"' not in result.stdout + result.stderr

print("PASS relative protected identity import/create/info and strict source refusals")
