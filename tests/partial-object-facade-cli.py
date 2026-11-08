"""Actual CLI allowlist/arity/dispatch checks; missing local source, no service."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

binary, output = map(Path, sys.argv[1:])
output.mkdir(mode=0o700)
state = output / "native"
state.mkdir(mode=0o700)
token = lambda byte: base64.urlsafe_b64encode(bytes([byte]) * 32).decode().rstrip("=")
def save(name, value):
    path = output / name
    path.write_text(json.dumps(value))
    os.chmod(path, 0o600)
    return str(path)
config = save("config.json", {"origin": "https://control.invalid", "state_dir": str(state),
    "allow_loopback_http": False, "max_replay_artifact_bytes": 67108864})
source = save("source.json", {"workspace_id": token(1), "expected_owner_actor_id": token(2),
    "expected_owner_key_id": token(3), "protected_ts_state_path": str(output / "missing.state"),
    "protected_owner_pkcs8_path": str(output / "missing.pem"),
    "protected_ts_intent_db_path": str(output / "missing.sqlite")})
options = save("options.json", {"instance_id": token(4), "entrypoint": "migrated_discussion",
    "manifest": {}, "grants": []})
material = save("material.json", {})
cases = [
    ("inspect", [config, source, token(5), options, material], "SOURCE_CHANGED"),
    ("attach", [config, source, token(5), "0" * 64, options, material], "SOURCE_CHANGED"),
    ("recover", [config, token(6), token(5)], "NOT_FOUND"),
    ("inspect-arity", [config, source], "USAGE"),
]
results = []
for name, args, expected in cases:
    verb = "inspect" if name == "inspect-arity" else name
    result = subprocess.run([str(binary), "secure", f"owner-object-stage-{verb}", *args],
        capture_output=True, check=False)
    for suffix, data in [("stdout", result.stdout), ("stderr", result.stderr)]:
        path = output / f"{name}.{suffix}"
        path.write_bytes(data)
        os.chmod(path, 0o600)
    assert result.returncode == 1
    error = json.loads(result.stderr)
    assert error["code"] == expected, (name, error)
    results.append({"case": name, "code": error["code"], "exit_code": result.returncode})
assert not (output / "missing.state").exists()
assert not (output / "missing.pem").exists()
assert not (output / "missing.sqlite").exists()
print(json.dumps({"passed": True, "scope": "local CLI dispatch only; no service or successful attach", "cases": results}))
