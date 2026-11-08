"""Actual CLI help, route/arity and typed-input refusal; no service or enrollment."""
import json
import os
from pathlib import Path
import subprocess
import sys

binary, output = map(Path, sys.argv[1:])
output.mkdir(mode=0o700)
os.umask(0o077)
config = output / "invalid-config.json"
config.write_text("{}")
results = []
for verb, args in [
    ("owner-coordination-enable", [str(config), "w" * 43, str(output / "unused-input.json")]),
    ("owner-coordination-resume", [str(config), "w" * 43, "b" * 43]),
    ("owner-coordination-operations", [str(config), "w" * 43]),
]:
    help_result = subprocess.run([str(binary), "secure", verb, "--help"], capture_output=True)
    assert help_result.returncode == 0, help_result.stderr
    help_value = json.loads(help_result.stdout)
    assert help_value["command"] == verb and "WORKSPACE_ID" in help_value["usage"]
    assert help_value["input_example"] == {"version":2,"participants":[]}
    (output / f"{verb}.help.json").write_bytes(help_result.stdout)
    for label, arguments, code in [("route", args, "CONFIG_INVALID"), ("arity", [], "USAGE")]:
        result = subprocess.run([str(binary), "secure", verb, *arguments], capture_output=True)
        for suffix, data in [("stdout",result.stdout), ("stderr",result.stderr)]:
            (output / f"{verb}.{label}.{suffix}").write_bytes(data)
        assert result.returncode == 1
        error = json.loads(result.stderr)
        assert error["code"] == code, (verb, label, error)
        results.append({"verb":verb,"case":label,"code":code})

native = output / "native"
native.mkdir(mode=0o700)
valid = output / "config.json"
valid.write_text(json.dumps({"origin":"https://control.invalid","state_dir":str(native),
    "allow_loopback_http":False,"max_replay_artifact_bytes":67108864}))
unknown = output / "unknown-input.json"
unknown.write_text('{"material":{}}')
result = subprocess.run([str(binary), "secure", "owner-coordination-enable", str(valid),
    "w" * 43, str(unknown)], capture_output=True)
assert result.returncode == 1 and json.loads(result.stderr)["code"] == "INPUT_INVALID"
(output / "unknown-input.stderr").write_bytes(result.stderr)
assert list(native.iterdir()) == [], "typed refusal must not create protected native state"
print(json.dumps({"passed":True,"scope":"CLI help/dispatch/typed preflight only; no service", "cases":results}))
