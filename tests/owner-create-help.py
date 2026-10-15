#!/usr/bin/env python3
"""Verify Owner-create command help is local and argument validation stays strict."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

cli = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="peerwork-owner-create-help-") as tmp:
    cwd = Path(tmp)
    env = dict(os.environ, HOME=str(cwd))
    for flag in ("--help", "-h"):
        result = subprocess.run([str(cli), "secure", "owner-create", flag], cwd=cwd,
                                env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stderr == "", (flag, result)
        payload = json.loads(result.stdout)
        assert payload["command"] == "owner-create"
        assert payload["usage"] == "secure owner-create CONFIG_JSON_FILE INPUT_JSON_FILE"
        assert set(payload["config_fields"]) == {
            "origin", "state_dir", "allow_loopback_http (optional, explicit opt-in)",
            "max_replay_artifact_bytes (optional)", "max_replay_commits (optional, default 102400)", "transport (optional: request_timeout_ms, additional_root_pem_files)"}
        assert set(payload["input_fields"]) == {
            "name", "visibility (PUBLIC or PRIVATE)", "structured (optional)",
            "keep_encrypted_json (optional)", "coordination_version (optional)",
            "name_utf16 (optional only for an unpaired-surrogate name; mutually exclusive with nonempty name)"}
    invalid = subprocess.run([str(cli), "secure", "owner-create"], cwd=cwd,
                             env=env, capture_output=True, text=True, timeout=10)
    assert invalid.returncode != 0 and invalid.stdout == ""
    assert json.loads(invalid.stderr)["code"] == "USAGE"
    assert not list(cwd.iterdir()), list(cwd.iterdir())
print("Owner-create help is local; invalid invocation remains rejected")
