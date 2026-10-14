"""CLI multipart orphan preflight without source files or a live service."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


binary = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    state = root / "native-state"
    config = root / "config.json"
    config.write_text(json.dumps({"origin": "https://control.example/", "state_dir": str(state)}))
    material = root / "material.json"
    material.write_text('{"v":1}')
    input_file = root / "input.json"
    base = {
        "workspace_id": "w" * 43,
        "protected_ts_state_path": str(root / "missing-state"),
        "protected_ts_intent_db_path": str(root / "missing-db"),
        "protected_owner_pkcs8_path": str(root / "missing-pem"),
        "expected_owner_actor_id": "a" * 43,
        "expected_owner_key_id": "k" * 43,
        "recover_pending_action": False,
        "kernel_pending_command_ids": [],
    }

    def refuse(verb, value, expected_code):
        input_file.write_text(json.dumps(value))
        run = subprocess.run([str(binary), "secure", verb, str(config), str(input_file),
                              str(material)], text=True, capture_output=True, timeout=10)
        assert run.returncode != 0, (verb, run.stdout)
        error = json.loads(run.stderr)
        assert error["code"] == expected_code, (verb, error)
        assert not state.exists(), "invalid selection created protected native state"

    refuse("owner-stage-multipart-orphan-inspect", {**base,
        "selected_orphan_package_stage_command_id": "c" * 43,
        "expected_ts_state_digest": "d" * 64}, "INPUT_INVALID")
    refuse("owner-stage-multipart-orphan-attach", {**base,
        "selected_orphan_package_stage_command_id": "c" * 43,
        "selected_pending_package_stage_command_id": "p" * 43,
        "expected_ts_state_digest": "d" * 64}, "INPUT_INVALID")
    refuse("owner-stage-multipart-orphan-attach", {**base,
        "selected_orphan_package_stage_command_id": "c" * 43}, "INPUT_INVALID")

    help_result = subprocess.run([str(binary), "help"], text=True, capture_output=True,
                                 timeout=10, check=True)
    assert "owner-stage-multipart-orphan-inspect|owner-stage-multipart-orphan-attach" in json.loads(help_result.stdout)["usage"]
print("CLI orphan multipart facade: typed preflight and help PASS")
