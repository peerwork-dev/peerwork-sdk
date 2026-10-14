"""CLI direct BEGIN preflight, without protected source files or service calls."""
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
    input_file = root / "input.json"
    options = root / "options.json"
    material = root / "material.json"
    options.write_text('{"v":1}')
    material.write_text('{"v":1}')
    base = {
        "workspace_id": "w" * 43,
        "protected_ts_state_path": str(root / "missing-state"),
        "protected_ts_intent_db_path": str(root / "missing-db"),
        "protected_owner_pkcs8_path": str(root / "missing-pem"),
        "expected_owner_actor_id": "a" * 43,
        "expected_owner_key_id": "k" * 43,
    }
    selected = "c" * 43
    digest = "d" * 64
    def refuse(verb, value, *suffix):
        input_file.write_text(json.dumps(value))
        run = subprocess.run([str(binary), "secure", verb, str(config),
                              str(input_file), selected, *suffix],
                             text=True, capture_output=True, timeout=10)
        assert run.returncode != 0 and not run.stdout
        assert json.loads(run.stderr)["code"] == "INPUT_INVALID"
        assert not state.exists()
        assert "PRIVATE KEY" not in run.stderr and material.read_text() not in run.stderr
    refuse("owner-direct-begin-inspect", {**base,
        "selected_pending_package_stage_command_id": selected,
        "expected_ts_state_digest": digest}, str(options), str(material))
    refuse("owner-direct-begin-attach", {**base,
        "recover_pending_action": True}, digest, str(options), str(material))
    refuse("owner-direct-begin-attach", base, "", str(options), str(material))
    for family in ("owner-direct-packet", "owner-direct-completed"):
        refuse(family + "-inspect", {**base, "recover_pending_action": True}, str(options), str(material))
        refuse(family + "-attach", {**base, "expected_ts_state_digest": digest}, digest, str(options), str(material))
        refuse(family + "-attach", base, "", str(options), str(material))
    help_result = subprocess.run([str(binary), "help"], text=True,
                                 capture_output=True, timeout=10, check=True)
    usage = json.loads(help_result.stdout)["usage"]
    for verb in ("owner-direct-begin-inspect", "owner-direct-begin-attach",
                 "owner-direct-begin-recover", "owner-direct-packet-inspect",
                 "owner-direct-packet-attach", "owner-direct-packet-recover",
                 "owner-direct-completed-inspect", "owner-direct-completed-attach"):
        assert verb in usage
print("CLI direct packet aliases/completed typed preflight and help PASS")
