#!/usr/bin/env python3
"""No-model restricted-child smoke for config-aware legacy Owner import.

All command output is retained mode 0600 under the supplied fresh test root;
the console report contains only result classes, hashes, and booleans.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


if len(sys.argv) != 4:
    raise SystemExit("usage: smoke.py FRESH_TEST_ROOT PEERWORK_CLI CODEX_CLI")
root = Path(sys.argv[1]).absolute()
cli = str(Path(sys.argv[2]).resolve())
codex = str(Path(sys.argv[3]).resolve())
if root.exists():
    raise SystemExit("test root must be new")
root.mkdir(mode=0o700, parents=True)
root.chmod(0o700)

source_pem = Path("/root/workdir/message/.test-data/agent-trial-current-3605-20261014-three/observer/identity-import-probe1/precreated-parent/owner-private.pem")
if not source_pem.is_file():
    raise SystemExit("selected protected test PEM is unavailable")
pem = root / "legacy-owner.pem"
shutil.copyfile(source_pem, pem)
pem.chmod(0o600)

settings = [
    'approval_policy="never"',
    'default_permissions="trial"',
    'permissions.trial.extends=":workspace"',
    'permissions.trial.network.enabled=true',
    'permissions.trial.network.domains={"127.0.0.1"="allow"}',
    'permissions.trial.network.allow_local_binding=false',
    'permissions.trial.network.allow_upstream_proxy=false',
    'features.network_proxy.enabled=true',
    'features.network_proxy.domains={"127.0.0.1"="allow"}',
    'features.network_proxy.allow_local_binding=false',
    'features.network_proxy.allow_upstream_proxy=false',
    'features.network_proxy.enable_socks5=false',
    'features.network_proxy.enable_socks5_udp=false',
    'web_search="disabled"',
    'tools.web_search=false',
    'apps._default.enabled=false',
    'features.multi_agent=false',
    'mcp_servers={}',
]
env = os.environ.copy()
env.pop("PEERWORK_HTTP_PROXY", None)


def restricted(args: list[str], label: str) -> dict:
    argv = [codex, "sandbox", "-P", "trial"]
    for setting in settings:
        argv.extend(("-c", setting))
    argv.extend(("-C", str(root), "--", cli, *args))
    result = subprocess.run(argv, cwd=root, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=False)
    (root / f"{label}.stdout").write_bytes(result.stdout)
    (root / f"{label}.stderr").write_bytes(result.stderr)
    for path in (root / f"{label}.stdout", root / f"{label}.stderr"):
        path.chmod(0o600)
    parsed = None
    for output in (result.stdout, result.stderr):
        try:
            parsed = json.loads(output)
            break
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return {
        "exit": result.returncode,
        "code": parsed.get("code") if isinstance(parsed, dict) else None,
        "value": parsed if isinstance(parsed, dict) and result.returncode == 0 else None,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_length": len(result.stderr),
    }


def write_config(name: str, state_dir: Path) -> Path:
    path = root / name
    path.write_text(json.dumps({
        "origin": "http://127.0.0.1:1/",
        "state_dir": str(state_dir),
        "allow_loopback_http": True,
        "max_replay_artifact_bytes": 67108864,
    }, separators=(",", ":")))
    path.chmod(0o600)
    return path


state = root / "native-state"
config = write_config("owner-config.json", state)
imported = restricted(["identity", "import-legacy-owner-pem", str(config), str(pem)], "owner-import")
info = restricted(["identity", "info", str(state / "identity.state")], "owner-info")
identity_digest_before = hashlib.sha256((state / "identity.state").read_bytes()).hexdigest() if (state / "identity.state").is_file() else None
reimport = restricted(["identity", "import-legacy-owner-pem", str(config), str(pem)], "owner-reimport")

generic_parent = root / "generic-absent"
generic = restricted(["identity", "import-legacy-pem", str(generic_parent / "identity.state"), str(pem)], "generic-import")
generic_info = restricted(["identity", "info", str(generic_parent / "identity.state")], "generic-info")

unsafe_parent = root / "unsafe-parent"
unsafe_parent.mkdir(mode=0o755)
unsafe_parent.chmod(0o755)
unsafe_state = unsafe_parent / "native-state"
unsafe_config = write_config("unsafe-owner-config.json", unsafe_state)
unsafe = restricted(["identity", "import-legacy-owner-pem", str(unsafe_config), str(pem)], "unsafe-parent-import")

symlink_target = root / "symlink-target"
symlink_target.mkdir(mode=0o700)
symlink_state = root / "state-alias"
symlink_state.symlink_to(symlink_target, target_is_directory=True)
symlink_config = write_config("symlink-owner-config.json", symlink_state)
symlink = restricted(["identity", "import-legacy-owner-pem", str(symlink_config), str(pem)], "symlink-import")

identity_digest_after = hashlib.sha256((state / "identity.state").read_bytes()).hexdigest() if (state / "identity.state").is_file() else None
same_public_ids = bool(
    isinstance(imported.get("value"), dict)
    and isinstance(info.get("value"), dict)
    and isinstance(imported["value"].get("actor_id"), str)
    and bool(imported["value"].get("actor_id"))
    and isinstance(imported["value"].get("key_id"), str)
    and bool(imported["value"].get("key_id"))
    and imported["value"].get("actor_id") == info["value"].get("actor_id")
    and imported["value"].get("key_id") == info["value"].get("key_id")
)
summary = {
    "cli_sha256": hashlib.sha256(Path(cli).read_bytes()).hexdigest(),
    "restricted_policy": "trial; 127.0.0.1 only; upstream/SOCKS/web/apps/MCP/multiagent disabled; PEERWORK_HTTP_PROXY absent",
    "config_import": {"exit": imported["exit"], "state_dir_created": state.is_dir(), "identity_file_created": (state / "identity.state").is_file()},
    "identity_info": {"exit": info["exit"], "same_public_ids": same_public_ids},
    "reimport": {"exit": reimport["exit"], "error_code": reimport["code"], "identity_unchanged": identity_digest_before == identity_digest_after},
    "generic_absent_parent": {"import_exit": generic["exit"], "info_exit": generic_info["exit"], "parent_still_absent": not generic_parent.exists()},
    "unsafe_existing_parent": {"exit": unsafe["exit"], "error_code": unsafe["code"], "leaf_not_created": not unsafe_state.exists()},
    "symlink_leaf": {"exit": symlink["exit"], "error_code": symlink["code"], "target_identity_absent": not (symlink_target / "identity.state").exists()},
    "outputs": {name: {"stdout_sha256": item["stdout_sha256"], "stderr_sha256": item["stderr_sha256"], "stderr_length": item["stderr_length"]}
                for name, item in [("owner_import", imported), ("owner_info", info), ("owner_reimport", reimport),
                                   ("generic_import", generic), ("generic_info", generic_info),
                                   ("unsafe_parent", unsafe), ("symlink", symlink)]},
}
assert imported["exit"] == 0 and state.is_dir() and (state / "identity.state").is_file()
assert info["exit"] == 0 and same_public_ids
assert reimport["exit"] != 0 and reimport["code"] == "IDENTITY_STATE"
assert identity_digest_before == identity_digest_after
assert generic["exit"] != 0 and generic_info["exit"] != 0 and not generic_parent.exists()
assert unsafe["exit"] != 0 and unsafe["code"] == "IDENTITY_STATE" and not unsafe_state.exists()
assert symlink["exit"] != 0 and symlink["code"] == "IDENTITY_STATE"
assert not (symlink_target / "identity.state").exists()
summary_path = root / "summary.json"
summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
summary_path.chmod(0o600)
print(json.dumps(summary, sort_keys=True))
