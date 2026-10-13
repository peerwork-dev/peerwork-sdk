#!/usr/bin/env python3
"""Exercise installed identity creation and reopen across Python, Node, and CLI.

The caller supplies an existing private absolute directory. This script never
reads identity files, creates an enrollment, or contacts a service.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


PYTHON_CALL = (
    "import json, peerwork, sys; "
    "print(json.dumps(getattr(peerwork, sys.argv[1])(sys.argv[2])))"
)
NODE_CALL = (
    "const path = require('node:path'); "
    "const sdk = require(path.join(process.argv[1], 'node_modules', '@peerwork', 'agent-sdk')); "
    "sdk[process.argv[2]](process.argv[3]).then(value => "
    "console.log(JSON.stringify(value))).catch(error => { "
    "console.error(error.code || error.message); process.exitCode = 1; });"
)
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def invoke(command: list[str], cwd: Path) -> dict[str, str]:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, timeout=30, check=False
    )
    if result.returncode != 0:
        raise AssertionError(
            f"installed identity command exited {result.returncode}: {command[0]} "
            f"{result.stderr.strip()[:400]}"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or set(value) != {"actor_id", "key_id"}:
        raise AssertionError(f"identity result exposed unexpected fields: {sorted(value)}")
    if not all(isinstance(item, str) and TOKEN.fullmatch(item) for item in value.values()):
        raise AssertionError("identity result contains invalid public IDs")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    for option in ("python", "node", "node-consumer", "cli", "state-dir"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    # Keep the venv interpreter pathname: resolving its symlink to the host
    # binary would discard pyvenv.cfg and silently test a different Python.
    python = Path(os.path.abspath(args.python))
    node = Path(os.path.abspath(args.node))
    consumer = Path(os.path.abspath(args.node_consumer))
    cli = Path(os.path.abspath(args.cli))
    if not all(path.exists() for path in (python, node, consumer, cli)):
        raise AssertionError("installed executable or Node consumer is missing")
    state_dir = Path(args.state_dir)
    if not state_dir.is_absolute() or not state_dir.is_dir():
        raise AssertionError("an existing absolute protected state directory is required")
    if " " not in str(state_dir) or not any(ord(char) > 127 for char in str(state_dir)):
        raise AssertionError("state directory must exercise spaces and non-ASCII path handling")

    def python_call(operation: str, path: Path) -> dict[str, str]:
        return invoke([str(python), "-I", "-c", PYTHON_CALL, operation, str(path)], state_dir.parent)

    def node_call(operation: str, path: Path) -> dict[str, str]:
        return invoke([str(node), "-e", NODE_CALL, str(consumer), operation, str(path)], state_dir.parent)

    def cli_call(operation: str, path: Path) -> dict[str, str]:
        return invoke([str(cli), "identity", operation, str(path)], state_dir.parent)

    paths = [state_dir / f"身份 {name} identity.state" for name in ("python", "node", "cli")]
    creators = [
        lambda path: python_call("create_identity", path),
        lambda path: node_call("createIdentity", path),
        lambda path: cli_call("create", path),
    ]
    for label, path, create in zip(("python", "node", "cli"), paths, creators):
        if path.exists():
            raise AssertionError(f"identity path is not fresh: {label}")
        created = create(path)
        for opened in (
            python_call("open_identity", path),
            node_call("openIdentity", path),
            cli_call("info", path),
        ):
            if opened != created:
                raise AssertionError(f"{label} public IDs changed across installed entrypoints")
        print(f"{label}: create and three public-ID reopens passed")


if __name__ == "__main__":
    main()
