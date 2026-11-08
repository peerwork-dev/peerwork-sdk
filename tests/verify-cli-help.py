"""Check machine-readable CLI help and preserve invalid-usage failure."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("cli", type=Path)
args = parser.parse_args()
cli = args.cli.resolve()

with tempfile.TemporaryDirectory(prefix="peerwork-cli-help-") as directory:
    home = Path(directory)
    env = dict(os.environ, HOME=str(home))

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(cli), *arguments], cwd=home, env=env,
                              capture_output=True, text=True, timeout=10)

    help_messages = []
    for alias in ("--help", "-h", "help"):
        result = run(alias)
        assert result.returncode == 0 and result.stderr == "", (alias, result)
        value = json.loads(result.stdout)
        assert value["status"] == "HELP" and "secure owner-prepare" in value["usage"]
        help_messages.append(value["usage"])
    assert len(set(help_messages)) == 1

    invalid = run()
    assert invalid.returncode != 0 and invalid.stdout == ""
    failure = json.loads(invalid.stderr)
    assert failure == {"code": "USAGE", "message": help_messages[0]}

    version = run("version")
    assert version.returncode == 0 and json.loads(version.stdout)["status"] == "experimental"
    assert list(home.iterdir()) == []

print("CLI help is structured, side-effect-free, and invalid usage still fails")
