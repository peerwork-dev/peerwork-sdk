"""Check that an installed wheel exposes typed public signatures to mypy."""

import argparse
import subprocess
import tempfile
from pathlib import Path


def check(mypy: str, python: str, source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            mypy,
            "--strict",
            "--follow-imports=silent",
            "--no-incremental",
            "--python-executable",
            python,
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, help="Python from the fresh wheel install")
    parser.add_argument("--mypy", default="mypy", help="mypy executable")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="peerwork-installed-types-") as directory:
        root = Path(directory)
        positive = root / "positive.py"
        positive.write_text(
            "from peerwork import IdentityInfo, create_identity, open_identity\n"
            "created: IdentityInfo = create_identity('/tmp/peerwork-type-only')\n"
            "actor: str = created['actor_id']\n"
            "opened: IdentityInfo = open_identity('/tmp/peerwork-type-only')\n"
            "reveal_type(create_identity)\n",
            encoding="utf-8",
        )
        result = check(args.mypy, args.python, positive)
        if result.returncode != 0 or "Revealed type is" not in result.stdout or 'Revealed type is "Any"' in result.stdout:
            raise SystemExit(f"installed positive type check failed:\n{result.stdout}{result.stderr}")

        negative = root / "negative.py"
        negative.write_text("from peerwork import create_identity\ncreate_identity(123)\n", encoding="utf-8")
        result = check(args.mypy, args.python, negative)
        if (
            result.returncode == 0
            or 'Argument 1 to "create_identity"' not in result.stdout
            or 'incompatible type "int"' not in result.stdout
        ):
            raise SystemExit(f"installed wrong-argument type check did not fail as expected:\n{result.stdout}{result.stderr}")

    print("installed Peerwork signatures are typed and reject wrong arguments")


if __name__ == "__main__":
    main()
