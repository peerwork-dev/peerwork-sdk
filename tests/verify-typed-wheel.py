"""Require the PEP 561 marker in a built Peerwork Python wheel."""

import sys
import zipfile


if len(sys.argv) != 2:
    raise SystemExit("usage: verify-typed-wheel.py WHEEL")
with zipfile.ZipFile(sys.argv[1]) as wheel:
    names = wheel.namelist()
    if names.count("peerwork/py.typed") != 1:
        raise SystemExit("wheel omits peerwork/py.typed")
    if "peerwork/__init__.py" not in names:
        raise SystemExit("wheel omits peerwork/__init__.py")
    if wheel.read("peerwork/py.typed") != b"":
        raise SystemExit("peerwork/py.typed must be an empty full-typing marker")
print("typed Python wheel marker present")
