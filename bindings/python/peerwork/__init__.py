"""Experimental native Peerwork binding. No verified actions are exposed yet."""

import json
from ._peerwork_native import capabilities_json, version


def capabilities() -> dict:
    """Return the native core capability manifest."""
    return json.loads(capabilities_json())


__all__ = ["version", "capabilities"]
