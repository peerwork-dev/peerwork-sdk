"""Experimental native Peerwork binding. No verified actions are exposed yet."""

import asyncio
import json
from ._peerwork_native import (
    capabilities_json,
    identity_create_json,
    identity_open_json,
    version,
)


def capabilities() -> dict:
    """Return the native core capability manifest."""
    return json.loads(capabilities_json())


def create_identity(path: str) -> dict[str, str]:
    """Explicitly create a protected local signing identity; no enrollment occurs."""
    return json.loads(identity_create_json(path))


def open_identity(path: str) -> dict[str, str]:
    """Read only the public IDs of an existing protected local identity."""
    return json.loads(identity_open_json(path))


async def create_identity_async(path: str) -> dict[str, str]:
    return await asyncio.to_thread(create_identity, path)


async def open_identity_async(path: str) -> dict[str, str]:
    return await asyncio.to_thread(open_identity, path)


__all__ = ["version", "capabilities", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async"]
