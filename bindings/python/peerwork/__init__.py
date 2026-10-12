"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
from ._peerwork_native import (
    KernelCancelHandle,
    capabilities_json,
    identity_create_json,
    identity_open_json,
    kernel_json,
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


class KernelClient:
    """Experimental verified kernel command client with durable exact retry.

    Paths identify protected local state. The origin is an explicit trust input;
    loopback HTTP requires an explicit opt-in for local tests.
    """

    def __init__(self, origin: str, journal_path: str, identity_path: str,
                 *, required_features: tuple[str, ...] = (),
                 allow_loopback_http: bool = False,
                 authority: str | None = None):
        self.origin = origin
        self.journal_path = journal_path
        self.identity_path = identity_path
        self.required_features = tuple(required_features)
        self.allow_loopback_http = allow_loopback_http
        self.authority = authority

    def _call(self, operation: str, *, command: dict | None = None,
              command_id: str | None = None,
              upload_chunk: bytes | None = None,
              cancel_handle: KernelCancelHandle | None = None) -> dict | list:
        command_json = None if command is None else json.dumps(
            command, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
        return json.loads(kernel_json(
            operation, self.origin, self.journal_path, self.identity_path,
            list(self.required_features), self.allow_loopback_http,
            self.authority, command_json, command_id, upload_chunk, cancel_handle,
        ))

    async def _call_async(self, operation: str, *, command: dict | None = None,
                          command_id: str | None = None,
                          upload_chunk: bytes | None = None) -> dict | list:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._call, operation, command=command, command_id=command_id,
            upload_chunk=upload_chunk, cancel_handle=cancel_handle,
        ))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
            try:
                await asyncio.shield(worker)
            except Exception:
                pass
            raise

    def open(self) -> dict:
        return self._call("open")

    def prepare(self, command: dict, *, upload_chunk: bytes | None = None) -> dict:
        """Sign and save a fully specified kernel command; perform no POST."""
        if upload_chunk is not None and not isinstance(upload_chunk, bytes):
            raise TypeError("upload_chunk must be bytes")
        return self._call("prepare", command=command, upload_chunk=upload_chunk)

    def pending(self) -> list[dict]:
        return self._call("pending")

    def status(self, command_id: str) -> dict:
        return self._call("status", command_id=command_id)

    def submit_saved(self, command_id: str) -> dict:
        """POST saved bytes and require a verified, command-bound receipt."""
        return self._call("submit_saved", command_id=command_id)

    async def open_async(self) -> dict:
        return await self._call_async("open")

    async def prepare_async(self, command: dict, *, upload_chunk: bytes | None = None) -> dict:
        return await self._call_async("prepare", command=command, upload_chunk=upload_chunk)

    async def pending_async(self) -> list[dict]:
        return await self._call_async("pending")

    async def status_async(self, command_id: str) -> dict:
        return await self._call_async("status", command_id=command_id)

    async def submit_saved_async(self, command_id: str) -> dict:
        return await self._call_async("submit_saved", command_id=command_id)


__all__ = ["version", "capabilities", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async", "KernelClient"]
