"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
from ._peerwork_native import (
    KernelCancelHandle,
    capabilities_json,
    identity_create_json,
    identity_open_json,
    identity_import_seed_json,
    identity_import_pkcs8_pem_json,
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


def import_identity_seed_file(path: str, seed_file: str) -> dict[str, str]:
    """Import a protected local 32-byte Ed25519 seed for legacy recovery.

    The source file remains intact; keep it private and manage its lifecycle.
    """
    return json.loads(identity_import_seed_json(path, seed_file))


def import_legacy_identity_pem(path: str, pem_file: str) -> dict[str, str]:
    """Import a protected legacy Ed25519 PKCS#8 PEM identity file."""
    return json.loads(identity_import_pkcs8_pem_json(path, pem_file))


async def create_identity_async(path: str) -> dict[str, str]:
    return await asyncio.to_thread(create_identity, path)


async def open_identity_async(path: str) -> dict[str, str]:
    return await asyncio.to_thread(open_identity, path)


async def import_identity_seed_file_async(path: str, seed_file: str) -> dict[str, str]:
    return await asyncio.to_thread(import_identity_seed_file, path, seed_file)


async def import_legacy_identity_pem_async(path: str, pem_file: str) -> dict[str, str]:
    return await asyncio.to_thread(import_legacy_identity_pem, path, pem_file)


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
              cancel_handle: KernelCancelHandle | None = None,
              migration_source: str | None = None,
              migration_backup: str | None = None,
              trusted_signer_key_ids: list[str] | None = None) -> dict | list:
        command_json = None if command is None else json.dumps(
            command, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
        return json.loads(kernel_json(
            operation, self.origin, self.journal_path, self.identity_path,
            list(self.required_features), self.allow_loopback_http,
            self.authority, command_json, command_id, upload_chunk, cancel_handle,
            migration_source, migration_backup, trusted_signer_key_ids,
        ))

    async def _call_async(self, operation: str, *, command: dict | None = None,
                          command_id: str | None = None,
                          upload_chunk: bytes | None = None,
                          migration_source: str | None = None,
                          migration_backup: str | None = None,
                          trusted_signer_key_ids: list[str] | None = None) -> dict | list:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._call, operation, command=command, command_id=command_id,
            upload_chunk=upload_chunk, cancel_handle=cancel_handle,
            migration_source=migration_source, migration_backup=migration_backup,
            trusted_signer_key_ids=trusted_signer_key_ids,
        ))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
            # A caller may cancel the same task again while the native worker
            # drains. Keep ownership until it actually finishes.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    cancel_handle.cancel()
                except Exception:
                    break
            try:
                worker.result()
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

    def migrate_ts_store(self, source_path: str, backup_path: str,
                         trusted_signer_key_ids: list[str]) -> dict:
        """Import a quiesced TS v1 store after checked backup and receipt proof.

        Signer IDs are public verification-key pins for every historical actor.
        The source stays untouched. Keep the backup for readback and recovery.
        """
        if not trusted_signer_key_ids or not all(isinstance(k, str) for k in trusted_signer_key_ids):
            raise ValueError("trusted_signer_key_ids must contain public key IDs")
        return self._call("migrate_ts_store", migration_source=source_path,
                          migration_backup=backup_path,
                          trusted_signer_key_ids=trusted_signer_key_ids)

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

    async def migrate_ts_store_async(self, source_path: str, backup_path: str,
                                     trusted_signer_key_ids: list[str]) -> dict:
        if not trusted_signer_key_ids or not all(isinstance(k, str) for k in trusted_signer_key_ids):
            raise ValueError("trusted_signer_key_ids must contain public key IDs")
        return await self._call_async("migrate_ts_store", migration_source=source_path,
                                      migration_backup=backup_path,
                                      trusted_signer_key_ids=trusted_signer_key_ids)


__all__ = ["version", "capabilities", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async",
           "import_identity_seed_file", "import_identity_seed_file_async", "KernelClient"]
__all__ += ["import_legacy_identity_pem", "import_legacy_identity_pem_async"]
