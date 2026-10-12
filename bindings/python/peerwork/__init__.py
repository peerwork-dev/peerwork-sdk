"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
from typing import Literal, TypedDict, cast
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


class CapabilityManifest(TypedDict):
    version: str
    status: str
    wire_canonicalization: bool
    signed_artifact_verification: bool
    receipt_verification: bool
    verified_workspace_reads: bool
    safe_actions: bool
    durable_recovery: bool


class IdentityInfo(TypedDict):
    actor_id: str
    key_id: str


class KernelInfo(IdentityInfo):
    origin: str


class PendingIntent(TypedDict):
    command_id: str
    intent_digest: str
    created_at_ms: int


class NamespaceClaimResult(TypedDict):
    kind: Literal["namespace_claim"]
    namespace: str


class UploadBeginResult(TypedDict):
    kind: Literal["upload_begin"]
    upload_id: str
    state: Literal["STAGING"]
    expires_at: int


class UploadChunkResult(TypedDict):
    kind: Literal["upload_chunk"]
    upload_id: str
    index: int
    received_bytes: int
    state: Literal["STAGING", "READY"]


class PackagePublishResult(TypedDict):
    kind: Literal["package_publish"]
    namespace: str
    package_id: str
    version: str
    bundle_digest: str
    published: int


CatalogAcceptedResult = (
    NamespaceClaimResult | UploadBeginResult | UploadChunkResult | PackagePublishResult
)


class AcceptedResult(TypedDict):
    command_id: str
    workspace_id: str | None
    protocol_digest: str | None
    instance_id: str | None
    event_sequence: int | None
    revision: int | None
    produced_record_ids: list[str]
    catalog: CatalogAcceptedResult | None


class StatusNotFound(TypedDict):
    state: Literal["NOT_FOUND"]


class StatusPending(TypedDict):
    state: Literal["PENDING"]


class StatusAccepted(TypedDict):
    state: Literal["ACCEPTED"]
    result: AcceptedResult


KernelStatus = StatusNotFound | StatusPending | StatusAccepted


class TsMigrationReport(TypedDict):
    pending_count: int
    accepted_count: int


def capabilities() -> CapabilityManifest:
    """Return the native core capability manifest."""
    return cast(CapabilityManifest, json.loads(capabilities_json()))


def create_identity(path: str) -> IdentityInfo:
    """Explicitly create a protected local signing identity; no enrollment occurs."""
    return cast(IdentityInfo, json.loads(identity_create_json(path)))


def open_identity(path: str) -> IdentityInfo:
    """Read only the public IDs of an existing protected local identity."""
    return cast(IdentityInfo, json.loads(identity_open_json(path)))


def import_identity_seed_file(path: str, seed_file: str) -> IdentityInfo:
    """Import a protected local 32-byte Ed25519 seed for legacy recovery.

    The source file remains intact; keep it private and manage its lifecycle.
    """
    return cast(IdentityInfo, json.loads(identity_import_seed_json(path, seed_file)))


def import_legacy_identity_pem(path: str, pem_file: str) -> IdentityInfo:
    """Import a protected legacy Ed25519 PKCS#8 PEM identity file."""
    return cast(IdentityInfo, json.loads(identity_import_pkcs8_pem_json(path, pem_file)))


async def create_identity_async(path: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(create_identity, path))


async def open_identity_async(path: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(open_identity, path))


async def import_identity_seed_file_async(path: str, seed_file: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(import_identity_seed_file, path, seed_file))


async def import_legacy_identity_pem_async(path: str, pem_file: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(import_legacy_identity_pem, path, pem_file))


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
              trusted_signer_key_ids: list[str] | None = None) -> object:
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
                          trusted_signer_key_ids: list[str] | None = None) -> object:
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

    def open(self) -> KernelInfo:
        return cast(KernelInfo, self._call("open"))

    def prepare(self, command: dict, *, upload_chunk: bytes | None = None) -> PendingIntent:
        """Sign and save a fully specified kernel command; perform no POST."""
        if upload_chunk is not None and not isinstance(upload_chunk, bytes):
            raise TypeError("upload_chunk must be bytes")
        return cast(PendingIntent, self._call("prepare", command=command, upload_chunk=upload_chunk))

    def pending(self) -> list[PendingIntent]:
        return cast(list[PendingIntent], self._call("pending"))

    def status(self, command_id: str) -> KernelStatus:
        return cast(KernelStatus, self._call("status", command_id=command_id))

    def submit_saved(self, command_id: str) -> AcceptedResult:
        """POST saved bytes and require a verified, command-bound receipt."""
        return cast(AcceptedResult, self._call("submit_saved", command_id=command_id))

    def migrate_ts_store(self, source_path: str, backup_path: str,
                         trusted_signer_key_ids: list[str]) -> TsMigrationReport:
        """Import a quiesced TS v1 store after checked backup and receipt proof.

        Signer IDs are public verification-key pins for every historical actor.
        The source stays untouched. Keep the backup for readback and recovery.
        """
        if not trusted_signer_key_ids or not all(isinstance(k, str) for k in trusted_signer_key_ids):
            raise ValueError("trusted_signer_key_ids must contain public key IDs")
        return cast(TsMigrationReport, self._call("migrate_ts_store", migration_source=source_path,
                                                   migration_backup=backup_path,
                                                   trusted_signer_key_ids=trusted_signer_key_ids))

    async def open_async(self) -> KernelInfo:
        return cast(KernelInfo, await self._call_async("open"))

    async def prepare_async(self, command: dict, *, upload_chunk: bytes | None = None) -> PendingIntent:
        return cast(PendingIntent, await self._call_async("prepare", command=command, upload_chunk=upload_chunk))

    async def pending_async(self) -> list[PendingIntent]:
        return cast(list[PendingIntent], await self._call_async("pending"))

    async def status_async(self, command_id: str) -> KernelStatus:
        return cast(KernelStatus, await self._call_async("status", command_id=command_id))

    async def submit_saved_async(self, command_id: str) -> AcceptedResult:
        return cast(AcceptedResult, await self._call_async("submit_saved", command_id=command_id))

    async def migrate_ts_store_async(self, source_path: str, backup_path: str,
                                     trusted_signer_key_ids: list[str]) -> TsMigrationReport:
        if not trusted_signer_key_ids or not all(isinstance(k, str) for k in trusted_signer_key_ids):
            raise ValueError("trusted_signer_key_ids must contain public key IDs")
        return cast(TsMigrationReport, await self._call_async("migrate_ts_store", migration_source=source_path,
                                                               migration_backup=backup_path,
                                                               trusted_signer_key_ids=trusted_signer_key_ids))


__all__ = ["version", "capabilities", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async",
           "import_identity_seed_file", "import_identity_seed_file_async", "KernelClient",
           "CapabilityManifest", "IdentityInfo", "KernelInfo", "PendingIntent",
           "NamespaceClaimResult", "UploadBeginResult", "UploadChunkResult",
           "PackagePublishResult", "CatalogAcceptedResult", "AcceptedResult",
           "StatusNotFound", "StatusPending", "StatusAccepted", "KernelStatus",
           "TsMigrationReport"]
__all__ += ["import_legacy_identity_pem", "import_legacy_identity_pem_async"]
