"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
from pathlib import Path
from typing import Literal, TypedDict, cast
from ._peerwork_native import (
    KernelCancelHandle,
    capabilities_json,
    identity_create_json,
    identity_open_json,
    identity_import_seed_json,
    identity_import_pkcs8_pem_json,
    kernel_json,
    secure_read_json,
    secure_read_profile_json,
    secure_public_action_json,
    secure_public_install_json,
    secure_recipient_enrollment_json,
    secure_identity_directory_json,
    secure_public_admission_json,
    secure_public_decision_json,
    version,
)


class CapabilityManifest(TypedDict):
    version: str
    status: str
    wire_canonicalization: bool
    signed_artifact_verification: bool
    receipt_verification: bool
    verified_public_workspace_reads: bool
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


class VerifiedSecureWorkspace(TypedDict):
    origin: str
    workspace_id: str
    sequence: int
    head: str | None
    policy_hash: str
    structure_status: Literal["UNSTRUCTURED", "ACTIVE"]
    objects: list[object]
    operations: list[object]
    recoveries: list[object]


class SecureReadError(RuntimeError):
    """A typed refusal from verified secure journal reading."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SecureActionReceipt(TypedDict):
    command_id: str
    commit_hash: str
    sequence: int
    actor_id: str
    instance_id: str
    action_id: str
    effects: list[object]


class SecureActionPending(TypedDict):
    status: Literal["PENDING"]
    command_id: str
    workspace_id: str
    action_id: str
    sequence: None
    commit_hash: None
    receipt: None


class SecureActionAccepted(TypedDict):
    status: Literal["ACCEPTED"]
    command_id: str
    workspace_id: str
    action_id: str
    sequence: int
    commit_hash: str
    receipt: SecureActionReceipt


SecureActionResult = SecureActionPending | SecureActionAccepted


class PendingSecureAction(TypedDict):
    """Redacted local intent for recovering an unreturned command ID."""

    command_id: str
    actor_id: str
    origin: str
    workspace_id: str
    action_id: str
    request_sha256: str
    commit_hash: str


class SecureActionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


class SecureSnapshotClient:
    """Read an explicitly pinned protected snapshot with advanced path control.

    The paths hold protected discovery, exact pages, and key lifecycle state.
    The replay artifact budget is for retained signed wires; it is not a cap on
    the decoded result graph. Pending or seeding histories refuse verified read.
    """

    def __init__(self, origin: str, kernel_journal_path: str, read_state_path: str,
                 lifecycle_path: str, identity_path: str, workspace_id: str,
                 authority: str, owner_actor_id: str, owner_key_id: str, *,
                 required_features: tuple[str, ...] = (),
                 allow_loopback_http: bool = False,
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024):
        if isinstance(max_replay_artifact_bytes, bool) or not isinstance(max_replay_artifact_bytes, int) or max_replay_artifact_bytes <= 0 or max_replay_artifact_bytes > 2**64 - 1:
            raise ValueError("max_replay_artifact_bytes must be a positive u64")
        self._config = {
            "origin": origin,
            "kernel_journal_path": kernel_journal_path,
            "read_state_path": read_state_path,
            "lifecycle_path": lifecycle_path,
            "identity_path": identity_path,
            "workspace_id": workspace_id,
            "authority": authority,
            "owner_actor_id": owner_actor_id,
            "owner_key_id": owner_key_id,
            "required_features": list(required_features),
            "allow_loopback_http": allow_loopback_http,
            "max_replay_artifact_bytes": max_replay_artifact_bytes,
        }

    def _read(self, cancel_handle: KernelCancelHandle | None = None) -> VerifiedSecureWorkspace:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_read_json(config_json, cancel_handle))
        if result["ok"] is not True:
            raise SecureReadError(result["code"], result["message"])
        return cast(VerifiedSecureWorkspace, result["value"])

    def read(self) -> VerifiedSecureWorkspace:
        return self._read()

    async def read_async(self) -> VerifiedSecureWorkspace:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._read, cancel_handle))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
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


__all__ = ["version", "capabilities", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async",
           "import_identity_seed_file", "import_identity_seed_file_async", "KernelClient",
           "CapabilityManifest", "IdentityInfo", "KernelInfo", "PendingIntent",
           "NamespaceClaimResult", "UploadBeginResult", "UploadChunkResult",
           "PackagePublishResult", "CatalogAcceptedResult", "AcceptedResult",
           "StatusNotFound", "StatusPending", "StatusAccepted", "KernelStatus",
           "TsMigrationReport"]
__all__ += ["import_legacy_identity_pem", "import_legacy_identity_pem_async"]
__all__ += ["SecureReadClient", "SecureReadError", "VerifiedSecureWorkspace"]


class SecureReadClient:
    """Read the latest verified PUBLIC workspace using a protected state directory.

    Owner actor/key pins are required on first contact. Reopens may omit them;
    the stored pins remain mandatory. A failed refresh keeps the last good
    checkpoint, and the call raises instead of returning stale data as latest.
    """

    def __init__(self, origin: str, state_dir: str, identity_path: str,
                 workspace_id: str, *, owner_actor_id: str | None = None,
                 owner_key_id: str | None = None, authority: str | None = None,
                 required_features: tuple[str, ...] = (),
                 allow_loopback_http: bool = False,
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024):
        if isinstance(max_replay_artifact_bytes, bool) or not isinstance(max_replay_artifact_bytes, int) or max_replay_artifact_bytes <= 0 or max_replay_artifact_bytes > 2**64 - 1:
            raise ValueError("max_replay_artifact_bytes must be a positive u64")
        if (owner_actor_id is None) != (owner_key_id is None):
            raise ValueError("owner actor and key pins must be provided together")
        self._config = {
            "origin": origin,
            "state_dir": state_dir,
            "identity_path": identity_path,
            "workspace_id": workspace_id,
            "owner_actor_id": owner_actor_id,
            "owner_key_id": owner_key_id,
            "authority": authority,
            "required_features": list(required_features),
            "allow_loopback_http": allow_loopback_http,
            "max_replay_artifact_bytes": max_replay_artifact_bytes,
        }

    def _read(self, cancel_handle: KernelCancelHandle | None = None) -> VerifiedSecureWorkspace:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_read_profile_json(config_json, cancel_handle))
        if result["ok"] is not True:
            raise SecureReadError(result["code"], result["message"])
        return cast(VerifiedSecureWorkspace, result["value"])

    def read(self) -> VerifiedSecureWorkspace:
        return self._read()

    async def read_async(self) -> VerifiedSecureWorkspace:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._read, cancel_handle))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
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


__all__ += ["SecureSnapshotClient"]


class SecurePublicActionClient(SecureReadClient):
    """Submit PUBLIC actions through the protected latest profile.

    An uncertain submit remains pending. Reconcile before retrying the saved
    command; a retry reuses its exact signed packet and allocation tokens.
    """

    def _action(self, operation: str, *, input_value: dict | None = None,
                command_id: str | None = None,
                cancel_handle: KernelCancelHandle | None = None) -> SecureActionResult | list[PendingSecureAction]:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        input_json = None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_public_action_json(operation, config_json, input_json, command_id, cancel_handle))
        if result["ok"] is not True:
            raise SecureActionError(result["code"], result["message"])
        value = result["value"]
        if operation == "pending":
            return cast(list[PendingSecureAction], value)
        receipt_json = value.pop("receipt_canonical_json")
        value["receipt"] = None if receipt_json is None else json.loads(receipt_json)
        return cast(SecureActionResult, value)

    def submit(self, action_id: str, instance_id: str, body: object, *,
               exact_input_refs: list[object] | None = None,
               allocations: list[object] | None = None,
               command_id: str | None = None,
               issued_at_ms: int | None = None) -> SecureActionResult:
        """Prepare once, save exact bytes, POST, and return PENDING."""
        value = {
            "action_id": action_id,
            "instance_id": instance_id,
            "body_json": json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "exact_input_refs_json": None if exact_input_refs is None else json.dumps(exact_input_refs, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "allocations_json": None if allocations is None else json.dumps(allocations, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "command_id": command_id,
            "issued_at_ms": issued_at_ms,
        }
        return cast(SecureActionResult, self._action("submit", input_value=value))

    def reconcile(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, self._action("reconcile", command_id=command_id))

    def retry_saved(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, self._action("retry", command_id=command_id))

    def pending(self) -> list[PendingSecureAction]:
        """List protected pending IDs locally, including IDs lost to cancellation."""
        return cast(list[PendingSecureAction], self._action("pending"))

    async def _action_async(self, operation: str, *, input_value: dict | None = None,
                            command_id: str | None = None) -> SecureActionResult | list[PendingSecureAction]:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._action, operation, input_value=input_value,
            command_id=command_id, cancel_handle=cancel_handle))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
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

    async def reconcile_async(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, await self._action_async("reconcile", command_id=command_id))

    async def submit_async(self, action_id: str, instance_id: str, body: object, *,
                           exact_input_refs: list[object] | None = None,
                           allocations: list[object] | None = None,
                           command_id: str | None = None,
                           issued_at_ms: int | None = None) -> SecureActionResult:
        value = {
            "action_id": action_id,
            "instance_id": instance_id,
            "body_json": json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "exact_input_refs_json": None if exact_input_refs is None else json.dumps(exact_input_refs, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "allocations_json": None if allocations is None else json.dumps(allocations, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "command_id": command_id,
            "issued_at_ms": issued_at_ms,
        }
        return cast(SecureActionResult, await self._action_async("submit", input_value=value))

    async def retry_saved_async(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, await self._action_async("retry", command_id=command_id))

    async def pending_async(self) -> list[PendingSecureAction]:
        """List protected pending IDs without a network read."""
        return cast(list[PendingSecureAction], await self._action_async("pending"))


__all__ += ["SecurePublicActionClient", "SecureActionResult", "SecureActionReceipt", "PendingSecureAction", "SecureActionError"]


class PublicInstallBeginResult(TypedDict):
    status: Literal["PENDING"]
    command_id: str
    workspace_id: str
    package_id: str
    package_version: str
    package_digest: str
    protocol_digest: str
    instance_id: str
    commit_hash: str


class PublicInstallProgress(TypedDict):
    status: Literal["PENDING", "ACCEPTED"]
    begin_command_id: str
    step_command_id: str
    step_action_id: Literal["secure.structure.begin", "secure.structure.page", "secure.structure.end"]
    workspace_id: str
    package_digest: str
    protocol_digest: str
    instance_id: str
    commit_hash: str


class PendingPublicInstall(TypedDict):
    begin_command_id: str
    pending_step_id: str
    pending_action_id: Literal["secure.structure.begin", "secure.structure.page", "secure.structure.end"]
    workspace_id: str
    package_id: str
    package_version: str
    package_digest: str
    protocol_digest: str
    instance_id: str


class PublicInstallError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SecurePublicPackageInstaller(SecureReadClient):
    """Begin and continue a PUBLIC direct install using protected local state.

    The selected closure and expected digests are explicit caller inputs. Local
    digest/compiler checks do not authenticate an external package publisher.
    """

    def _install(self, operation: str, *, input_value: dict | None = None,
                 begin_command_id: str | None = None,
                 cancel_handle: KernelCancelHandle | None = None) -> PublicInstallBeginResult | PublicInstallProgress | list[PendingPublicInstall]:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        input_json = None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_public_install_json(operation, config_json, input_json, begin_command_id, cancel_handle))
        if result["ok"] is not True:
            raise PublicInstallError(result["code"], result["message"])
        return cast(PublicInstallBeginResult | PublicInstallProgress | list[PendingPublicInstall], result["value"])

    def begin(self, closure_json: str, *, expected_package_id: str,
              expected_package_version: str, expected_package_digest: str,
              expected_protocol_digest: str, instance_id: str, entrypoint: str,
              grants_json: str = "[]", command_id: str | None = None,
              issued_at_ms: int | None = None) -> PublicInstallBeginResult:
        """Persist exact BEGIN before POST; the returned status remains PENDING."""
        value = dict(closure_json=closure_json, expected_package_id=expected_package_id,
                     expected_package_version=expected_package_version,
                     expected_package_digest=expected_package_digest,
                     expected_protocol_digest=expected_protocol_digest,
                     instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(PublicInstallBeginResult, self._install("begin", input_value=value))

    def continue_install(self, begin_command_id: str) -> PublicInstallProgress:
        """Advance or reconcile one protected install step against signed replay."""
        return cast(PublicInstallProgress, self._install("continue", begin_command_id=begin_command_id))

    def pending(self) -> list[PendingPublicInstall]:
        """Recover pending IDs from protected local state without network access."""
        return cast(list[PendingPublicInstall], self._install("pending"))

    async def _install_async(self, operation: str, *, input_value: dict | None = None,
                             begin_command_id: str | None = None) -> PublicInstallBeginResult | PublicInstallProgress | list[PendingPublicInstall]:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._install, operation, input_value=input_value,
            begin_command_id=begin_command_id, cancel_handle=cancel_handle))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel_handle.cancel()
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

    async def begin_async(self, closure_json: str, *, expected_package_id: str,
                          expected_package_version: str, expected_package_digest: str,
                          expected_protocol_digest: str, instance_id: str, entrypoint: str,
                          grants_json: str = "[]", command_id: str | None = None,
                          issued_at_ms: int | None = None) -> PublicInstallBeginResult:
        value = dict(closure_json=closure_json, expected_package_id=expected_package_id,
                     expected_package_version=expected_package_version,
                     expected_package_digest=expected_package_digest,
                     expected_protocol_digest=expected_protocol_digest,
                     instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(PublicInstallBeginResult, await self._install_async("begin", input_value=value))

    async def continue_install_async(self, begin_command_id: str) -> PublicInstallProgress:
        return cast(PublicInstallProgress, await self._install_async("continue", begin_command_id=begin_command_id))

    async def pending_async(self) -> list[PendingPublicInstall]:
        return cast(list[PendingPublicInstall], await self._install_async("pending"))


__all__ += ["SecurePublicPackageInstaller", "PublicInstallBeginResult", "PublicInstallProgress", "PendingPublicInstall", "PublicInstallError"]


class RecipientEnrollmentResult(TypedDict):
    status: Literal["LOCAL", "REGISTRATION_PENDING", "PUBLICATION_PENDING", "PUBLISHED", "PUBLISHED_LOCAL"]
    actor_id: str
    signing_key_id: str
    encryption_key_id: str
    certificate_digest: str
    registration_command_id: str | None
    directory_entry_hash: str | None


class RecipientKeyUpdateResult(TypedDict):
    status: Literal["PENDING", "PUBLISHED"]
    update_id: str
    mode: Literal["ROTATE", "RENEW"]
    previous_certificate_hash: str
    certificate_digest: str
    directory_version: int
    directory_head: str


class RecipientEnrollmentError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SecureRecipientEnrollmentClient:
    """Explicit protected recipient creation and directory publication.

    Publication does not grant workspace membership. Reopen and call publish
    again after an uncertain response; the native journal reuses saved bytes.
    """

    def __init__(self, origin: str, state_dir: str, *,
                 allow_loopback_http: bool = False):
        self._origin = origin
        self._state_dir = state_dir
        self._allow_loopback_http = allow_loopback_http

    def _enroll(self, operation: str,
                cancel_handle: KernelCancelHandle | None = None, *,
                mode: str | None = None, expected_certificate_hash: str | None = None,
                update_id: str | None = None) -> RecipientEnrollmentResult | RecipientKeyUpdateResult | list[RecipientKeyUpdateResult] | str | None:
        result = json.loads(secure_recipient_enrollment_json(
            operation, self._origin, self._state_dir,
            self._allow_loopback_http, cancel_handle, mode, expected_certificate_hash, update_id))
        if result["ok"] is not True:
            raise RecipientEnrollmentError(result["code"], result["message"])
        return cast(RecipientEnrollmentResult | RecipientKeyUpdateResult | list[RecipientKeyUpdateResult] | str | None, result["value"])

    def create_local(self) -> RecipientEnrollmentResult:
        """Create or reopen protected signing and recipient keys offline."""
        return cast(RecipientEnrollmentResult, self._enroll("create_local"))

    def publish(self) -> RecipientEnrollmentResult:
        """Register then publish the signed certificate; pending is not success."""
        return cast(RecipientEnrollmentResult, self._enroll("publish"))

    def pending(self) -> RecipientEnrollmentResult | None:
        """Inspect protected local progress without a network request."""
        return self._enroll("pending")

    def certificate_json(self) -> str:
        """Export the exact signed public certificate; publication is separate."""
        return cast(str, self._enroll("certificate"))

    def update_key(self, mode: Literal["ROTATE", "RENEW"], expected_certificate_hash: str,
                   *, update_id: str | None = None) -> RecipientKeyUpdateResult:
        """Save a successor key/entry before POST; use pending updates after lost replies."""
        return cast(RecipientKeyUpdateResult, self._enroll("update_key", mode=mode,
            expected_certificate_hash=expected_certificate_hash, update_id=update_id))

    def retry_key_update(self, update_id: str) -> RecipientKeyUpdateResult:
        return cast(RecipientKeyUpdateResult, self._enroll("retry_key_update", update_id=update_id))

    def pending_key_updates(self) -> list[RecipientKeyUpdateResult]:
        """Read protected local update IDs; listed rows are not publication proof."""
        return cast(list[RecipientKeyUpdateResult], self._enroll("pending_key_updates"))

    async def update_key_async(self, mode: Literal["ROTATE", "RENEW"],
                               expected_certificate_hash: str, *,
                               update_id: str | None = None) -> RecipientKeyUpdateResult:
        worker = asyncio.create_task(asyncio.to_thread(self.update_key, mode,
            expected_certificate_hash, update_id=update_id))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    break
            try:
                worker.result()
            except Exception:
                pass
            raise

    async def retry_key_update_async(self, update_id: str) -> RecipientKeyUpdateResult:
        worker = asyncio.create_task(asyncio.to_thread(self.retry_key_update, update_id))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    break
            try:
                worker.result()
            except Exception:
                pass
            raise

    async def publish_async(self) -> RecipientEnrollmentResult:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._enroll, "publish", cancel_handle))
        try:
            return cast(RecipientEnrollmentResult, await asyncio.shield(worker))
        except asyncio.CancelledError:
            cancel_handle.cancel()
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

__all__ += ["SecureRecipientEnrollmentClient", "RecipientEnrollmentResult", "RecipientKeyUpdateResult", "RecipientEnrollmentError"]


class VerifiedIdentityCertificate(TypedDict):
    actor_id: str
    signing_key_id: str
    directory_version: int
    directory_head: str
    certificate_json: str


class IdentityDirectoryError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SecureIdentityDirectoryClient:
    """Read a signed public certificate with explicit peer pins and protected continuity."""

    def __init__(self, origin: str, state_dir: str, identity_path: str | None = None, *,
                 allow_loopback_http: bool = False):
        if not origin or not state_dir:
            raise ValueError("origin and state directory are required")
        self._origin = origin
        self._state_dir = state_dir
        self._identity_path = identity_path or str(Path(state_dir) / "identity.state")
        self._allow_loopback_http = allow_loopback_http

    def _lookup(self, actor_id: str, signing_key_id: str,
                cancel_handle: KernelCancelHandle | None = None) -> VerifiedIdentityCertificate:
        if not actor_id or not signing_key_id:
            raise ValueError("explicit peer actor and signing key pins are required")
        result = json.loads(secure_identity_directory_json(
            self._origin, self._state_dir, self._identity_path,
            actor_id, signing_key_id, self._allow_loopback_http, cancel_handle))
        if result["ok"] is not True:
            raise IdentityDirectoryError(result["code"], result["message"])
        return cast(VerifiedIdentityCertificate, result["value"])

    def lookup(self, actor_id: str, signing_key_id: str) -> VerifiedIdentityCertificate:
        return self._lookup(actor_id, signing_key_id)

    async def lookup_async(self, actor_id: str, signing_key_id: str) -> VerifiedIdentityCertificate:
        handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._lookup, actor_id, signing_key_id, handle))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            handle.cancel()
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    handle.cancel()
                except Exception:
                    break
            try:
                worker.result()
            except Exception:
                pass
            raise


__all__ += ["SecureIdentityDirectoryClient", "VerifiedIdentityCertificate", "IdentityDirectoryError"]


class PublicAdmissionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class PublicOfferResult(TypedDict):
    status: Literal["PENDING"]
    invite_id: str
    workspace_id: str
    offer_hash: str


class PublicDeliveryResult(TypedDict):
    status: Literal["PENDING", "AUTHORIZED"]
    invite_id: str
    grant_id: str
    workspace_id: str
    grant_hash: str


class PublicDecisionResult(TypedDict):
    status: Literal["PENDING"]
    invite_id: str
    workspace_id: str
    decision_hash: str


class PublicReceiveResult(TypedDict):
    status: Literal["PENDING", "READY"]
    invite_id: str
    workspace_id: str
    receipt_hash: str


async def _run_admission_async(method, operation: str, **kwargs):
    cancel_handle = KernelCancelHandle()
    worker = asyncio.create_task(asyncio.to_thread(
        method, operation, cancel_handle=cancel_handle, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancel_handle.cancel()
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


class SecurePublicAdmissionClient(SecureReadClient):
    """Owner-signed PUBLIC offer and delivery from protected latest workspace state."""

    def _admission(self, operation: str, *, input_value: dict | None = None,
                   invite_id: str | None = None, grant_id: str | None = None,
                   cancel_handle: KernelCancelHandle | None = None) -> dict | list[dict]:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        input_json = None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_public_admission_json(operation, config_json, input_json, invite_id, grant_id, cancel_handle))
        if result["ok"] is not True:
            raise PublicAdmissionError(result["code"], result["message"])
        return cast(dict | list[dict], result["value"])

    @staticmethod
    def _offer_input(recipient_certificate_json: str, scopes_json: str, message: str,
                     invite_id: str | None, issued_at_ms: int | None,
                     expires_at_ms: int | None) -> dict:
        message_bytes = message.encode("utf-16-le", "surrogatepass")
        message_utf16 = [int.from_bytes(message_bytes[index:index + 2], "little")
                         for index in range(0, len(message_bytes), 2)]
        return dict(
            recipient_certificate_json=recipient_certificate_json, scopes_json=scopes_json,
            message="", message_utf16=message_utf16,
            invite_id=invite_id, issued_at_ms=issued_at_ms,
            expires_at_ms=expires_at_ms)

    def offer(self, recipient_certificate_json: str, scopes_json: str, *, message: str = "",
              invite_id: str | None = None, issued_at_ms: int | None = None,
              expires_at_ms: int | None = None) -> PublicOfferResult:
        return cast(PublicOfferResult, self._admission("offer", input_value=self._offer_input(
            recipient_certificate_json, scopes_json, message, invite_id, issued_at_ms, expires_at_ms)))

    async def offer_async(self, recipient_certificate_json: str, scopes_json: str, *, message: str = "",
                          invite_id: str | None = None, issued_at_ms: int | None = None,
                          expires_at_ms: int | None = None) -> PublicOfferResult:
        return cast(PublicOfferResult, await _run_admission_async(self._admission, "offer", input_value=self._offer_input(
            recipient_certificate_json, scopes_json, message, invite_id, issued_at_ms, expires_at_ms)))

    def retry_offer(self, invite_id: str) -> PublicOfferResult:
        return cast(PublicOfferResult, self._admission("retry_offer", invite_id=invite_id))

    async def retry_offer_async(self, invite_id: str) -> PublicOfferResult:
        return cast(PublicOfferResult, await _run_admission_async(self._admission, "retry_offer", invite_id=invite_id))

    def pending_offers(self) -> list[dict]:
        return cast(list[dict], self._admission("pending_offers"))

    def deliver(self, invite_id: str) -> PublicDeliveryResult:
        return cast(PublicDeliveryResult, self._admission("deliver", invite_id=invite_id))

    async def deliver_async(self, invite_id: str) -> PublicDeliveryResult:
        return cast(PublicDeliveryResult, await _run_admission_async(self._admission, "deliver", invite_id=invite_id))

    def retry_delivery(self, grant_id: str) -> PublicDeliveryResult:
        return cast(PublicDeliveryResult, self._admission("retry_delivery", grant_id=grant_id))

    async def retry_delivery_async(self, grant_id: str) -> PublicDeliveryResult:
        return cast(PublicDeliveryResult, await _run_admission_async(self._admission, "retry_delivery", grant_id=grant_id))

    def pending_deliveries(self) -> list[dict]:
        return cast(list[dict], self._admission("pending_deliveries"))


class SecurePublicDecisionClient:
    """Recipient consent and receipt with explicit immutable owner and authority pins."""

    def __init__(self, origin: str, state_dir: str, workspace_id: str,
                 owner_actor_id: str, owner_key_id: str, authority: str | None = None, *,
                 allow_loopback_http: bool = False,
                 required_features: tuple[str, ...] = (),
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024):
        if not all((origin, state_dir, workspace_id, owner_actor_id, owner_key_id)):
            raise ValueError("origin, state directory, workspace and owner pins are required")
        if authority is not None and not authority:
            raise ValueError("explicit authority must be nonempty")
        if isinstance(max_replay_artifact_bytes, bool) or not isinstance(max_replay_artifact_bytes, int) or max_replay_artifact_bytes <= 0 or max_replay_artifact_bytes > 2**64 - 1:
            raise ValueError("max_replay_artifact_bytes must be a positive u64")
        from pathlib import Path
        self._config = dict(origin=origin, state_dir=state_dir,
                            identity_path=str(Path(state_dir) / "identity.state"),
                            workspace_id=workspace_id, owner_actor_id=owner_actor_id,
                            owner_key_id=owner_key_id, authority=authority or "",
                            allow_loopback_http=allow_loopback_http,
                            required_features=list(required_features),
                            max_replay_artifact_bytes=max_replay_artifact_bytes)

    def _decision(self, operation: str, *, invite_id: str | None = None,
                  decision: str | None = None,
                  cancel_handle: KernelCancelHandle | None = None) -> dict | list[dict]:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_public_decision_json(operation, config_json, invite_id, decision, cancel_handle))
        if result["ok"] is not True:
            raise PublicAdmissionError(result["code"], result["message"])
        return cast(dict | list[dict], result["value"])

    def decide(self, invite_id: str, decision: Literal["ACCEPT", "DECLINE"]) -> PublicDecisionResult:
        return cast(PublicDecisionResult, self._decision("decide", invite_id=invite_id, decision=decision))

    async def decide_async(self, invite_id: str, decision: Literal["ACCEPT", "DECLINE"]) -> PublicDecisionResult:
        return cast(PublicDecisionResult, await _run_admission_async(self._decision, "decide", invite_id=invite_id, decision=decision))

    def retry_decision(self, invite_id: str) -> PublicDecisionResult:
        return cast(PublicDecisionResult, self._decision("retry_decision", invite_id=invite_id))

    async def retry_decision_async(self, invite_id: str) -> PublicDecisionResult:
        return cast(PublicDecisionResult, await _run_admission_async(self._decision, "retry_decision", invite_id=invite_id))

    def pending_decisions(self) -> list[dict]:
        return cast(list[dict], self._decision("pending_decisions"))

    def receive(self, invite_id: str) -> PublicReceiveResult:
        return cast(PublicReceiveResult, self._decision("receive", invite_id=invite_id))

    async def receive_async(self, invite_id: str) -> PublicReceiveResult:
        return cast(PublicReceiveResult, await _run_admission_async(self._decision, "receive", invite_id=invite_id))

    def retry_receive(self, invite_id: str) -> PublicReceiveResult:
        return cast(PublicReceiveResult, self._decision("retry_receive", invite_id=invite_id))

    async def retry_receive_async(self, invite_id: str) -> PublicReceiveResult:
        return cast(PublicReceiveResult, await _run_admission_async(self._decision, "retry_receive", invite_id=invite_id))

    def pending_receipts(self) -> list[dict]:
        return cast(list[dict], self._decision("pending_receipts"))


__all__ += ["SecurePublicAdmissionClient", "SecurePublicDecisionClient", "PublicAdmissionError",
            "PublicOfferResult", "PublicDeliveryResult", "PublicDecisionResult", "PublicReceiveResult"]
