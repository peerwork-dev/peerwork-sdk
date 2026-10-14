"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, NotRequired, TypeAlias, TypedDict, cast

JSONValue: TypeAlias = "None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]"

class _OmittedInstallOption:
    pass


_OMITTED_BINDINGS = _OmittedInstallOption()
_OMITTED_DISCLOSURE = _OmittedInstallOption()

from ._peerwork_native import (
    KernelCancelHandle,
    capabilities_json,
    identity_create_json,
    identity_open_json,
    identity_import_seed_json,
    identity_import_pkcs8_pem_json,
    identity_import_owner_pem_json,
    kernel_json,
    secure_read_json,
    secure_read_profile_json,
    secure_private_read_json,
    secure_public_action_json,
    secure_public_install_json,
    secure_owner_create_json,
    secure_owner_consumer_json,
    public_catalog_json,
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


class IdentityError(RuntimeError):
    """Identity operation failure with a stable machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def open_identity(path: str) -> IdentityInfo:
    """Read only the public IDs of an existing protected local identity."""
    try:
        return cast(IdentityInfo, json.loads(identity_open_json(path)))
    except RuntimeError as error:
        code, separator, message = str(error).partition(": ")
        if separator and code in {"IDENTITY_MISSING", "IDENTITY_STATE"}:
            raise IdentityError(code, message) from error
        raise


def import_identity_seed_file(path: str, seed_file: str) -> IdentityInfo:
    """Import a protected local 32-byte Ed25519 seed for legacy recovery.

    The source file remains intact; keep it private and manage its lifecycle.
    """
    return cast(IdentityInfo, json.loads(identity_import_seed_json(path, seed_file)))


def import_legacy_identity_pem(path: str, pem_file: str) -> IdentityInfo:
    """Import a protected legacy Ed25519 PKCS#8 PEM identity file."""
    return cast(IdentityInfo, json.loads(identity_import_pkcs8_pem_json(path, pem_file)))


def import_legacy_owner_identity(config_file: str, pem_file: str) -> IdentityInfo:
    """Import the selected legacy Owner PEM into identity.state from its Owner config."""
    return cast(IdentityInfo, json.loads(identity_import_owner_pem_json(config_file, pem_file)))


async def create_identity_async(path: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(create_identity, path))


async def open_identity_async(path: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(open_identity, path))


async def import_identity_seed_file_async(path: str, seed_file: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(import_identity_seed_file, path, seed_file))


async def import_legacy_identity_pem_async(path: str, pem_file: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(import_legacy_identity_pem, path, pem_file))


async def import_legacy_owner_identity_async(config_file: str, pem_file: str) -> IdentityInfo:
    return cast(IdentityInfo, await asyncio.to_thread(import_legacy_owner_identity, config_file, pem_file))


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


__all__ = ["version", "capabilities", "IdentityError", "create_identity", "open_identity",
           "create_identity_async", "open_identity_async",
           "import_identity_seed_file", "import_identity_seed_file_async", "KernelClient",
           "CapabilityManifest", "IdentityInfo", "KernelInfo", "PendingIntent",
           "NamespaceClaimResult", "UploadBeginResult", "UploadChunkResult",
           "PackagePublishResult", "CatalogAcceptedResult", "AcceptedResult",
           "StatusNotFound", "StatusPending", "StatusAccepted", "KernelStatus",
           "TsMigrationReport"]
__all__ += ["import_legacy_identity_pem", "import_legacy_identity_pem_async",
            "import_legacy_owner_identity", "import_legacy_owner_identity_async"]
__all__ += ["SecureReadClient", "SecureReadError", "VerifiedSecureWorkspace"]


class SecureReadClient:
    """Read the latest verified workspace using a protected state directory.

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

    def _activate_private(self, cancel_handle: KernelCancelHandle | None = None) -> VerifiedSecureWorkspace:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_private_read_json(config_json, cancel_handle))
        if result["ok"] is not True:
            raise SecureReadError(result["code"], result["message"])
        return cast(VerifiedSecureWorkspace, result["value"])

    def read_private(self) -> VerifiedSecureWorkspace:
        """Read verified PRIVATE state, recovering a protected direct grant when needed."""
        return self._activate_private()

    async def read_private_async(self) -> VerifiedSecureWorkspace:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._activate_private, cancel_handle))
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
              issued_at_ms: int | None = None,
              bindings: Mapping[str, JSONValue] | _OmittedInstallOption = _OMITTED_BINDINGS) -> PublicInstallBeginResult:
        """Persist exact BEGIN before POST; the returned status remains PENDING."""
        value = dict(closure_json=closure_json, expected_package_id=expected_package_id,
                     expected_package_version=expected_package_version,
                     expected_package_digest=expected_package_digest,
                     expected_protocol_digest=expected_protocol_digest,
                     instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        if bindings is not _OMITTED_BINDINGS:
            if not isinstance(bindings, Mapping):
                raise TypeError("bindings must be a JSON object")
            value["bindings_json"] = json.dumps(dict(bindings), ensure_ascii=True,
                allow_nan=False, separators=(",", ":"))
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
                          issued_at_ms: int | None = None,
                          bindings: Mapping[str, JSONValue] | _OmittedInstallOption = _OMITTED_BINDINGS) -> PublicInstallBeginResult:
        value = dict(closure_json=closure_json, expected_package_id=expected_package_id,
                     expected_package_version=expected_package_version,
                     expected_package_digest=expected_package_digest,
                     expected_protocol_digest=expected_protocol_digest,
                     instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        if bindings is not _OMITTED_BINDINGS:
            if not isinstance(bindings, Mapping):
                raise TypeError("bindings must be a JSON object")
            value["bindings_json"] = json.dumps(dict(bindings), ensure_ascii=True,
                allow_nan=False, separators=(",", ":"))
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

    def key_updates(self) -> list[RecipientKeyUpdateResult]:
        """Read protected local update history, including signed-reconciled published IDs."""
        return cast(list[RecipientKeyUpdateResult], self._enroll("key_updates"))

    async def update_key_async(self, mode: Literal["ROTATE", "RENEW"],
                               expected_certificate_hash: str, *,
                               update_id: str | None = None) -> RecipientKeyUpdateResult:
        handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._enroll, "update_key", handle,
            mode=mode, expected_certificate_hash=expected_certificate_hash, update_id=update_id))
        try:
            return cast(RecipientKeyUpdateResult, await asyncio.shield(worker))
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

    async def retry_key_update_async(self, update_id: str) -> RecipientKeyUpdateResult:
        handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._enroll, "retry_key_update", handle,
            update_id=update_id))
        try:
            return cast(RecipientKeyUpdateResult, await asyncio.shield(worker))
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


class OwnerWorkspaceResult(TypedDict):
    status: Literal["PENDING", "CREATED_LOCAL", "CREATED"]
    command_id: str
    workspace_id: str
    visibility: Literal["PUBLIC", "PRIVATE"]
    sequence: int | None
    head: str | None


class HistoricalOwnerAttachmentResult(TypedDict):
    attach_id: str
    workspace_id: str
    provenance: Literal["HISTORICAL_TS_OWNER"]
    status: Literal["PREPARED", "ATTACHED_RESTRICTED", "ATTACHED"]
    owner_actor_id: str
    owner_key_id: str
    sequence: int | None
    head: str | None
    selected_kernel_count: int
    retained_other_kernel_count: int
    pending_action_command_id: str | None
    pending_action_status: Literal["RETAINED_UNRESOLVED", "ACCEPTED"] | None
    pending_package_stage_command_id: str | None
    pending_package_stage_status: Literal["PENDING_UNRESOLVED", "PART_ACCEPTED_CONTINUATION_PENDING", "ACCEPTED"] | None
    pending_package_stage_id: str | None
    pending_direct_install_command_id: str | None
    pending_direct_install_instance_id: str | None
    pending_direct_install_status: Literal["PENDING_UNRESOLVED", "BEGIN_ACCEPTED_CONTINUATION_PENDING", "ACCEPTED"] | None
    orphan_package_stage_command_id: str | None
    orphan_package_stage_status: Literal["ORPHAN_NO_PACKET", "REPLAN_SELECTED_UNVERIFIED", "ORPHAN_REPLANNED"] | None
    orphan_replan_stage_id: str | None
    orphan_replan_command_id: str | None


class HistoricalDirectInstallPendingInventory(TypedDict):
    ts_state_digest: str
    command_id: str
    instance_id: str
    intent_hash: str
    original_commit_hash: str
    status: Literal["PENDING_UNRESOLVED", "APPLIED_IN_SIGNED_REPLAY"]


class HistoricalDirectInstallCompletedInventory(TypedDict):
    ts_state_digest: str
    instance_id: str
    intent_hash: str
    begin_command_id: str
    begin_commit_hash: str
    end_sequence: int
    protocol_digest: str
    status: Literal["COMPLETED_IN_SIGNED_REPLAY"]


class HistoricalPackageStagePendingInventory(TypedDict):
    ts_state_digest: str
    command_id: str
    source_id: str
    source_sha256: str
    source_sequence: int
    part_index: int
    part_count: int | None
    original_commit_hash: str | None
    status: Literal["PENDING_UNRESOLVED", "APPLIED_IN_SIGNED_REPLAY"]


class HistoricalPackageStageOrphanInventory(TypedDict):
    ts_state_digest: str
    command_id: str
    source_id: str
    source_sha256: str
    source_sequence: int
    part_index: int
    part_count: int | None
    status: Literal["ORPHAN_NO_PACKET", "APPLIED_IN_SIGNED_REPLAY"]


class HistoricalKernelCommandStatus(TypedDict):
    command_id: str
    intent_digest: str
    expires_at_ms: int
    status: Literal["PENDING", "RETAINED_UNRESOLVED", "EXPIRED_UNRESOLVED", "ACCEPTED"]
    last_http_status: int | None


class HistoricalKernelPendingInventory(TypedDict):
    intent_db_digest: str
    commands: list[HistoricalKernelCommandStatus]
    retained_other_pending_count: int
    retained_nonworkspace_pending_count: int


class OwnerFormatTransitionResult(TypedDict):
    command_id: str
    workspace_id: str
    transition: Literal["UPGRADE_WIRE_V3", "RAISE_PRIVATE_CEILING_TWO"]
    status: Literal["PENDING", "ACCEPTED"]
    sequence: int | None
    policy_hash: str | None


class OwnerWorkspaceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SecureOwnerWorkspaceClient:
    """Create and read workspaces from one protected Owner state directory.

    Preparation saves the exact generated IDs and signed request locally before
    any workspace POST. Recover a lost return ID with operations(), then resume.
    """

    def __init__(self, origin: str, state_dir: str, *, allow_loopback_http: bool = False,
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024):
        self._config = dict(origin=origin, state_dir=state_dir,
            allow_loopback_http=allow_loopback_http,
            max_replay_artifact_bytes=max_replay_artifact_bytes)

    def _owner(self, operation: str, *, input_value: dict | str | None = None,
               command_id: str | None = None, workspace_id: str | None = None,
               cancel_handle: KernelCancelHandle | None = None):
        result = json.loads(secure_owner_create_json(operation,
            json.dumps(self._config, ensure_ascii=True, separators=(",", ":")),
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, separators=(",", ":")),
            command_id, workspace_id, cancel_handle))
        if result["ok"] is not True:
            raise OwnerWorkspaceError(result["code"], result["message"])
        return result["value"]

    @staticmethod
    def _attachment_input(workspace_id: str, protected_ts_state_path: str,
                          protected_ts_intent_db_path: str,
                          protected_owner_pkcs8_path: str,
                          expected_owner_actor_id: str, expected_owner_key_id: str,
                          recover_pending_action: bool = False,
                          retain_pending_action_command_id: str | None = None,
                          kernel_pending_command_ids: list[str] | None = None,
                          expected_kernel_intent_db_digest: str | None = None,
                          selected_pending_package_stage_command_id: str | None = None,
                          selected_orphan_package_stage_command_id: str | None = None,
                          expected_ts_state_digest: str | None = None) -> dict:
        if type(recover_pending_action) is not bool:
            raise TypeError("recover_pending_action must be a bool")
        if retain_pending_action_command_id is not None:
            if not isinstance(retain_pending_action_command_id, str) or not retain_pending_action_command_id:
                raise TypeError("retain_pending_action_command_id must be a nonempty string")
            if not recover_pending_action:
                raise ValueError("retaining a pending Owner action requires recover_pending_action")
        ids = [] if kernel_pending_command_ids is None else kernel_pending_command_ids
        if not isinstance(ids, list) or any(not isinstance(item, str) or not item for item in ids):
            raise TypeError("kernel_pending_command_ids must be a list of nonempty strings")
        if ids and not expected_kernel_intent_db_digest:
            raise ValueError("selected kernel commands require the inspected intent DB digest")
        if (selected_pending_package_stage_command_id is not None and
                selected_orphan_package_stage_command_id is not None):
            raise ValueError("select one pending or orphan package stage")
        selected_stage_id = (selected_pending_package_stage_command_id if
            selected_pending_package_stage_command_id is not None else
            selected_orphan_package_stage_command_id)
        if (selected_stage_id is None) != (expected_ts_state_digest is None):
            raise ValueError("selected package stage requires the inspected TS state digest")
        if selected_stage_id is not None and (
            not isinstance(selected_stage_id, str)
            or not selected_stage_id
            or not isinstance(expected_ts_state_digest, str)
            or not expected_ts_state_digest
        ):
            raise TypeError("selected package stage ID and TS state digest must be nonempty strings")
        return dict(workspace_id=workspace_id,
            protected_ts_state_path=protected_ts_state_path,
            protected_ts_intent_db_path=protected_ts_intent_db_path,
            protected_owner_pkcs8_path=protected_owner_pkcs8_path,
            expected_owner_actor_id=expected_owner_actor_id,
            expected_owner_key_id=expected_owner_key_id,
            recover_pending_action=recover_pending_action,
            retain_pending_action_command_id=retain_pending_action_command_id,
            kernel_pending_command_ids=ids,
            expected_kernel_intent_db_digest=expected_kernel_intent_db_digest,
            selected_pending_package_stage_command_id=selected_pending_package_stage_command_id,
            selected_orphan_package_stage_command_id=selected_orphan_package_stage_command_id,
            expected_ts_state_digest=expected_ts_state_digest)

    @staticmethod
    def _input(name: str, visibility: Literal["PUBLIC", "PRIVATE"], *,
               structured: bool = False, keep_encrypted: list | None = None,
               coordination_version: int | None = None) -> dict:
        has_surrogate = False
        index = 0
        while index < len(name):
            unit = ord(name[index])
            if 0xD800 <= unit <= 0xDBFF:
                if index + 1 < len(name) and 0xDC00 <= ord(name[index + 1]) <= 0xDFFF:
                    index += 2
                    continue
                has_surrogate = True
                break
            if 0xDC00 <= unit <= 0xDFFF:
                has_surrogate = True
                break
            index += 1
        encoded = name.encode("utf-16-le", "surrogatepass") if has_surrogate else b""
        units = [int.from_bytes(encoded[offset:offset + 2], "little")
            for offset in range(0, len(encoded), 2)] if has_surrogate else None
        return dict(name="" if has_surrogate else name, name_utf16=units,
            visibility=visibility, structured=structured,
            keep_encrypted_json=json.dumps(keep_encrypted if keep_encrypted is not None else [],
                ensure_ascii=True, separators=(",", ":")),
            coordination_version=coordination_version)

    def prepare(self, name: str, visibility: Literal["PUBLIC", "PRIVATE"], *,
                structured: bool = False, keep_encrypted: list | None = None,
                coordination_version: int | None = None) -> OwnerWorkspaceResult:
        return cast(OwnerWorkspaceResult, self._owner("prepare", input_value=self._input(name,
            visibility, structured=structured, keep_encrypted=keep_encrypted,
            coordination_version=coordination_version)))

    def create(self, name: str, visibility: Literal["PUBLIC", "PRIVATE"], *,
               structured: bool = False, keep_encrypted: list | None = None,
               coordination_version: int | None = None) -> OwnerWorkspaceResult:
        return cast(OwnerWorkspaceResult, self._owner("create", input_value=self._input(name,
            visibility, structured=structured, keep_encrypted=keep_encrypted,
            coordination_version=coordination_version)))

    def resume(self, command_id: str) -> OwnerWorkspaceResult:
        return cast(OwnerWorkspaceResult, self._owner("resume", command_id=command_id))

    def operations(self) -> list[OwnerWorkspaceResult]:
        """Local protected PENDING and CREATED history; no fresh service status."""
        return cast(list[OwnerWorkspaceResult], self._owner("operations"))

    def attach(self, workspace_id: str, protected_ts_state_path: str,
               protected_ts_intent_db_path: str, protected_owner_pkcs8_path: str,
               expected_owner_actor_id: str,
               expected_owner_key_id: str, *,
               recover_pending_action: bool = False,
               retain_pending_action_command_id: str | None = None,
               kernel_pending_command_ids: list[str] | None = None,
               expected_kernel_intent_db_digest: str | None = None,
               selected_pending_package_stage_command_id: str | None = None,
               selected_orphan_package_stage_command_id: str | None = None,
               expected_ts_state_digest: str | None = None) -> HistoricalOwnerAttachmentResult:
        """Attach a stopped Owner; selected kernel packets stay local until explicit recovery."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id, recover_pending_action,
            retain_pending_action_command_id, kernel_pending_command_ids,
            expected_kernel_intent_db_digest,
            selected_pending_package_stage_command_id,
            selected_orphan_package_stage_command_id, expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, self._owner("attach", input_value=value))

    def inspect_kernel_pending(self, workspace_id: str, protected_ts_state_path: str,
                               protected_ts_intent_db_path: str,
                               protected_owner_pkcs8_path: str,
                               expected_owner_actor_id: str,
                               expected_owner_key_id: str) -> HistoricalKernelPendingInventory:
        """Inspect verified pending source commands without attaching or submitting them."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalKernelPendingInventory,
            self._owner("kernel_inspect", input_value=value))

    def inspect_pending_package_stage(self, workspace_id: str, protected_ts_state_path: str,
                                      protected_ts_intent_db_path: str,
                                      protected_owner_pkcs8_path: str,
                                      expected_owner_actor_id: str,
                                      expected_owner_key_id: str) -> HistoricalPackageStagePendingInventory:
        """Inspect one saved ADMIN stage packet without attaching or submitting it."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStagePendingInventory,
            self._owner("stage_inspect", input_value=value))

    @staticmethod
    def _multipart_stage_request(attachment_input: dict, material_json: str) -> dict:
        if not isinstance(material_json, str) or not material_json:
            raise TypeError("material_json must be a nonempty JSON string")
        return {"attachment_input": attachment_input, "material_json": material_json}

    @staticmethod
    def _direct_begin_request(attachment_input: dict, selected_command_id: str,
            expected_ts_state_digest: str | None, options_json: str, material_json: str,
            *, attach: bool) -> dict:
        if any(not isinstance(value, str) or not value for value in
               (selected_command_id, options_json, material_json)):
            raise TypeError("direct install requires selected ID, options and material JSON strings")
        if attach and (not isinstance(expected_ts_state_digest, str) or not expected_ts_state_digest):
            raise ValueError("direct install attach requires the inspected TS state digest")
        if not attach and expected_ts_state_digest is not None:
            raise ValueError("direct install inspection must not select a TS state digest")
        return dict(attachment_input=attachment_input, selected_command_id=selected_command_id,
            expected_ts_state_digest=expected_ts_state_digest, options_json=options_json,
            material_json=material_json)

    def inspect_pending_direct_install_begin(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            options_json: str, material_json: str) -> HistoricalDirectInstallPendingInventory:
        """Verify an exact retained BEGIN/PAGE/END against selected options/material; no POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalDirectInstallPendingInventory, self._owner(
            "direct_begin_inspect", input_value=request))

    def attach_pending_direct_install_begin(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        """Import only the inspected retained BEGIN/PAGE/END; recover its selected packet ID."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "direct_begin_attach", input_value=request))

    def recover_pending_direct_install_begin(self, attach_id: str,
            expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        """Explicit same-ID recovery of a retained direct BEGIN/PAGE/END packet."""
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "direct_begin_recover", command_id=expected_command_id,
            workspace_id=attach_id))

    # Generic packet names share the existing native recovery implementation.
    inspect_pending_direct_install_packet = inspect_pending_direct_install_begin
    attach_pending_direct_install_packet = attach_pending_direct_install_begin
    recover_pending_direct_install_packet = recover_pending_direct_install_begin

    @staticmethod
    def _completed_direct_request(attachment_input: dict, selected_instance_id: str,
            expected_ts_state_digest: str | None, options_json: str, material_json: str,
            *, attach: bool) -> dict:
        value = SecureOwnerWorkspaceClient._direct_begin_request(attachment_input,
            selected_instance_id, expected_ts_state_digest, options_json, material_json,
            attach=attach)
        value["selected_instance_id"] = value.pop("selected_command_id")
        return value

    def inspect_completed_direct_install(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_instance_id: str,
            options_json: str, material_json: str) -> HistoricalDirectInstallCompletedInventory:
        """Verify a selected completed END and current authority; no install POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._completed_direct_request(value, selected_instance_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalDirectInstallCompletedInventory, self._owner(
            "direct_completed_inspect", input_value=request))

    def attach_completed_direct_install(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_instance_id: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        """Attach the inspected completed map without sending an install packet."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._completed_direct_request(value, selected_instance_id,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "direct_completed_attach", input_value=request))

    def inspect_pending_multipart_package_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str) -> HistoricalPackageStagePendingInventory:
        """Verify the full material and saved nonzero part; no attach row or POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStagePendingInventory, self._owner(
            "stage_multipart_inspect", input_value=self._multipart_stage_request(value, material_json)))

    def attach_pending_multipart_package_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str, *,
            selected_pending_package_stage_command_id: str,
            expected_ts_state_digest: str) -> HistoricalOwnerAttachmentResult:
        """Import one inspected multipart stage without POST; recovery remains explicit."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id,
            selected_pending_package_stage_command_id=selected_pending_package_stage_command_id,
            expected_ts_state_digest=expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "stage_multipart_attach", input_value=self._multipart_stage_request(value, material_json)))

    def recover_pending_package_stage(self, attach_id: str,
                                      expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        """Explicitly reconcile or submit one retained original ADMIN stage packet."""
        return cast(HistoricalOwnerAttachmentResult,
            self._owner("stage_recover", command_id=expected_command_id,
                        workspace_id=attach_id))

    def inspect_orphan_package_stage(self, workspace_id: str, protected_ts_state_path: str,
                                     protected_ts_intent_db_path: str,
                                     protected_owner_pkcs8_path: str,
                                     expected_owner_actor_id: str,
                                     expected_owner_key_id: str) -> HistoricalPackageStageOrphanInventory:
        """Inspect an original stage marker with no saved signed packet; no POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStageOrphanInventory,
            self._owner("orphan_inspect", input_value=value))

    def inspect_multipart_orphan_package_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str) -> HistoricalPackageStageOrphanInventory:
        """Verify complete material against an orphaned nonzero part; no attach row or POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStageOrphanInventory, self._owner(
            "orphan_multipart_inspect",
            input_value=self._multipart_stage_request(value, material_json)))

    def attach_multipart_orphan_package_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str, *,
            selected_orphan_package_stage_command_id: str,
            expected_ts_state_digest: str) -> HistoricalOwnerAttachmentResult:
        """Import a verified orphaned nonzero part without POST; replan remains explicit."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id,
            selected_orphan_package_stage_command_id=selected_orphan_package_stage_command_id,
            expected_ts_state_digest=expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "orphan_multipart_attach",
            input_value=self._multipart_stage_request(value, material_json)))

    def replan_orphan_package_stage(self, attach_id: str,
                                    original_command_id: str,
                                    material_json: str | None = None) -> HistoricalOwnerAttachmentResult:
        """Select one new stage; omit material only to resume a saved replan."""
        if material_json is not None and (not isinstance(material_json, str) or not material_json):
            raise TypeError("material_json must be a nonempty JSON string when supplied")
        return cast(HistoricalOwnerAttachmentResult, self._owner("orphan_replan",
            input_value=material_json,
            command_id=original_command_id, workspace_id=attach_id))

    def kernel_command_status(self, attach_id: str) -> list[HistoricalKernelCommandStatus]:
        """Read local status for selected commands; this does not contact the service."""
        return cast(list[HistoricalKernelCommandStatus],
            self._owner("kernel_status", command_id=attach_id))

    def recover_kernel_command(self, attach_id: str,
                               command_id: str) -> HistoricalKernelCommandStatus:
        """Explicitly retry one imported original signed kernel command."""
        return cast(HistoricalKernelCommandStatus,
            self._owner("kernel_recover", command_id=command_id, workspace_id=attach_id))

    def resume_attachment(self, attach_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult,
            self._owner("resume_attachment", command_id=attach_id))

    def retain_pending_action(self, attach_id: str, expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        """Keep one original signed ACTION unresolved without submitting it."""
        return cast(HistoricalOwnerAttachmentResult,
            self._owner("retain_pending_action", command_id=expected_command_id,
                        workspace_id=attach_id))

    def attachments(self) -> list[HistoricalOwnerAttachmentResult]:
        """Protected local attachment history; PREPARED is not remote acceptance."""
        return cast(list[HistoricalOwnerAttachmentResult], self._owner("attachments"))

    def submit_format_transition(self, workspace_id: str,
                                 transition: Literal["UPGRADE_WIRE_V3", "RAISE_PRIVATE_CEILING_TWO"],
                                 *, command_id: str | None = None,
                                 issued_at_ms: int | None = None) -> OwnerFormatTransitionResult:
        value = dict(workspace_id=workspace_id, transition=transition,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(OwnerFormatTransitionResult,
                    self._owner("format_submit", input_value=value))

    def resume_format_transition(self, workspace_id: str, command_id: str) -> OwnerFormatTransitionResult:
        return cast(OwnerFormatTransitionResult,
                    self._owner("format_resume", command_id=command_id, workspace_id=workspace_id))

    def format_transitions(self, workspace_id: str) -> list[OwnerFormatTransitionResult]:
        """Protected local PENDING/ACCEPTED history; PENDING is not remote acceptance."""
        return cast(list[OwnerFormatTransitionResult], self._owner("format_history", workspace_id=workspace_id))

    def read(self, workspace_id: str) -> VerifiedSecureWorkspace:
        return cast(VerifiedSecureWorkspace, self._owner("read", workspace_id=workspace_id))

    def public_actions(self, workspace_id: str) -> "OwnerWorkspaceActionClient":
        return OwnerWorkspaceActionClient(self._config, workspace_id, "public_action")

    def private_actions(self, workspace_id: str) -> "OwnerWorkspaceActionClient":
        return OwnerWorkspaceActionClient(self._config, workspace_id, "private_action")

    def public_installer(self, workspace_id: str) -> "OwnerWorkspacePackageInstaller":
        return OwnerWorkspacePackageInstaller(self._config, workspace_id)

    def private_package_stager(self, workspace_id: str) -> "OwnerWorkspacePrivatePackageStager":
        return OwnerWorkspacePrivatePackageStager(self._config, workspace_id)

    def private_package_installer(self, workspace_id: str) -> "OwnerWorkspacePrivatePackageInstaller":
        return OwnerWorkspacePrivatePackageInstaller(self._config, workspace_id)

    def public_admission(self, workspace_id: str) -> "OwnerWorkspaceAdmissionClient":
        return OwnerWorkspaceAdmissionClient(self._config, workspace_id)

    def private_admission(self, workspace_id: str) -> "OwnerWorkspacePrivateAdmissionClient":
        return OwnerWorkspacePrivateAdmissionClient(self._config, workspace_id)

    async def prepare_async(self, name: str, visibility: Literal["PUBLIC", "PRIVATE"], *,
                            structured: bool = False, keep_encrypted: list | None = None,
                            coordination_version: int | None = None) -> OwnerWorkspaceResult:
        value = self._input(name, visibility, structured=structured,
            keep_encrypted=keep_encrypted, coordination_version=coordination_version)
        return cast(OwnerWorkspaceResult, await _run_cancelled_async(self._owner,
            "prepare", input_value=value))

    async def create_async(self, name: str, visibility: Literal["PUBLIC", "PRIVATE"], *,
                           structured: bool = False, keep_encrypted: list | None = None,
                           coordination_version: int | None = None) -> OwnerWorkspaceResult:
        value = self._input(name, visibility, structured=structured,
            keep_encrypted=keep_encrypted, coordination_version=coordination_version)
        return cast(OwnerWorkspaceResult, await _run_cancelled_async(self._owner,
            "create", input_value=value))

    async def resume_async(self, command_id: str) -> OwnerWorkspaceResult:
        return cast(OwnerWorkspaceResult, await _run_cancelled_async(self._owner,
            "resume", command_id=command_id))

    async def operations_async(self) -> list[OwnerWorkspaceResult]:
        return cast(list[OwnerWorkspaceResult], await _run_cancelled_async(self._owner,
            "operations"))

    async def attach_async(self, workspace_id: str, protected_ts_state_path: str,
                           protected_ts_intent_db_path: str,
                           protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
                           expected_owner_key_id: str, *,
                           recover_pending_action: bool = False,
                           retain_pending_action_command_id: str | None = None,
                           kernel_pending_command_ids: list[str] | None = None,
                           expected_kernel_intent_db_digest: str | None = None,
                           selected_pending_package_stage_command_id: str | None = None,
                           selected_orphan_package_stage_command_id: str | None = None,
                           expected_ts_state_digest: str | None = None) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id, recover_pending_action,
            retain_pending_action_command_id, kernel_pending_command_ids,
            expected_kernel_intent_db_digest,
            selected_pending_package_stage_command_id,
            selected_orphan_package_stage_command_id, expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "attach", input_value=value))

    async def inspect_kernel_pending_async(self, workspace_id: str,
                                           protected_ts_state_path: str,
                                           protected_ts_intent_db_path: str,
                                           protected_owner_pkcs8_path: str,
                                           expected_owner_actor_id: str,
                                           expected_owner_key_id: str) -> HistoricalKernelPendingInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalKernelPendingInventory, await _run_cancelled_async(
            self._owner, "kernel_inspect", input_value=value))

    async def inspect_pending_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str) -> HistoricalPackageStagePendingInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStagePendingInventory, await _run_cancelled_async(
            self._owner, "stage_inspect", input_value=value))

    async def inspect_pending_direct_install_begin_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            options_json: str, material_json: str) -> HistoricalDirectInstallPendingInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalDirectInstallPendingInventory, await _run_cancelled_async(
            self._owner, "direct_begin_inspect", input_value=request))

    async def attach_pending_direct_install_begin_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "direct_begin_attach", input_value=request))

    async def recover_pending_direct_install_begin_async(self, attach_id: str,
            expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "direct_begin_recover", command_id=expected_command_id,
            workspace_id=attach_id))

    inspect_pending_direct_install_packet_async = inspect_pending_direct_install_begin_async
    attach_pending_direct_install_packet_async = attach_pending_direct_install_begin_async
    recover_pending_direct_install_packet_async = recover_pending_direct_install_begin_async

    async def inspect_completed_direct_install_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_instance_id: str,
            options_json: str, material_json: str) -> HistoricalDirectInstallCompletedInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._completed_direct_request(value, selected_instance_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalDirectInstallCompletedInventory, await _run_cancelled_async(
            self._owner, "direct_completed_inspect", input_value=request))

    async def attach_completed_direct_install_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_instance_id: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._completed_direct_request(value, selected_instance_id,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "direct_completed_attach", input_value=request))

    async def inspect_pending_multipart_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str) -> HistoricalPackageStagePendingInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStagePendingInventory, await _run_cancelled_async(
            self._owner, "stage_multipart_inspect",
            input_value=self._multipart_stage_request(value, material_json)))

    async def attach_pending_multipart_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str, *,
            selected_pending_package_stage_command_id: str,
            expected_ts_state_digest: str) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id,
            selected_pending_package_stage_command_id=selected_pending_package_stage_command_id,
            expected_ts_state_digest=expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "stage_multipart_attach",
            input_value=self._multipart_stage_request(value, material_json)))

    async def recover_pending_package_stage_async(self, attach_id: str,
            expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "stage_recover", command_id=expected_command_id,
            workspace_id=attach_id))

    async def inspect_orphan_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str) -> HistoricalPackageStageOrphanInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStageOrphanInventory, await _run_cancelled_async(
            self._owner, "orphan_inspect", input_value=value))

    async def inspect_multipart_orphan_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str) -> HistoricalPackageStageOrphanInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(HistoricalPackageStageOrphanInventory, await _run_cancelled_async(
            self._owner, "orphan_multipart_inspect",
            input_value=self._multipart_stage_request(value, material_json)))

    async def attach_multipart_orphan_package_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, material_json: str, *,
            selected_orphan_package_stage_command_id: str,
            expected_ts_state_digest: str) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id,
            selected_orphan_package_stage_command_id=selected_orphan_package_stage_command_id,
            expected_ts_state_digest=expected_ts_state_digest)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "orphan_multipart_attach",
            input_value=self._multipart_stage_request(value, material_json)))

    async def replan_orphan_package_stage_async(self, attach_id: str,
            original_command_id: str,
            material_json: str | None = None) -> HistoricalOwnerAttachmentResult:
        if material_json is not None and (not isinstance(material_json, str) or not material_json):
            raise TypeError("material_json must be a nonempty JSON string when supplied")
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "orphan_replan",
            input_value=material_json,
            command_id=original_command_id, workspace_id=attach_id))

    async def kernel_command_status_async(self, attach_id: str) -> list[HistoricalKernelCommandStatus]:
        return cast(list[HistoricalKernelCommandStatus], await _run_cancelled_async(
            self._owner, "kernel_status", command_id=attach_id))

    async def recover_kernel_command_async(self, attach_id: str,
                                           command_id: str) -> HistoricalKernelCommandStatus:
        return cast(HistoricalKernelCommandStatus, await _run_cancelled_async(
            self._owner, "kernel_recover", command_id=command_id, workspace_id=attach_id))

    async def resume_attachment_async(self, attach_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "resume_attachment", command_id=attach_id))

    async def retain_pending_action_async(self, attach_id: str,
                                          expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "retain_pending_action", command_id=expected_command_id,
            workspace_id=attach_id))

    async def attachments_async(self) -> list[HistoricalOwnerAttachmentResult]:
        return cast(list[HistoricalOwnerAttachmentResult], await _run_cancelled_async(
            self._owner, "attachments"))

    async def submit_format_transition_async(self, workspace_id: str,
                                              transition: Literal["UPGRADE_WIRE_V3", "RAISE_PRIVATE_CEILING_TWO"],
                                              *, command_id: str | None = None,
                                              issued_at_ms: int | None = None) -> OwnerFormatTransitionResult:
        value = dict(workspace_id=workspace_id, transition=transition,
                     command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(OwnerFormatTransitionResult, await _run_cancelled_async(
            self._owner, "format_submit", input_value=value))

    async def resume_format_transition_async(self, workspace_id: str, command_id: str) -> OwnerFormatTransitionResult:
        return cast(OwnerFormatTransitionResult, await _run_cancelled_async(
            self._owner, "format_resume", command_id=command_id, workspace_id=workspace_id))

    async def format_transitions_async(self, workspace_id: str) -> list[OwnerFormatTransitionResult]:
        return cast(list[OwnerFormatTransitionResult], await _run_cancelled_async(
            self._owner, "format_history", workspace_id=workspace_id))

    async def read_async(self, workspace_id: str) -> VerifiedSecureWorkspace:
        return cast(VerifiedSecureWorkspace, await _run_cancelled_async(self._owner,
            "read", workspace_id=workspace_id))


class OwnerWorkspaceActionClient(SecurePublicActionClient):
    """Actions for a workspace selected from protected Owner creation history."""

    def __init__(self, owner_config: dict, workspace_id: str, kind: str):
        self._owner_config = owner_config
        self._workspace_id = workspace_id
        self._kind = kind

    def _action(self, operation: str, *, input_value: dict | None = None,
                command_id: str | None = None,
                cancel_handle: KernelCancelHandle | None = None) -> SecureActionResult | list[PendingSecureAction]:
        result = json.loads(secure_owner_consumer_json(self._kind, operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            command_id, cancel_handle))
        if result["ok"] is not True:
            raise SecureActionError(result["code"], result["message"])
        value = result["value"]
        if operation == "pending":
            return cast(list[PendingSecureAction], value)
        receipt_json = value.pop("receipt_canonical_json")
        value["receipt"] = None if receipt_json is None else json.loads(receipt_json)
        return cast(SecureActionResult, value)


class OwnerWorkspacePackageInstaller(SecurePublicPackageInstaller):
    """Install a selected PUBLIC closure into an Owner-created workspace."""

    def __init__(self, owner_config: dict, workspace_id: str):
        self._owner_config = owner_config
        self._workspace_id = workspace_id

    def _install(self, operation: str, *, input_value: dict | None = None,
                 begin_command_id: str | None = None,
                 cancel_handle: KernelCancelHandle | None = None) -> PublicInstallBeginResult | PublicInstallProgress | list[PendingPublicInstall]:
        result = json.loads(secure_owner_consumer_json("public_install", operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            begin_command_id, cancel_handle))
        if result["ok"] is not True:
            raise PublicInstallError(result["code"], result["message"])
        return cast(PublicInstallBeginResult | PublicInstallProgress | list[PendingPublicInstall], result["value"])


class PrivatePackageStageResult(TypedDict):
    status: Literal["PENDING", "STAGED"]
    stage_id: str
    workspace_id: str
    source_id: str
    root_package_digest: str
    protocol_digest: str
    part_count: int
    applied_parts: int
    pending_command_id: str | None


class SavedPrivatePackageStage(TypedDict):
    stage_id: str
    workspace_id: str
    source_id: str
    root_package_digest: str
    protocol_digest: str
    part_count: int
    saved_steps: int
    locally_verified_complete: bool


class PrivatePackageStageError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class OwnerWorkspacePrivatePackageStager:
    """Save and verify PRIVATE package parts; STAGED does not install them."""

    def __init__(self, owner_config: dict, workspace_id: str):
        self._owner_config = owner_config
        self._workspace_id = workspace_id

    def _stage(self, operation: str, *, input_value: dict | None = None,
               stage_id: str | None = None,
               cancel_handle: KernelCancelHandle | None = None) -> PrivatePackageStageResult | list[SavedPrivatePackageStage]:
        result = json.loads(secure_owner_consumer_json("private_stage", operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            stage_id, cancel_handle))
        if result["ok"] is not True:
            raise PrivatePackageStageError(result["code"], result["message"])
        return cast(PrivatePackageStageResult | list[SavedPrivatePackageStage], result["value"])

    def stage(self, material_json: str, *, expected_root_package_digest: str,
              expected_protocol_digest: str, stage_id: str | None = None,
              command_id: str | None = None,
              issued_at_ms: int | None = None) -> PrivatePackageStageResult:
        input_value = dict(material_json=material_json,
            expected_root_package_digest=expected_root_package_digest,
            expected_protocol_digest=expected_protocol_digest,
            stage_id=stage_id, command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(PrivatePackageStageResult, self._stage("stage", input_value=input_value))

    def continue_stage(self, stage_id: str) -> PrivatePackageStageResult:
        return cast(PrivatePackageStageResult, self._stage("continue", stage_id=stage_id))

    def stages(self) -> list[SavedPrivatePackageStage]:
        """Protected local stage IDs and progress, not fresh service status."""
        return cast(list[SavedPrivatePackageStage], self._stage("stages"))

    async def stage_async(self, material_json: str, *, expected_root_package_digest: str,
                          expected_protocol_digest: str, stage_id: str | None = None,
                          command_id: str | None = None,
                          issued_at_ms: int | None = None) -> PrivatePackageStageResult:
        input_value = dict(material_json=material_json,
            expected_root_package_digest=expected_root_package_digest,
            expected_protocol_digest=expected_protocol_digest,
            stage_id=stage_id, command_id=command_id, issued_at_ms=issued_at_ms)
        return cast(PrivatePackageStageResult, await _run_cancelled_async(self._stage,
            "stage", input_value=input_value))

    async def continue_stage_async(self, stage_id: str) -> PrivatePackageStageResult:
        return cast(PrivatePackageStageResult, await _run_cancelled_async(self._stage,
            "continue", stage_id=stage_id))

    async def stages_async(self) -> list[SavedPrivatePackageStage]:
        return cast(list[SavedPrivatePackageStage], await _run_cancelled_async(self._stage,
            "stages"))


class PrivatePackageInstallProgress(TypedDict):
    status: Literal["PENDING", "ACCEPTED"]
    begin_command_id: str
    step_command_id: str
    step_action_id: Literal["secure.structure.begin", "secure.structure.page", "secure.structure.end"]
    workspace_id: str
    protocol_digest: str
    instance_id: str
    commit_hash: str


class SavedPrivatePackageInstall(TypedDict):
    begin_command_id: str
    source_kind: Literal["DIRECT", "STAGED"]
    stage_id: NotRequired[str]
    workspace_id: str
    instance_id: str
    protocol_digest: str
    locally_saved: bool


class PrivateFieldDisclosure(TypedDict):
    schema: str
    fields: list[str]


def _selected_disclosure(value: object) -> list[PrivateFieldDisclosure]:
    if not isinstance(value, list) or any(
        not isinstance(row, dict) or set(row) != {"schema", "fields"}
        or not isinstance(row["schema"], str)
        or not isinstance(row["fields"], list)
        or any(not isinstance(field, str) for field in row["fields"])
        for row in value
    ):
        raise TypeError("disclose must be a list of {schema, fields} selections")
    return cast(list[PrivateFieldDisclosure], value)


class PrivatePackageInstallError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class OwnerWorkspacePrivatePackageInstaller(OwnerWorkspacePrivatePackageStager):
    """Install a staged or directly selected PRIVATE package through signed replay.

    ACCEPTED is a step result; only verified END and a later signed ACTIVE
    read prove the installed protocol is usable.
    """

    def _install(self, operation: str, *, input_value: dict | None = None,
                 begin_command_id: str | None = None,
                 cancel_handle: KernelCancelHandle | None = None) -> PrivatePackageInstallProgress | list[SavedPrivatePackageInstall]:
        result = json.loads(secure_owner_consumer_json("private_install", operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            begin_command_id, cancel_handle))
        if result["ok"] is not True:
            raise PrivatePackageInstallError(result["code"], result["message"])
        return cast(PrivatePackageInstallProgress | list[SavedPrivatePackageInstall], result["value"])

    def begin(self, stage_id: str, instance_id: str, entrypoint: str, *,
              grants_json: str = "[]", command_id: str | None = None,
              issued_at_ms: int | None = None,
              disclose: list[PrivateFieldDisclosure] | _OmittedInstallOption = _OMITTED_DISCLOSURE) -> PrivatePackageInstallProgress:
        value = dict(stage_id=stage_id, instance_id=instance_id, entrypoint=entrypoint,
            grants_json=grants_json, command_id=command_id, issued_at_ms=issued_at_ms)
        if disclose is not _OMITTED_DISCLOSURE:
            value["disclose"] = _selected_disclosure(disclose)
        return cast(PrivatePackageInstallProgress, self._install("begin", input_value=value))

    def begin_direct(self, closure_json: str, expected_root_package_digest: str,
                     expected_protocol_digest: str, instance_id: str, entrypoint: str, *,
                     grants_json: str = "[]", command_id: str | None = None,
                     issued_at_ms: int | None = None,
                     bindings: Mapping[str, JSONValue] | _OmittedInstallOption = _OMITTED_BINDINGS,
                     disclose: list[PrivateFieldDisclosure] | _OmittedInstallOption = _OMITTED_DISCLOSURE) -> PrivatePackageInstallProgress:
        """Select raw package closure JSON directly; no source parts are staged."""
        value = dict(closure_json=closure_json,
            expected_root_package_digest=expected_root_package_digest,
            expected_protocol_digest=expected_protocol_digest,
            instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
            command_id=command_id, issued_at_ms=issued_at_ms)
        if bindings is not _OMITTED_BINDINGS:
            if not isinstance(bindings, Mapping):
                raise TypeError("bindings must be a JSON object")
            value["bindings_json"] = json.dumps(dict(bindings), ensure_ascii=True,
                allow_nan=False, separators=(",", ":"))
        if disclose is not _OMITTED_DISCLOSURE:
            value["disclose"] = _selected_disclosure(disclose)
        return cast(PrivatePackageInstallProgress, self._install("begin_direct", input_value=value))

    def continue_install(self, begin_command_id: str) -> PrivatePackageInstallProgress:
        return cast(PrivatePackageInstallProgress, self._install("continue", begin_command_id=begin_command_id))

    def installs(self) -> list[SavedPrivatePackageInstall]:
        """Recover saved BEGIN IDs locally; rows do not establish acceptance."""
        return cast(list[SavedPrivatePackageInstall], self._install("installs"))

    async def begin_async(self, stage_id: str, instance_id: str, entrypoint: str, *,
                          grants_json: str = "[]", command_id: str | None = None,
                          issued_at_ms: int | None = None,
                          disclose: list[PrivateFieldDisclosure] | _OmittedInstallOption = _OMITTED_DISCLOSURE) -> PrivatePackageInstallProgress:
        value = dict(stage_id=stage_id, instance_id=instance_id, entrypoint=entrypoint,
            grants_json=grants_json, command_id=command_id, issued_at_ms=issued_at_ms)
        if disclose is not _OMITTED_DISCLOSURE:
            value["disclose"] = _selected_disclosure(disclose)
        return cast(PrivatePackageInstallProgress, await _run_cancelled_async(self._install,
            "begin", input_value=value))

    async def begin_direct_async(self, closure_json: str, expected_root_package_digest: str,
                                 expected_protocol_digest: str, instance_id: str,
                                 entrypoint: str, *, grants_json: str = "[]",
                                 command_id: str | None = None,
                                 issued_at_ms: int | None = None,
                                 bindings: Mapping[str, JSONValue] | _OmittedInstallOption = _OMITTED_BINDINGS,
                                 disclose: list[PrivateFieldDisclosure] | _OmittedInstallOption = _OMITTED_DISCLOSURE) -> PrivatePackageInstallProgress:
        value = dict(closure_json=closure_json,
            expected_root_package_digest=expected_root_package_digest,
            expected_protocol_digest=expected_protocol_digest,
            instance_id=instance_id, entrypoint=entrypoint, grants_json=grants_json,
            command_id=command_id, issued_at_ms=issued_at_ms)
        if bindings is not _OMITTED_BINDINGS:
            if not isinstance(bindings, Mapping):
                raise TypeError("bindings must be a JSON object")
            value["bindings_json"] = json.dumps(dict(bindings), ensure_ascii=True,
                allow_nan=False, separators=(",", ":"))
        if disclose is not _OMITTED_DISCLOSURE:
            value["disclose"] = _selected_disclosure(disclose)
        return cast(PrivatePackageInstallProgress, await _run_cancelled_async(self._install,
            "begin_direct", input_value=value))

    async def continue_install_async(self, begin_command_id: str) -> PrivatePackageInstallProgress:
        return cast(PrivatePackageInstallProgress, await _run_cancelled_async(self._install,
            "continue", begin_command_id=begin_command_id))

    async def installs_async(self) -> list[SavedPrivatePackageInstall]:
        return cast(list[SavedPrivatePackageInstall], await _run_cancelled_async(self._install,
            "installs"))


__all__ += ["HistoricalDirectInstallPendingInventory", "HistoricalDirectInstallCompletedInventory"]
__all__ += ["SecureOwnerWorkspaceClient", "OwnerWorkspaceResult", "HistoricalOwnerAttachmentResult", "HistoricalKernelCommandStatus", "HistoricalKernelPendingInventory", "HistoricalPackageStagePendingInventory", "OwnerFormatTransitionResult", "OwnerWorkspaceError",
            "OwnerWorkspaceActionClient", "OwnerWorkspacePackageInstaller",
            "OwnerWorkspacePrivatePackageStager", "PrivatePackageStageResult",
            "SavedPrivatePackageStage", "PrivatePackageStageError",
            "OwnerWorkspacePrivatePackageInstaller", "PrivatePackageInstallProgress",
            "SavedPrivatePackageInstall", "PrivateFieldDisclosure", "PrivatePackageInstallError"]


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


class AdmissionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AdmissionOfferResult(TypedDict):
    status: Literal["PENDING"]
    invite_id: str
    workspace_id: str
    offer_hash: str


class AdmissionDeliveryResult(TypedDict):
    status: Literal["PENDING", "AUTHORIZED"]
    invite_id: str
    grant_id: str
    workspace_id: str
    grant_hash: str


class InvitationDecisionResult(TypedDict):
    status: Literal["PENDING"]
    invite_id: str
    workspace_id: str
    decision_hash: str


class InvitationReceiveResult(TypedDict):
    status: Literal["PENDING", "READY"]
    invite_id: str
    workspace_id: str
    receipt_hash: str


async def _run_cancelled_async(method, operation: str, **kwargs):
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
            raise AdmissionError(result["code"], result["message"])
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
              expires_at_ms: int | None = None) -> AdmissionOfferResult:
        return cast(AdmissionOfferResult, self._admission("offer", input_value=self._offer_input(
            recipient_certificate_json, scopes_json, message, invite_id, issued_at_ms, expires_at_ms)))

    async def offer_async(self, recipient_certificate_json: str, scopes_json: str, *, message: str = "",
                          invite_id: str | None = None, issued_at_ms: int | None = None,
                          expires_at_ms: int | None = None) -> AdmissionOfferResult:
        return cast(AdmissionOfferResult, await _run_cancelled_async(self._admission, "offer", input_value=self._offer_input(
            recipient_certificate_json, scopes_json, message, invite_id, issued_at_ms, expires_at_ms)))

    def retry_offer(self, invite_id: str) -> AdmissionOfferResult:
        return cast(AdmissionOfferResult, self._admission("retry_offer", invite_id=invite_id))

    async def retry_offer_async(self, invite_id: str) -> AdmissionOfferResult:
        return cast(AdmissionOfferResult, await _run_cancelled_async(self._admission, "retry_offer", invite_id=invite_id))

    def pending_offers(self) -> list[dict]:
        return cast(list[dict], self._admission("pending_offers"))

    def deliver(self, invite_id: str) -> AdmissionDeliveryResult:
        return cast(AdmissionDeliveryResult, self._admission("deliver", invite_id=invite_id))

    async def deliver_async(self, invite_id: str) -> AdmissionDeliveryResult:
        return cast(AdmissionDeliveryResult, await _run_cancelled_async(self._admission, "deliver", invite_id=invite_id))

    def retry_delivery(self, grant_id: str) -> AdmissionDeliveryResult:
        return cast(AdmissionDeliveryResult, self._admission("retry_delivery", grant_id=grant_id))

    async def retry_delivery_async(self, grant_id: str) -> AdmissionDeliveryResult:
        return cast(AdmissionDeliveryResult, await _run_cancelled_async(self._admission, "retry_delivery", grant_id=grant_id))

    def pending_deliveries(self) -> list[dict]:
        return cast(list[dict], self._admission("pending_deliveries"))


class OwnerWorkspaceAdmissionClient(SecurePublicAdmissionClient):
    """Owner invitation and delivery for a PUBLIC workspace in protected creation history."""

    _kind = "public_admission"

    def __init__(self, owner_config: dict, workspace_id: str):
        self._owner_config = owner_config
        self._workspace_id = workspace_id

    def _admission(self, operation: str, *, input_value: dict | None = None,
                   invite_id: str | None = None, grant_id: str | None = None,
                   cancel_handle: KernelCancelHandle | None = None) -> dict | list[dict]:
        command_id = grant_id if operation == "retry_delivery" else invite_id
        result = json.loads(secure_owner_consumer_json(self._kind, operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            command_id, cancel_handle))
        if result["ok"] is not True:
            raise AdmissionError(result["code"], result["message"])
        return cast(dict | list[dict], result["value"])


class OwnerWorkspacePrivateAdmissionClient(OwnerWorkspaceAdmissionClient):
    """Owner invitation and delivery for a PRIVATE workspace in protected creation history."""

    _kind = "private_admission"


class PublicCatalogError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class PublicCatalogListing(TypedDict):
    catalog_origin: str
    listing_canonical_json: str
    listing: object


class InspectedPublicPackage(TypedDict):
    catalog_origin: str
    bundle_digest: str
    summary_canonical_json: str
    bundle_canonical_json: str
    summary: object
    bundle: object


class PublicCatalogClient:
    """Anonymous advisory search and exact-digest public package inspection.

    A matching digest proves package byte identity; it does not authenticate a
    publisher or grant authority to install it.
    """

    def __init__(self, origin: str, *, allow_loopback_http: bool = False,
                 max_listing_bytes: int | None = None):
        self._config = dict(origin=origin, allow_loopback_http=allow_loopback_http,
                            max_listing_bytes=max_listing_bytes)

    def _call(self, operation: str, *, query: str | None = None, after: str | None = None,
              limit: int | None = None, digest: str | None = None,
              cancel_handle: KernelCancelHandle | None = None) -> dict:
        result = json.loads(public_catalog_json(operation,
            json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            query, after, limit, digest, cancel_handle))
        if result["ok"] is not True:
            raise PublicCatalogError(result["code"], result["message"])
        return cast(dict, result["value"])

    def search(self, query: str, *, after: str | None = None, limit: int = 20) -> PublicCatalogListing:
        value = self._call("search", query=query, after=after, limit=limit)
        value["listing"] = json.loads(value["listing_canonical_json"])
        return cast(PublicCatalogListing, value)

    async def search_async(self, query: str, *, after: str | None = None, limit: int = 20) -> PublicCatalogListing:
        value = await _run_cancelled_async(self._call, "search", query=query, after=after, limit=limit)
        value["listing"] = json.loads(value["listing_canonical_json"])
        return cast(PublicCatalogListing, value)

    def inspect_exact(self, digest: str) -> InspectedPublicPackage:
        value = self._call("inspect", digest=digest)
        value["summary"] = json.loads(value["summary_canonical_json"])
        value["bundle"] = json.loads(value["bundle_canonical_json"])
        return cast(InspectedPublicPackage, value)

    async def inspect_exact_async(self, digest: str) -> InspectedPublicPackage:
        value = await _run_cancelled_async(self._call, "inspect", digest=digest)
        value["summary"] = json.loads(value["summary_canonical_json"])
        value["bundle"] = json.loads(value["bundle_canonical_json"])
        return cast(InspectedPublicPackage, value)


__all__ += ["OwnerWorkspaceAdmissionClient", "OwnerWorkspacePrivateAdmissionClient",
            "PublicCatalogClient", "PublicCatalogError",
            "PublicCatalogListing", "InspectedPublicPackage"]


class SecureInvitationClient:
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
            raise AdmissionError(result["code"], result["message"])
        return cast(dict | list[dict], result["value"])

    def decide(self, invite_id: str, decision: Literal["ACCEPT", "DECLINE"]) -> InvitationDecisionResult:
        return cast(InvitationDecisionResult, self._decision("decide", invite_id=invite_id, decision=decision))

    async def decide_async(self, invite_id: str, decision: Literal["ACCEPT", "DECLINE"]) -> InvitationDecisionResult:
        return cast(InvitationDecisionResult, await _run_cancelled_async(self._decision, "decide", invite_id=invite_id, decision=decision))

    def retry_decision(self, invite_id: str) -> InvitationDecisionResult:
        return cast(InvitationDecisionResult, self._decision("retry_decision", invite_id=invite_id))

    async def retry_decision_async(self, invite_id: str) -> InvitationDecisionResult:
        return cast(InvitationDecisionResult, await _run_cancelled_async(self._decision, "retry_decision", invite_id=invite_id))

    def pending_decisions(self) -> list[dict]:
        return cast(list[dict], self._decision("pending_decisions"))

    def receive(self, invite_id: str) -> InvitationReceiveResult:
        return cast(InvitationReceiveResult, self._decision("receive", invite_id=invite_id))

    async def receive_async(self, invite_id: str) -> InvitationReceiveResult:
        return cast(InvitationReceiveResult, await _run_cancelled_async(self._decision, "receive", invite_id=invite_id))

    def retry_receive(self, invite_id: str) -> InvitationReceiveResult:
        return cast(InvitationReceiveResult, self._decision("retry_receive", invite_id=invite_id))

    async def retry_receive_async(self, invite_id: str) -> InvitationReceiveResult:
        return cast(InvitationReceiveResult, await _run_cancelled_async(self._decision, "retry_receive", invite_id=invite_id))

    def pending_receipts(self) -> list[dict]:
        return cast(list[dict], self._decision("pending_receipts"))


__all__ += ["SecurePublicAdmissionClient", "SecureInvitationClient", "AdmissionError",
            "AdmissionOfferResult", "AdmissionDeliveryResult", "InvitationDecisionResult", "InvitationReceiveResult"]
