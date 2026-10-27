"""Experimental native Peerwork binding with verified kernel command results."""

import asyncio
import json
import warnings
from dataclasses import dataclass
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, NotRequired, TypeAlias, TypedDict, cast

JSONValue: TypeAlias = "None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]"


def _positive_u64_option(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2**64 - 1:
        raise ValueError(f"{name} must be a positive u64")
    return value


@dataclass(frozen=True)
class TransportOptions:
    """Explicit HTTP transport controls; certificate contents remain native-owned."""

    request_timeout_ms: int = 15000
    additional_root_pem_files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _positive_u64_option("request_timeout_ms", self.request_timeout_ms)
        paths = self.additional_root_pem_files
        if not isinstance(paths, (tuple, list)) or len(paths) > 16:
            raise ValueError("additional_root_pem_files must contain at most 16 paths")
        if any(not isinstance(path, str) or not path for path in paths):
            raise ValueError("additional_root_pem_files must contain nonempty paths")
        object.__setattr__(self, "additional_root_pem_files", tuple(paths))

    def _json_value(self) -> dict:
        return {"request_timeout_ms": self.request_timeout_ms,
                "additional_root_pem_files": list(self.additional_root_pem_files)}


def _transport_config(transport: TransportOptions | None) -> dict | None:
    if transport is None:
        return None
    if not isinstance(transport, TransportOptions):
        raise TypeError("transport must be a TransportOptions")
    return transport._json_value()

class _OmittedInstallOption:
    pass


_OMITTED_BINDINGS = _OmittedInstallOption()
_OMITTED_DISCLOSURE = _OmittedInstallOption()

from ._peerwork_native import (
    protocol_workbench_json,
    KernelCancelHandle,
    acquisition_observations_json,
    agent_context_json,
    navigation_json,
    read_view_json,
    private_read_view_json,
    current_page_json,
    capabilities_json,
    load_config_json,
    identity_create_json,
    prepare_owner_checkpoint_json,
    inspect_owner_cache_json,
    plan_owner_checkpoint_from_cache_json,
    prepare_owner_checkpoint_from_cache_json,
    identity_open_json,
    identity_import_seed_json,
    identity_import_pkcs8_pem_json,
    identity_import_owner_pem_json,
    kernel_json,
    secure_read_json,
    secure_read_profile_json,
    secure_private_read_json,
    secure_public_action_json,
    secure_private_action_json,
    secure_public_install_json,
    secure_owner_create_json,
    owner_guard_time_json,
    owner_member_scopes_json,
    secure_owner_consumer_json,
    public_catalog_json,
    secure_recipient_enrollment_json,
    secure_identity_directory_json,
    secure_public_admission_json,
    secure_public_decision_json,
    version,
)


class CapabilityManifest(TypedDict):
    backend_structure_execution: bool
    backend_current_state_reads: bool
    backend_durable_recovery: bool
    legacy_online_modes: Literal['RETIRED']
    protocol_offline_simulation: bool
    protocol_verified_export: bool
    protocol_plan_apply: bool
    guarded_invitation_finalize: bool
    producer_compatibility_report: bool
    workspace_url_generation: bool
    anonymous_changelog_read: bool
    public_authorized_state_read: bool
    private_authorized_state_read: bool
    private_system_current_page_read: bool
    owner_guard_time_enable: bool
    owner_member_scopes: bool
    private_install_auto_transport: bool
    private_install_reviewed_recovery: bool
    private_time_add_guard_windows: bool
    version: str
    status: str
    wire_canonicalization: bool
    signed_artifact_verification: bool
    receipt_verification: bool
    verified_public_workspace_reads: bool
    verified_workspace_reads: bool
    safe_actions: bool
    durable_recovery: bool


class ClientConfig(TypedDict):
    origin: str
    state_dir: str
    transport: NotRequired[TransportOptions]


class ConfigError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def load_config(path: str | None = None) -> ClientConfig:
    """Read explicit/env/OS protected config; never creates identity or contacts a service."""
    result = json.loads(load_config_json(path))
    if result["ok"] is not True:
        raise ConfigError(result["code"], result["message"])
    value = result["value"]
    if "transport" in value:
        selected = value["transport"]
        value["transport"] = TransportOptions(
            request_timeout_ms=selected["request_timeout_ms"],
            additional_root_pem_files=tuple(selected["additional_root_pem_files"]))
    return cast(ClientConfig, value)


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


class OpenedStructureBody(TypedDict):
    record_id: str
    revision: int
    source_command_id: str
    record_index: int
    key_id: str | None
    state: Literal["OPENED", "NO_CONTENT", "KEY_UNAVAILABLE", "AUTHENTICATION_FAILED", "BODY_INVALID", "KEY_STATE_INVALID", "UNSUPPORTED_ENCODING"]
    text: str | None
    assurance: Literal["AUTHOR_SIGNATURE_AND_AEAD"] | None


class KeyHistoryReadiness(TypedDict):
    job_id: str
    through_epoch: int
    state: Literal["READY", "PENDING", "UNAVAILABLE"]
    code: str | None

class AcceptedResult(TypedDict):
    warnings: NotRequired[list[dict[str, JSONValue]]]
    key_history: NotRequired[KeyHistoryReadiness]
    browser_approval_reference: NotRequired[str]
    opened_contents: NotRequired[list[OpenedStructureBody]]
    command_id: str
    workspace_id: str | None
    protocol_digest: str | None
    instance_id: str | None
    event_sequence: int | None
    revision: int | None
    produced_record_ids: list[str]
    catalog: CatalogAcceptedResult | None
    structure: NotRequired[dict[str, JSONValue]]


class StatusNotFound(TypedDict):
    state: Literal["NOT_FOUND"]


class StatusPending(TypedDict):
    state: Literal["PENDING"]


class StatusAccepted(TypedDict):
    state: Literal["ACCEPTED", "REJECTED", "COMMITTED"]
    result: AcceptedResult


KernelStatus = StatusNotFound | StatusPending | StatusAccepted


class StructureIntentPending(TypedDict):
    state: Literal["PENDING"]
    command_id: str
    code: str
    phase: str
    retryable: bool
    recovery: Literal["RESUME_SAME_INTENT", "NEW_READ", "OBSERVE_SAME_OPERATION"]


class StructureIntentCompleted(TypedDict):
    state: Literal["COMPLETED"]
    command_id: str
    result: AcceptedResult


StructureIntentOutcome = StatusAccepted | StructureIntentPending | StructureIntentCompleted



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
    status: Literal["ACCEPTED", "REJECTED", "COMMITTED"]
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


def prepare_owner_checkpoint(*, identity_path: str, expected_actor: str, origin: str,
                             audience: str, source_path: str, plan_path: str,
                             output_path: str, content_keys_path: str | None = None,
                             allow_loopback_http: bool = False) -> dict:
    """Prepare a mapped Owner checkpoint offline; return metadata, never keys.

    The protected JSONL input is an explicit current-state export. Business
    fields require allowlisted paths in the plan; selected body text is encrypted.
    Reopening the same output verifies and reuses its exact signed bytes.
    """
    request = dict(identity_path=identity_path, expected_actor=expected_actor,
                   origin=origin, audience=audience, source_path=source_path,
                   plan_path=plan_path, output_path=output_path,
                   content_keys_path=content_keys_path,
                   allow_loopback_http=allow_loopback_http)
    result = json.loads(prepare_owner_checkpoint_json(json.dumps(request)))
    if not result.get("ok"):
        error = RuntimeError(result.get("code", "CHECKPOINT_PREPARATION_FAILED"))
        for key in ("code", "stage", "effect_certainty", "recovery", "diagnostic"):
            setattr(error, key, result.get(key))
        raise error
    return result["value"]


def inspect_owner_cache(*, state_dir: str, workspace_id: str, report_path: str,
                        expected_actor: str | None = None, cache_selection: Literal["ACTIVE", "RECOVERY", "INSTALL"] = "ACTIVE", refresh_source: bool = False) -> dict:
    """Pause Owner operations first. Review only a selected verified ACTIVE cache.

    The private report stays inside the Owner directory. No refresh, submission,
    identity export or disclosure of field values occurs.
    """
    result = json.loads(inspect_owner_cache_json(json.dumps(dict(
        state_dir=state_dir, workspace_id=workspace_id, report_path=report_path,
        expected_actor=expected_actor,cache_selection=cache_selection,refresh_source=refresh_source))))
    if not result.get("ok"):
        error = RuntimeError(result.get("code", "OWNER_CACHE_REVIEW_FAILED"))
        for key in ("code", "stage", "effect_certainty", "diagnostic"):
            setattr(error, key, result.get(key))
        raise error
    return result["value"]


def _cached_conversion_result(value: str) -> dict:
    result = json.loads(value)
    if not result.get("ok"):
        error = RuntimeError(result.get("code", "CHECKPOINT_CACHE_FAILED"))
        for key in ("code", "stage", "effect_certainty", "diagnostic"):
            setattr(error, key, result.get(key))
        raise error
    return result["value"]


def plan_owner_checkpoint_from_cache(*, state_dir: str, workspace_id: str,
        expected_actor: str, snapshot_sha256: str, name: str, plan_path: str, cache_selection: Literal["ACTIVE", "RECOVERY", "INSTALL"] = "ACTIVE", refresh_source: bool = False) -> dict:
    """Generate a protected body/structure mapping without persisting body values."""
    return _cached_conversion_result(plan_owner_checkpoint_from_cache_json(json.dumps(dict(
        state_dir=state_dir, workspace_id=workspace_id, expected_actor=expected_actor,
        snapshot_sha256=snapshot_sha256, name=name, plan_path=plan_path,cache_selection=cache_selection,refresh_source=refresh_source))))


def prepare_owner_checkpoint_from_cache(*, state_dir: str, workspace_id: str,
        expected_actor: str, plan_path: str, output_path: str, origin: str,
        audience: str, allow_loopback_http: bool = False, cache_selection: Literal["ACTIVE", "RECOVERY", "INSTALL"] = "ACTIVE", refresh_source: bool = False) -> dict:
    """Verify selected cache and persist signed structure/ciphertext, no plaintext source."""
    return _cached_conversion_result(prepare_owner_checkpoint_from_cache_json(json.dumps(dict(
        state_dir=state_dir, workspace_id=workspace_id, expected_actor=expected_actor,
        plan_path=plan_path, output_path=output_path, origin=origin, audience=audience,
        allow_loopback_http=allow_loopback_http,cache_selection=cache_selection,refresh_source=refresh_source))))


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


class KernelError(RuntimeError):
    """Redacted native Kernel failure with a stable machine-readable code."""
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details
        self.http_status = details.get("http_status") if details else None
        self.server_code = details.get("server_code") if details else None
        self.phase = details.get("phase") if details else None
        self.retryable = details.get("retryable") if details else None
        self.recovery = details.get("recovery") if details else None


class KernelClient:
    """Experimental verified kernel command client with durable exact retry.

    Paths identify protected local state. The origin is an explicit trust input;
    loopback HTTP requires an explicit opt-in for local tests.
    """

    def __init__(self, origin: str, journal_path: str, identity_path: str,
                 *, required_features: tuple[str, ...] = (),
                 allow_loopback_http: bool = False,
                 authority: str | None = None,
                 transport: TransportOptions | None = None):
        self.origin = origin
        self.journal_path = journal_path
        self.identity_path = identity_path
        self.required_features = tuple(required_features)
        self.allow_loopback_http = allow_loopback_http
        self.authority = authority
        self.transport = transport
        self._storage_warnings: dict[str, str] = {}

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
        value = json.loads(kernel_json(
            operation, self.origin, self.journal_path, self.identity_path,
            list(self.required_features), self.allow_loopback_http,
            self.authority, command_json, command_id, upload_chunk, cancel_handle,
            migration_source, migration_backup, trusted_signer_key_ids,
            None if self.transport is None else json.dumps(_transport_config(self.transport),
                ensure_ascii=True, allow_nan=False, separators=(",", ":")),
        ))

        if isinstance(value, dict) and value.get("ok") is False:
            raise KernelError(value["code"], value["message"], value.get("details"))
        # Native verification pins the exact request, service, profile and
        # assurance before exposing authorized structural data to this binding.
        if isinstance(value, dict):
            for accepted in (value, value.get("result")):
                if isinstance(accepted, dict) and isinstance(accepted.get("structure_result_json"), str):
                    accepted["structure"] = json.loads(accepted.pop("structure_result_json"))
                    if "warnings" in accepted["structure"]:
                        accepted["warnings"] = accepted["structure"]["warnings"]
                    quota, workspace = accepted["structure"].get("capacity"), accepted.get("workspace_id")
                    if isinstance(quota, dict) and workspace and quota.get("status") in ("OK", "WARNING", "CRITICAL") and isinstance(quota.get("percent_used"), int) and isinstance(quota.get("remaining_write_bytes"), int):
                        previous = self._storage_warnings.get(workspace)
                        if quota["status"] != "OK" and previous != quota["status"]:
                            try:
                                warnings.warn(f"WORKSPACE_STORAGE_NEAR_LIMIT: workspace {workspace}, {quota['percent_used']}% used; {quota['remaining_write_bytes']} bytes available for ordinary writes.", RuntimeWarning, stacklevel=2)
                            except RuntimeWarning:
                                pass  # Warning-as-error must not hide an already verified outcome.
                        if len(self._storage_warnings) >= 64 and workspace not in self._storage_warnings:
                            self._storage_warnings.pop(next(iter(self._storage_warnings)))
                        self._storage_warnings[workspace] = quota["status"]
        return value

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

    def pending_page(self, *, after: str | None = None, preparations_after: str | None = None, limit: int = 32) -> dict:
        return cast(dict, self._call("pending_page", command={"after": after, "preparations_after": preparations_after, "limit": limit}))

    def build_pending_index(self) -> dict:
        """Explicit bounded legacy locator maintenance; never submits requests."""
        return cast(dict, self._call("build_pending_index"))

    def request_access(self, selection: dict) -> dict:
        """Create a platform-time-bound request; recipient keys stay in protected native state."""
        return cast(dict, self._call("request_access", command=selection))

    def publish_selected_record(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, self._call("publish_selected_record", command=selection))

    async def publish_selected_record_async(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("publish_selected_record", command=selection))

    def authorize_access(self, selection: dict) -> StructureIntentOutcome:
        """Owner approval with durable exact-packet recovery; read-only by default."""
        return cast(StructureIntentOutcome, self._call("authorize_access", command=selection))

    def accept_content_keys(self, selection: dict) -> dict:
        """Verify selected Owner key deliveries and import them atomically."""
        return cast(dict, self._call("accept_content_keys", command=selection))

    def coordinate_content_keys(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, self._call("coordinate_content_keys", command=selection))

    async def coordinate_content_keys_async(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("coordinate_content_keys", command=selection))

    def rotate_content_key(self, selection: dict) -> StructureIntentOutcome:
        """Owner-select a fresh canonical body key with durable operation recovery."""
        return cast(StructureIntentOutcome, self._call("rotate_content_key", command=selection))

    async def rotate_content_key_async(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("rotate_content_key", command=selection))

    def ensure_local_content_key(self, workspace_id: str) -> dict:
        """Create/reopen a local body key; does not grant access or deliver it."""
        return cast(dict, self._call("ensure_local_content_key", command={"workspace_id": workspace_id}))

    def status(self, command_id: str) -> KernelStatus:
        return cast(KernelStatus, self._call("status", command_id=command_id))

    def submit_saved(self, command_id: str) -> AcceptedResult:
        """POST saved bytes and require a verified, command-bound receipt."""
        return cast(AcceptedResult, self._call("submit_saved", command_id=command_id))

    def migrate_archive(self, selection: dict) -> StructureIntentOutcome:
        """Owner self-service migration with native upload, backend activation and exact resume."""
        return cast(StructureIntentOutcome, self._call("migrate_archive", command=selection))

    def execute_structure_intent(self, intent: dict) -> StructureIntentOutcome:
        """Sign and submit business intent using verified service time and durable recovery."""
        return cast(StructureIntentOutcome, self._call("execute_structure_intent", command=intent))

    def resume_structure_intent(self, command_id: str) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, self._call("resume_structure_intent", command_id=command_id))

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

    async def pending_page_async(self, *, after: str | None = None, preparations_after: str | None = None, limit: int = 32) -> dict:
        return cast(dict, await self._call_async("pending_page", command={"after": after, "preparations_after": preparations_after, "limit": limit}))

    async def build_pending_index_async(self) -> dict:
        return cast(dict, await self._call_async("build_pending_index"))

    async def request_access_async(self, selection: dict) -> dict:
        return cast(dict, await self._call_async("request_access", command=selection))

    async def authorize_access_async(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("authorize_access", command=selection))

    async def accept_content_keys_async(self, selection: dict) -> dict:
        return cast(dict, await self._call_async("accept_content_keys", command=selection))

    async def ensure_local_content_key_async(self, workspace_id: str) -> dict:
        return cast(dict, await self._call_async("ensure_local_content_key", command={"workspace_id": workspace_id}))

    async def status_async(self, command_id: str) -> KernelStatus:
        return cast(KernelStatus, await self._call_async("status", command_id=command_id))

    async def submit_saved_async(self, command_id: str) -> AcceptedResult:
        return cast(AcceptedResult, await self._call_async("submit_saved", command_id=command_id))

    async def migrate_archive_async(self, selection: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("migrate_archive", command=selection))

    async def execute_structure_intent_async(self, intent: dict) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("execute_structure_intent", command=intent))

    async def resume_structure_intent_async(self, command_id: str) -> StructureIntentOutcome:
        return cast(StructureIntentOutcome, await self._call_async("resume_structure_intent", command_id=command_id))

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
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024,
                 max_replay_commits: int = 102400,
                 transport: TransportOptions | None = None):
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
            "max_replay_commits": _positive_u64_option("max_replay_commits", max_replay_commits),
        }
        wire_transport = _transport_config(transport)
        if wire_transport is not None:
            self._config["transport"] = wire_transport

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
           "TransportOptions", "ClientConfig",
           "create_identity_async", "open_identity_async",
           "import_identity_seed_file", "import_identity_seed_file_async", "KernelClient",
           "CapabilityManifest", "IdentityInfo", "KernelInfo", "PendingIntent",
           "NamespaceClaimResult", "UploadBeginResult", "UploadChunkResult",
           "PackagePublishResult", "CatalogAcceptedResult", "AcceptedResult",
           "StatusNotFound", "StatusPending", "StatusAccepted", "KernelStatus", "StructureIntentOutcome", "StructureIntentPending", "StructureIntentCompleted",
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
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024,
                 max_replay_commits: int = 102400,
                 transport: TransportOptions | None = None):
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
            "max_replay_commits": _positive_u64_option("max_replay_commits", max_replay_commits),
        }
        wire_transport = _transport_config(transport)
        if wire_transport is not None:
            self._config["transport"] = wire_transport

    def export_fixture(self, instance_ids: list[str], *, time_ms: int, cached: bool = False) -> dict:
        """Export selected verified data without copying identity or recipient keys."""
        return export_protocol_fixture(self._config, instance_ids, time_ms=time_ms, cached=cached)

    async def export_fixture_async(self, instance_ids: list[str], *, time_ms: int, cached: bool = False) -> dict:
        return await export_protocol_fixture_async(self._config, instance_ids, time_ms=time_ms, cached=cached)

    def apply_plan(self, plan: dict, operation_id: str) -> dict:
        return apply_protocol_plan(self._config, plan, operation_id)

    async def apply_plan_async(self, plan: dict, operation_id: str) -> dict:
        return await apply_protocol_plan_async(self._config, plan, operation_id)

    def current_pages(self) -> "CurrentPageClient":
        """Open bounded system-selected reads using this already active profile."""
        client = CurrentPageClient.__new__(CurrentPageClient)
        client._profile = json.loads(json.dumps(self._config, ensure_ascii=True, allow_nan=False))
        return client

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
                operation_id: str | None = None,
                cancel_handle: KernelCancelHandle | None = None) -> SecureActionResult | list[PendingSecureAction]:
        if operation_id is not None:
            raise ValueError("operation_id is available only for guarded PRIVATE Owner actions")
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
               issued_at_ms: int | None = None,
               operation_id: str | None = None) -> SecureActionResult:
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
        return cast(SecureActionResult, self._action("submit", input_value=value, operation_id=operation_id))

    def reconcile(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, self._action("reconcile", command_id=command_id))

    def retry_saved(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, self._action("retry", command_id=command_id))

    def pending(self) -> list[PendingSecureAction]:
        """List protected pending IDs locally, including IDs lost to cancellation."""
        return cast(list[PendingSecureAction], self._action("pending"))

    async def _action_async(self, operation: str, *, input_value: dict | None = None,
                            command_id: str | None = None,
                            operation_id: str | None = None) -> SecureActionResult | list[PendingSecureAction]:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._action, operation, input_value=input_value,
            command_id=command_id, operation_id=operation_id, cancel_handle=cancel_handle))
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
                           issued_at_ms: int | None = None,
                           operation_id: str | None = None) -> SecureActionResult:
        value = {
            "action_id": action_id,
            "instance_id": instance_id,
            "body_json": json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "exact_input_refs_json": None if exact_input_refs is None else json.dumps(exact_input_refs, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "allocations_json": None if allocations is None else json.dumps(allocations, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "command_id": command_id,
            "issued_at_ms": issued_at_ms,
        }
        return cast(SecureActionResult, await self._action_async("submit", input_value=value, operation_id=operation_id))

    async def retry_saved_async(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, await self._action_async("retry", command_id=command_id))

    async def pending_async(self) -> list[PendingSecureAction]:
        """List protected pending IDs without a network read."""
        return cast(list[PendingSecureAction], await self._action_async("pending"))


__all__ += ["SecurePublicActionClient", "SecureActionResult", "SecureActionReceipt", "PendingSecureAction", "SecureActionError"]


class SecurePrivateActionClient(SecureReadClient):
    """Submit PRIVATE member actions using an explicit protected read profile.

    The native engine activates the selected PRIVATE workspace and persists the
    exact prepared request before POST. A guarded PRIVATE action may require a
    stable ``operation_id``; server-side role and capability checks still apply.
    """

    def _action(self, operation: str, *, input_value: dict | None = None,
                command_id: str | None = None, operation_id: str | None = None,
                cancel_handle: KernelCancelHandle | None = None) -> SecureActionResult | list[PendingSecureAction]:
        config_json = json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        input_json = None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(secure_private_action_json(
            operation, config_json, input_json, command_id, operation_id, cancel_handle))
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
               command_id: str | None = None, issued_at_ms: int | None = None,
               operation_id: str | None = None) -> SecureActionResult:
        """Prepare durably and submit one PRIVATE member action."""
        value = {
            "action_id": action_id,
            "instance_id": instance_id,
            "body_json": json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "exact_input_refs_json": None if exact_input_refs is None else json.dumps(exact_input_refs, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "allocations_json": None if allocations is None else json.dumps(allocations, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "command_id": command_id,
            "issued_at_ms": issued_at_ms,
        }
        return cast(SecureActionResult, self._action("submit", input_value=value, operation_id=operation_id))

    def reconcile(self, command_id: str) -> SecureActionResult:
        """Reconcile a saved command against a fresh signed PRIVATE replay."""
        return cast(SecureActionResult, self._action("reconcile", command_id=command_id))

    def resume(self, command_id: str) -> SecureActionResult:
        """Resume by reconciling the exact previously saved command ID."""
        return self.reconcile(command_id)

    def retry_saved(self, command_id: str) -> SecureActionResult:
        """Retry only the exact protected packet saved under ``command_id``."""
        return cast(SecureActionResult, self._action("retry", command_id=command_id))

    def pending(self) -> list[PendingSecureAction]:
        """List unresolved PRIVATE action IDs from the selected local profile."""
        return cast(list[PendingSecureAction], self._action("pending"))

    async def _action_async(self, operation: str, *, input_value: dict | None = None,
                            command_id: str | None = None,
                            operation_id: str | None = None) -> SecureActionResult | list[PendingSecureAction]:
        cancel_handle = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(
            self._action, operation, input_value=input_value,
            command_id=command_id, operation_id=operation_id, cancel_handle=cancel_handle))
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

    async def submit_async(self, action_id: str, instance_id: str, body: object, *,
                           exact_input_refs: list[object] | None = None,
                           allocations: list[object] | None = None,
                           command_id: str | None = None, issued_at_ms: int | None = None,
                           operation_id: str | None = None) -> SecureActionResult:
        value = {
            "action_id": action_id,
            "instance_id": instance_id,
            "body_json": json.dumps(body, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "exact_input_refs_json": None if exact_input_refs is None else json.dumps(exact_input_refs, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "allocations_json": None if allocations is None else json.dumps(allocations, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            "command_id": command_id,
            "issued_at_ms": issued_at_ms,
        }
        return cast(SecureActionResult, await self._action_async("submit", input_value=value, operation_id=operation_id))

    async def reconcile_async(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, await self._action_async("reconcile", command_id=command_id))

    async def resume_async(self, command_id: str) -> SecureActionResult:
        """Resume by reconciling the same durable command ID."""
        return await self.reconcile_async(command_id)

    async def retry_saved_async(self, command_id: str) -> SecureActionResult:
        return cast(SecureActionResult, await self._action_async("retry", command_id=command_id))

    async def pending_async(self) -> list[PendingSecureAction]:
        return cast(list[PendingSecureAction], await self._action_async("pending"))


__all__ += ["SecurePrivateActionClient"]


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


class LegacyRecipientImportResult(TypedDict):
    status: Literal["IMPORTED", "ALREADY_IMPORTED"]
    actor_id: str
    signing_key_id: str
    certificate_digest: str
    historical_certificates: int
    source_digest: str


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
                 allow_loopback_http: bool = False,
                 transport: TransportOptions | None = None):
        self._origin = origin
        self._state_dir = state_dir
        self._allow_loopback_http = allow_loopback_http
        self._transport = transport

    def _enroll(self, operation: str,
                cancel_handle: KernelCancelHandle | None = None, *,
                mode: str | None = None, expected_certificate_hash: str | None = None,
                update_id: str | None = None, input_value: dict | None = None) -> RecipientEnrollmentResult | LegacyRecipientImportResult | RecipientKeyUpdateResult | list[RecipientKeyUpdateResult] | str | None:
        result = json.loads(secure_recipient_enrollment_json(
            operation, self._origin, self._state_dir,
            self._allow_loopback_http, cancel_handle, mode, expected_certificate_hash, update_id,
            None if self._transport is None else json.dumps(_transport_config(self._transport),
                ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False)))
        if result["ok"] is not True:
            raise RecipientEnrollmentError(result["code"], result["message"])
        return cast(RecipientEnrollmentResult | LegacyRecipientImportResult | RecipientKeyUpdateResult | list[RecipientKeyUpdateResult] | str | None, result["value"])

    def create_local(self) -> RecipientEnrollmentResult:
        """Create or reopen protected signing and recipient keys offline."""
        return cast(RecipientEnrollmentResult, self._enroll("create_local"))

    def import_legacy_keys(self, protected_ts_state_path: str, *, expected_actor_id: str,
                           expected_signing_key_id: str, expected_source_digest: str) -> LegacyRecipientImportResult:
        """Import pinned existing member credentials offline; no membership or pending-work migration."""
        return cast(LegacyRecipientImportResult, self._enroll("import_legacy_keys", input_value=dict(
            protected_ts_state_path=protected_ts_state_path, expected_actor_id=expected_actor_id,
            expected_signing_key_id=expected_signing_key_id, expected_source_digest=expected_source_digest)))

    async def import_legacy_keys_async(self, protected_ts_state_path: str, *, expected_actor_id: str,
                                      expected_signing_key_id: str, expected_source_digest: str) -> LegacyRecipientImportResult:
        return await asyncio.to_thread(self.import_legacy_keys, protected_ts_state_path,
            expected_actor_id=expected_actor_id, expected_signing_key_id=expected_signing_key_id,
            expected_source_digest=expected_source_digest)

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

__all__ += ["SecureRecipientEnrollmentClient", "RecipientEnrollmentResult", "RecipientKeyUpdateResult", "LegacyRecipientImportResult", "RecipientEnrollmentError"]


class OwnerCoordinationProgress(TypedDict):
    status: Literal["PENDING", "ACCEPTED"]
    workspace_id: str
    version: Literal[1, 2]
    protocol_digest: str
    instance_id: str
    begin_command_id: str | None
    step_command_id: str | None
    step_action_id: str | None
    sequence: int | None
    head: str | None
    policy_hash: str | None


class OwnerWorkspaceResult(TypedDict):
    status: Literal["PENDING", "CREATED_LOCAL", "CREATED"]
    command_id: str
    workspace_id: str
    visibility: Literal["PUBLIC", "PRIVATE"]
    sequence: int | None
    head: str | None


class HistoricalCoordinationIntent(TypedDict):
    marker_key: str
    input_hash: str
    action: str
    status: Literal["ARCHIVED_COMPLETED", "RETAINED_UNRESOLVED", "RETIRED_LOCAL"]
    proof_sequence: int | None
    proof_commit_hash: str | None


class HistoricalOwnerAttachmentResult(TypedDict):
    coordination_intents: list[HistoricalCoordinationIntent]
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
    object_stage_intent_marker_hash: NotRequired[str]
    pending_object_stage_command_id: str | None
    pending_object_stage_instance_id: str | None
    pending_object_stage_status: Literal["PENDING_UNRESOLVED", "STAGE_ACCEPTED_INSTALL_PENDING", "NATIVE_BEGIN_CONTINUATION_PENDING", "ACCEPTED"] | None
    pending_object_stage_native_begin_command_id: str | None
    orphan_package_stage_command_id: str | None
    orphan_package_stage_status: Literal["ORPHAN_NO_PACKET", "REPLAN_SELECTED_UNVERIFIED", "ORPHAN_REPLANNED"] | None
    orphan_replan_stage_id: str | None
    orphan_replan_command_id: str | None


class HistoricalObjectStageIntentCandidate(TypedDict):
    workspace_id: str
    instance_id: str
    marker_hash: str
    original_command_id: str | None
    original_options_hash: str
    protocol_digest: str
    part_count: int

class HistoricalObjectStageIntentInventory(TypedDict):
    ts_state_digest: str
    marker_hash: str
    instance_id: str
    source_id: str
    protocol_digest: str
    accepted_parts: int
    part_count: int

class HistoricalObjectStagePendingInventory(TypedDict):
    ts_state_digest: str
    command_id: str
    instance_id: str
    source_id: str
    protocol_digest: str
    part_index: int
    part_count: int
    original_commit_hash: str
    original_options_hash: str
    status: Literal["PENDING_UNRESOLVED", "APPLIED_IN_SIGNED_REPLAY"]


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
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024,
                 max_replay_commits: int = 102400,
                 transport: TransportOptions | None = None):
        self._config = dict(origin=origin, state_dir=state_dir,
            allow_loopback_http=allow_loopback_http,
            max_replay_artifact_bytes=max_replay_artifact_bytes,
            max_replay_commits=_positive_u64_option("max_replay_commits", max_replay_commits))
        wire_transport = _transport_config(transport)
        if wire_transport is not None:
            self._config["transport"] = wire_transport

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

    @staticmethod
    def _marker_hash(value: str) -> str:
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("marker_hash must be the inspected lowercase SHA256, not a command ID")
        return value

    @staticmethod
    def _object_stage_intent_request(attachment_input: dict, marker_hash: str,
            expected_ts_state_digest: str | None, options_json: str, material_json: str,
            *, attach: bool) -> dict:
        value = SecureOwnerWorkspaceClient._direct_begin_request(attachment_input,
            SecureOwnerWorkspaceClient._marker_hash(marker_hash), expected_ts_state_digest,
            options_json, material_json, attach=attach)
        value["selected_marker_hash"] = value.pop("selected_command_id")
        return value

    def object_stage_intent_candidates(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str) -> list[HistoricalObjectStageIntentCandidate]:
        """Redacted protected-source candidates, not authenticated acceptance; no POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(list[HistoricalObjectStageIntentCandidate], self._owner("object_intent_candidates", input_value=value))

    def inspect_object_stage_intent(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, marker_hash: str,
            options_json: str, material_json: str) -> HistoricalObjectStageIntentInventory:
        """Verify explicit marker/options.instance_id and full material; no attach or POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._object_stage_intent_request(value, marker_hash, None,
            options_json, material_json, attach=False)
        return cast(HistoricalObjectStageIntentInventory, self._owner(
            "object_intent_inspect", input_value=request))

    def attach_object_stage_intent(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, marker_hash: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        """Protect the inspected object-stage plan without POST; recovery remains explicit."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._object_stage_intent_request(value, marker_hash,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "object_intent_attach", input_value=request))

    def recover_object_stage_intent(self, attach_id: str,
            marker_hash: str) -> HistoricalOwnerAttachmentResult:
        """Recover the protected marker selection; never reconstruct a missing original packet."""
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "object_intent_recover", command_id=self._marker_hash(marker_hash),
            workspace_id=attach_id))

    def inspect_pending_object_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            options_json: str, material_json: str) -> HistoricalObjectStagePendingInventory:
        """Verify one selected final object-stage packet and full author material; no POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalObjectStagePendingInventory, self._owner(
            "object_stage_inspect", input_value=request))

    def attach_pending_object_stage(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        """Protect the inspected object-stage plan without POST; recovery remains explicit."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "object_stage_attach", input_value=request))

    def recover_pending_object_stage(self, attach_id: str,
            expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        """Reconcile the original stage; explicitly finish its distinct native installation."""
        return cast(HistoricalOwnerAttachmentResult, self._owner(
            "object_stage_recover", command_id=expected_command_id,
            workspace_id=attach_id))

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

    def retire_coordination_intent(self, attach_id: str, marker_key: str,
                                   expected_input_hash: str) -> HistoricalOwnerAttachmentResult:
        """Retire only a retained local marker; no message or cancellation is sent."""
        return cast(HistoricalOwnerAttachmentResult, self._owner("coordination_marker_retire",
            input_value=dict(attach_id=attach_id, marker_key=marker_key,
                             expected_input_hash=expected_input_hash)))

    async def retire_coordination_intent_async(self, attach_id: str, marker_key: str,
                                               expected_input_hash: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(self._owner,
            "coordination_marker_retire", input_value=dict(attach_id=attach_id,
                marker_key=marker_key, expected_input_hash=expected_input_hash)))

    def attachments(self) -> list[HistoricalOwnerAttachmentResult]:
        """Protected local attachment history; PREPARED is not remote acceptance."""
        return cast(list[HistoricalOwnerAttachmentResult], self._owner("attachments"))

    @staticmethod
    def _coordination_input(version: int | None, participants: list[str] | None) -> dict:
        if version is not None and (type(version) is not int or version not in (1, 2)):
            raise TypeError("coordination version must be 1 or 2")
        if participants is not None and (not isinstance(participants, list) or
                any(not isinstance(actor, str) or not actor for actor in participants)):
            raise TypeError("participants must be a list of nonempty actor IDs")
        return dict(version=version, participants=participants)

    def enable_coordination(self, workspace_id: str, *, version: int | None = None,
                            participants: list[str] | None = None) -> OwnerCoordinationProgress:
        """Enable/upgrade dedicated coordination, advancing at most one saved step.

        Omitted version defaults to v1. Omitted participants and an explicit empty
        list remain distinct inputs: omission uses Owner on a new installation,
        but requests no participant grant check when already enabled. [] explicitly
        requests Owner and is checked on the already-enabled path too.
        PENDING requires discovery/resume with the original BEGIN ID.
        """
        return cast(OwnerCoordinationProgress, self._owner("coordination_enable",
            workspace_id=workspace_id, input_value=self._coordination_input(version, participants)))

    def resume_coordination(self, workspace_id: str, begin_command_id: str) -> OwnerCoordinationProgress:
        return cast(OwnerCoordinationProgress, self._owner("coordination_resume",
            workspace_id=workspace_id, command_id=begin_command_id))

    def coordination_operations(self, workspace_id: str) -> list[OwnerCoordinationProgress]:
        """Protected local operations; this does not refresh remote acceptance."""
        return cast(list[OwnerCoordinationProgress], self._owner("coordination_operations",
            workspace_id=workspace_id))

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

    def member_scopes(self, workspace_id: str) -> "OwnerWorkspaceMemberScopesClient":
        return OwnerWorkspaceMemberScopesClient(self._config, workspace_id)

    def guard_time(self, workspace_id: str) -> "OwnerWorkspaceGuardTimeClient":
        """Owner-signed guard-time activation with explicit pins, consent and durable recovery."""
        return OwnerWorkspaceGuardTimeClient(self._config, workspace_id)

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

    async def object_stage_intent_candidates_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str) -> list[HistoricalObjectStageIntentCandidate]:
        """Redacted protected-source candidates, not authenticated acceptance; no POST."""
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        return cast(list[HistoricalObjectStageIntentCandidate], await _run_cancelled_async(self._owner, "object_intent_candidates", input_value=value))

    async def inspect_object_stage_intent_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, marker_hash: str,
            options_json: str, material_json: str) -> HistoricalObjectStageIntentInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._object_stage_intent_request(value, marker_hash, None,
            options_json, material_json, attach=False)
        return cast(HistoricalObjectStageIntentInventory, await _run_cancelled_async(
            self._owner, "object_intent_inspect", input_value=request))

    async def attach_object_stage_intent_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, marker_hash: str,
            expected_ts_state_digest: str, options_json: str,
            material_json: str) -> HistoricalOwnerAttachmentResult:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._object_stage_intent_request(value, marker_hash,
            expected_ts_state_digest, options_json, material_json, attach=True)
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "object_intent_attach", input_value=request))

    async def recover_object_stage_intent_async(self, attach_id: str,
            marker_hash: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "object_intent_recover", command_id=self._marker_hash(marker_hash),
            workspace_id=attach_id))

    async def inspect_pending_object_stage_async(self, workspace_id: str,
            protected_ts_state_path: str, protected_ts_intent_db_path: str,
            protected_owner_pkcs8_path: str, expected_owner_actor_id: str,
            expected_owner_key_id: str, selected_command_id: str,
            options_json: str, material_json: str) -> HistoricalObjectStagePendingInventory:
        value = self._attachment_input(workspace_id, protected_ts_state_path,
            protected_ts_intent_db_path, protected_owner_pkcs8_path,
            expected_owner_actor_id, expected_owner_key_id)
        request = self._direct_begin_request(value, selected_command_id, None,
            options_json, material_json, attach=False)
        return cast(HistoricalObjectStagePendingInventory, await _run_cancelled_async(
            self._owner, "object_stage_inspect", input_value=request))

    async def attach_pending_object_stage_async(self, workspace_id: str,
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
            self._owner, "object_stage_attach", input_value=request))

    async def recover_pending_object_stage_async(self, attach_id: str,
            expected_command_id: str) -> HistoricalOwnerAttachmentResult:
        return cast(HistoricalOwnerAttachmentResult, await _run_cancelled_async(
            self._owner, "object_stage_recover", command_id=expected_command_id,
            workspace_id=attach_id))

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

    async def enable_coordination_async(self, workspace_id: str, *, version: int | None = None,
                                        participants: list[str] | None = None) -> OwnerCoordinationProgress:
        value = self._coordination_input(version, participants)
        return cast(OwnerCoordinationProgress, await _run_cancelled_async(self._owner,
            "coordination_enable", workspace_id=workspace_id, input_value=value))

    async def resume_coordination_async(self, workspace_id: str, begin_command_id: str) -> OwnerCoordinationProgress:
        return cast(OwnerCoordinationProgress, await _run_cancelled_async(self._owner,
            "coordination_resume", workspace_id=workspace_id, command_id=begin_command_id))

    async def coordination_operations_async(self, workspace_id: str) -> list[OwnerCoordinationProgress]:
        return cast(list[OwnerCoordinationProgress], await _run_cancelled_async(self._owner,
            "coordination_operations", workspace_id=workspace_id))

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
                operation_id: str | None = None,
                cancel_handle: KernelCancelHandle | None = None) -> SecureActionResult | list[PendingSecureAction]:
        if operation_id is not None and (self._kind != "private_action" or not isinstance(operation_id, str) or len(operation_id) != 43 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in operation_id)):
            raise ValueError("operation_id must be a 43-character stable ID for PRIVATE Owner actions")
        result = json.loads(secure_owner_consumer_json(self._kind, operation,
            json.dumps(self._owner_config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            self._workspace_id,
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            command_id, cancel_handle, operation_id))
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
    step_action_id: Literal["secure.protocol-object.stage", "secure.structure.begin", "secure.structure.page", "secure.structure.end"]
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
    phase: NotRequired[Literal["OBJECT_STAGING"]]
    saved_steps: NotRequired[int]
    recovered_by: NotRequired[str]


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


# Functional syntax retains the wire key "class", a Python reserved word.
PrivateInstallDiagnostic = TypedDict("PrivateInstallDiagnostic", {
    "schema": Literal["peerwork.install-diagnostic.v1"],
    "begin_command_id": str,
    "verified": bool,
    "submitted": Literal[False],
    "prior_sequence": NotRequired[int],
    "fresh_sequence": NotRequired[int],
    "structure_state": NotRequired[str],
    "begin_in_verified_history": NotRequired[bool],
    "code": NotRequired[Literal["VERIFICATION_FAILED"]],
    "stage": NotRequired[str],
    "class": NotRequired[str],
    "check": NotRequired[str],
    "sequence": NotRequired[int | None],
})


class PrivateInstallRecoveryPlan(TypedDict):
    schema: Literal["peerwork.install-recovery-plan.v1"]
    original_begin_id: str
    review_hash: str
    submitted: Literal[False]
    recovery: NotRequired[dict[str, JSONValue]]
    target_structure_hash: NotRequired[str]
    new_begin_required: NotRequired[Literal[True]]
    status: NotRequired[Literal["RECOVERED", "PENDING"]]
    operation_id: NotRequired[str]


class PrivateInstallRecoveryProgress(TypedDict):
    schema: Literal["peerwork.install-recovery-progress.v1"]
    original_begin_id: str
    operation_id: str
    status: Literal["PENDING", "ACCEPTED"]
    phase: Literal["RECOVERY", "SNAPSHOT", "ACTIVE"]
    new_begin_required: Literal[True]


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
                 cancel_handle: KernelCancelHandle | None = None) -> PrivatePackageInstallProgress | list[SavedPrivatePackageInstall] | PrivateInstallDiagnostic | PrivateInstallRecoveryPlan | PrivateInstallRecoveryProgress:
        required = ("private_install_auto_transport" if operation in ("begin", "begin_direct", "continue", "installs")
                    else "private_install_reviewed_recovery")
        if required is not None and not capabilities().get(required, False):
            raise PrivatePackageInstallError("SDK_NATIVE_VERSION_MISMATCH",
                "Install the matching Python wrapper and native extension from one SDK release archive")
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

    def diagnose(self, begin_command_id: str) -> PrivateInstallDiagnostic:
        """Verify the candidate without signing, POSTing or replacing ACTIVE."""
        return cast(PrivateInstallDiagnostic, self._install("diagnose", begin_command_id=begin_command_id))

    def recovery_plan(self, begin_command_id: str) -> PrivateInstallRecoveryPlan:
        """Read-only reviewed range; never exports private record bodies or keys."""
        return cast(PrivateInstallRecoveryPlan, self._install("recovery_plan", begin_command_id=begin_command_id))

    def recover_invalid(self, begin_command_id: str, *, expected_review_hash: str,
                        operation_id: str) -> PrivateInstallRecoveryProgress:
        return cast(PrivateInstallRecoveryProgress, self._install("recover_invalid", input_value={
            "begin_command_id": begin_command_id, "expected_review_hash": expected_review_hash,
            "operation_id": operation_id}))

    async def recovery_plan_async(self, begin_command_id: str) -> PrivateInstallRecoveryPlan:
        return cast(PrivateInstallRecoveryPlan, await _run_cancelled_async(self._install,
            "recovery_plan", begin_command_id=begin_command_id))

    async def recover_invalid_async(self, begin_command_id: str, *, expected_review_hash: str,
                                    operation_id: str) -> PrivateInstallRecoveryProgress:
        return cast(PrivateInstallRecoveryProgress, await _run_cancelled_async(self._install,
            "recover_invalid", input_value={"begin_command_id": begin_command_id,
            "expected_review_hash": expected_review_hash, "operation_id": operation_id}))

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

    async def diagnose_async(self, begin_command_id: str) -> PrivateInstallDiagnostic:
        return cast(PrivateInstallDiagnostic, await _run_cancelled_async(self._install,
            "diagnose", begin_command_id=begin_command_id))

    async def installs_async(self) -> list[SavedPrivatePackageInstall]:
        return cast(list[SavedPrivatePackageInstall], await _run_cancelled_async(self._install,
            "installs"))


__all__ += ["HistoricalObjectStagePendingInventory", "HistoricalObjectStageIntentCandidate", "HistoricalObjectStageIntentInventory", "HistoricalDirectInstallPendingInventory", "HistoricalDirectInstallCompletedInventory"]
__all__ += ["SecureOwnerWorkspaceClient", "OwnerCoordinationProgress", "OwnerWorkspaceResult", "HistoricalOwnerAttachmentResult", "HistoricalKernelCommandStatus", "HistoricalKernelPendingInventory", "HistoricalPackageStagePendingInventory", "OwnerFormatTransitionResult", "OwnerWorkspaceError",
            "OwnerWorkspaceActionClient", "OwnerWorkspacePackageInstaller",
            "OwnerWorkspacePrivatePackageStager", "PrivatePackageStageResult",
            "SavedPrivatePackageStage", "PrivatePackageStageError",
            "OwnerWorkspacePrivatePackageInstaller", "PrivatePackageInstallProgress",
            "SavedPrivatePackageInstall", "PrivateFieldDisclosure", "PrivatePackageInstallError", "PrivateInstallDiagnostic", "PrivateInstallRecoveryPlan", "PrivateInstallRecoveryProgress"]


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
                 allow_loopback_http: bool = False,
                 transport: TransportOptions | None = None):
        if not origin or not state_dir:
            raise ValueError("origin and state directory are required")
        self._origin = origin
        self._state_dir = state_dir
        self._identity_path = identity_path or str(Path(state_dir) / "identity.state")
        self._allow_loopback_http = allow_loopback_http
        self._transport = transport

    def _lookup(self, actor_id: str, signing_key_id: str,
                cancel_handle: KernelCancelHandle | None = None) -> VerifiedIdentityCertificate:
        if not actor_id or not signing_key_id:
            raise ValueError("explicit peer actor and signing key pins are required")
        result = json.loads(secure_identity_directory_json(
            self._origin, self._state_dir, self._identity_path,
            actor_id, signing_key_id, self._allow_loopback_http, cancel_handle,
            None if self._transport is None else json.dumps(_transport_config(self._transport),
                ensure_ascii=True, allow_nan=False, separators=(",", ":"))))
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
                 max_listing_bytes: int | None = None,
                 transport: TransportOptions | None = None):
        self._config = dict(origin=origin, allow_loopback_http=allow_loopback_http,
                            max_listing_bytes=max_listing_bytes)
        wire_transport = _transport_config(transport)
        if wire_transport is not None:
            self._config["transport"] = wire_transport

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
                 max_replay_artifact_bytes: int = 64 * 1024 * 1024,
                 max_replay_commits: int = 102400,
                 transport: TransportOptions | None = None):
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
        self._config["max_replay_commits"] = _positive_u64_option("max_replay_commits", max_replay_commits)
        wire_transport = _transport_config(transport)
        if wire_transport is not None:
            self._config["transport"] = wire_transport

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


class ObservationEvidence(TypedDict):
    status: Literal["unknown", "claimed", "checked"]
    reference: str | None


class ObservationRelease(TypedDict):
    catalog_origin: str
    namespace: str | None
    package_id: str
    version: str
    bundle_digest: str


class AcquisitionEvent(TypedDict):
    event_id: str
    occurred_at: int
    environment: Literal["production", "staging", "local_test"]
    audience_class: Literal["official_seed", "operator_synthetic", "external_evidenced", "unknown"]
    principal_ref: str | None
    principal_binding: ObservationEvidence
    external_status_evidence: NotRequired[ObservationEvidence | None]
    newness: Literal["proved_new", "first_observed", "existing", "unknown"]
    newness_evidence: ObservationEvidence
    journey_id: str
    task_ref: str | None
    logical_operation_id: str
    attempt_id: str
    event_type: Literal["qualified_start", "discovery_observed", "release_verified", "adoption_selected",
        "install_accepted", "task_outcome_verified", "publish_requested", "publish_accepted", "release_visible",
        "share_reference_observed", "attempt_finished", "coverage_ended", "correction", "withdrawal"]
    outcome: Literal["pass", "fail", "pending", "unverified"]
    attempt_class: Literal["first_attempt", "recovery", "redundant", "unknown"]
    evidence: ObservationEvidence
    observer: str
    observer_version: str
    release: NotRequired[ObservationRelease | None]
    protocol_digest: NotRequired[str | None]
    protocol_ref: NotRequired[str | None]
    instance_ref: NotRequired[str | None]
    association_evidence: NotRequired[ObservationEvidence | None]
    adoption_branch: NotRequired[Literal["new_install", "existing_install"] | None]
    acceptance_predicate_ref: NotRequired[str | None]
    signed_result_evidence: NotRequired[ObservationEvidence | None]
    enrollment_timing_evidence: NotRequired[ObservationEvidence | None]
    source_channel: NotRequired[Literal["mcp_search", "agent_entry", "canonical_share", "repository_release", "direct", "unknown"] | None]
    source_ref: NotRequired[str | None]
    source_evidence: NotRequired[ObservationEvidence | None]
    referrer_principal_ref: NotRequired[str | None]
    referrer_audience_class: NotRequired[Literal["official_seed", "operator_synthetic", "external_evidenced", "unknown"] | None]
    referrer_binding: NotRequired[ObservationEvidence | None]
    referrer_external_status_evidence: NotRequired[ObservationEvidence | None]
    distinct_controller_evidence: NotRequired[ObservationEvidence | None]
    publisher_principal_ref: NotRequired[str | None]
    error_code: NotRequired[str | None]
    active_execution_ms: NotRequired[int | None]
    external_wait_ms: NotRequired[int | None]
    calls: NotRequired[int | None]
    tokens: NotRequired[int | None]
    cost: NotRequired[dict | None]
    observation_end: NotRequired[int | None]
    coverage: NotRequired[Literal["complete", "lost", "unknown"] | None]
    run_kind: NotRequired[Literal["natural_agent", "scripted", "unknown"] | None]
    workflow_outcome: NotRequired[Literal["pass", "fail", "pending", "unverified"] | None]
    supersedes: NotRequired[str | None]
    client_ref: NotRequired[str | None]
    client_version: NotRequired[str | None]
    model_ref: NotRequired[str | None]
    model_version: NotRequired[str | None]
    instruction_ref: NotRequired[str | None]
    instruction_version: NotRequired[str | None]
    variant_ref: NotRequired[str | None]
    source_release: NotRequired[ObservationRelease | None]
    lineage_evidence: NotRequired[ObservationEvidence | None]


class AcquisitionAppendResult(TypedDict):
    event_id: str
    disposition: Literal["APPENDED", "DUPLICATE", "CONFLICT"]
    observed_at: int
    payload_sha256: str
    records: int


class ExternalPrincipalAttestation(TypedDict):
    attestation_id: str
    principal_ref: str
    binding_evidence_ref: str
    external_status_evidence_ref: str
    observer: str
    observer_version: str
    statement: Literal["observer_checked_external_principal_binding"]
    evidence_basis: Literal["consented_controller_grouping", "public_controller_evidence"]


class AcquisitionInstallObservation(TypedDict):
    event: AcquisitionEvent
    closure_json: str
    bindings_json: NotRequired[str | None]
    expected_package_id: str
    expected_package_version: str
    expected_package_digest: str
    expected_protocol_digest: str
    selected_instance_id: str
    result_package_digest: str | None
    result_protocol_digest: str
    result_instance_id: str
    result_status: Literal["SELECTED", "ACTIVE", "ACCEPTED"]
    result_step_action_id: str | None
    result_commit_hash: str | None


class RecordedAcquisitionObservation(TypedDict):
    event: AcquisitionEvent
    observed_at: int
    payload_sha256: str


class RecordedExternalPrincipalAttestation(TypedDict):
    attestation: ExternalPrincipalAttestation
    observed_at: int
    payload_sha256: str


AcquisitionScorecardWindow = TypedDict("AcquisitionScorecardWindow", {"from": int, "to_exclusive": int, "as_of": int})


class AcquisitionMetric(TypedDict):
    id: str
    value: JSONValue
    numerator: int | None
    denominator: int | None
    mature_cohort_size: int
    pending: int
    lost: int
    unknown: int
    details: JSONValue


class AcquisitionScorecard(TypedDict):
    definition_version: int
    window: AcquisitionScorecardWindow
    window_complete: bool
    snapshot_sha256: str
    visible_observations: int
    excluded_synthetic_seed: int
    unknown_audience_binding: int
    conflicting_events: int
    metrics: list[AcquisitionMetric]
    coverage_scope: str


class StoredAcquisitionScorecard(TypedDict):
    generated_at: int
    scorecard: AcquisitionScorecard


class AcquisitionObservationError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AcquisitionObservations:
    """Explicit protected local observations; no telemetry or business calls.

    Proof adapters preserve observer evidence judgments. Arbitrary result DTOs
    do not authenticate external controllers. Async cancellation drains atomic
    local work before raising; reopen/export to discover its disposition.
    """
    def __init__(self, path: str, *, max_records: int | None = None,
                 max_store_bytes: int | None = None):
        self._config = dict(path=path, max_records=max_records, max_store_bytes=max_store_bytes)

    def _call(self, operation: str, *, input_value: dict | None = None,
              cancel_handle: KernelCancelHandle | None = None):
        result = json.loads(acquisition_observations_json(operation,
            json.dumps(self._config, ensure_ascii=True, allow_nan=False, separators=(",", ":")),
            None if input_value is None else json.dumps(input_value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))))
        if result["ok"] is not True:
            raise AcquisitionObservationError(result["code"], result["message"])
        return result["value"]

    def attest_external_principal(self, attestation: ExternalPrincipalAttestation) -> AcquisitionAppendResult:
        """Explicit observer decision; does not independently prove a controller."""
        return self._call("attest_external_principal", input_value=attestation)

    async def attest_external_principal_async(self, attestation: ExternalPrincipalAttestation) -> AcquisitionAppendResult:
        return await _run_cancelled_async(self._call, "attest_external_principal", input_value=attestation)

    def attestations(self) -> list[RecordedExternalPrincipalAttestation]:
        return self._call("attestations")

    async def attestations_async(self) -> list[RecordedExternalPrincipalAttestation]:
        return await _run_cancelled_async(self._call, "attestations")

    def append(self, event: AcquisitionEvent) -> AcquisitionAppendResult:
        return self._call("append", input_value=event)

    async def append_async(self, event: AcquisitionEvent) -> AcquisitionAppendResult:
        return await _run_cancelled_async(self._call, "append", input_value=event)

    def export(self) -> list[RecordedAcquisitionObservation]:
        return self._call("export")

    async def export_async(self) -> list[RecordedAcquisitionObservation]:
        return await _run_cancelled_async(self._call, "export")

    def snapshots(self) -> list[StoredAcquisitionScorecard]:
        return self._call("snapshots")

    async def snapshots_async(self) -> list[StoredAcquisitionScorecard]:
        return await _run_cancelled_async(self._call, "snapshots")

    def scorecard(self, *, from_ms: int, to_exclusive: int, as_of: int) -> StoredAcquisitionScorecard:
        return self._call("scorecard", input_value=dict(**{"from":from_ms}, to_exclusive=to_exclusive, as_of=as_of))

    async def scorecard_async(self, *, from_ms: int, to_exclusive: int, as_of: int) -> StoredAcquisitionScorecard:
        return await _run_cancelled_async(self._call, "scorecard",
            input_value=dict(**{"from":from_ms}, to_exclusive=to_exclusive, as_of=as_of))

    @staticmethod
    def _catalog_input(event: AcquisitionEvent, result: InspectedPublicPackage) -> dict:
        return dict(event=event, catalog_origin=result["catalog_origin"],
            bundle_digest=result["bundle_digest"], bundle_canonical_json=result["bundle_canonical_json"])

    def record_catalog_result(self, event: AcquisitionEvent, result: InspectedPublicPackage) -> AcquisitionAppendResult:
        return self._call("catalog_result", input_value=self._catalog_input(event, result))

    async def record_catalog_result_async(self, event: AcquisitionEvent, result: InspectedPublicPackage) -> AcquisitionAppendResult:
        return await _run_cancelled_async(self._call, "catalog_result", input_value=self._catalog_input(event, result))

    def record_install_result(self, input_value: AcquisitionInstallObservation) -> AcquisitionAppendResult:
        """Strict minimized source selection/progress DTO; full receipts are rejected."""
        return self._call("install_result", input_value=input_value)

    async def record_install_result_async(self, input_value: AcquisitionInstallObservation) -> AcquisitionAppendResult:
        return await _run_cancelled_async(self._call, "install_result", input_value=input_value)

    @staticmethod
    def _action_input(event: AcquisitionEvent, selected_instance_id: str,
                      result_instance_id: str, result: SecureActionResult) -> dict:
        return dict(event=event, selected_instance_id=selected_instance_id,
            result_instance_id=result_instance_id, result_status=result["status"],
            result_command_id=result["command_id"], result_commit_hash=result.get("commit_hash"),
            result_sequence=result.get("sequence"))

    def record_action_result(self, event: AcquisitionEvent, selected_instance_id: str,
                             result_instance_id: str, result: SecureActionResult) -> AcquisitionAppendResult:
        return self._call("action_result", input_value=self._action_input(event, selected_instance_id, result_instance_id, result))

    async def record_action_result_async(self, event: AcquisitionEvent, selected_instance_id: str,
                                        result_instance_id: str, result: SecureActionResult) -> AcquisitionAppendResult:
        return await _run_cancelled_async(self._call, "action_result",
            input_value=self._action_input(event, selected_instance_id, result_instance_id, result))


__all__ += ["AcquisitionObservations", "AcquisitionEvent", "AcquisitionAppendResult",
            "AcquisitionObservationError", "ObservationEvidence", "ObservationRelease",
            "ExternalPrincipalAttestation", "AcquisitionInstallObservation", "RecordedAcquisitionObservation",
            "RecordedExternalPrincipalAttestation", "AcquisitionMetric", "AcquisitionScorecard",
            "StoredAcquisitionScorecard", "AcquisitionScorecardWindow"]

__all__ += ["KernelError"]


class AgentProtocolActionIntent(TypedDict):
    document_times: NotRequired[list[JSONValue]]
    plaintext_contents: NotRequired[list[JSONValue]]
    kind: Literal["protocol.action"]
    instance_id: str
    action_id: str
    values: JSONValue
    refs: NotRequired[list[JSONValue]]
    protocol_digest: NotRequired[str]
    expected_instance_revision: NotRequired[int]
    contents: NotRequired[list[JSONValue]]


class AgentStructureIntent(TypedDict):
    kind: Literal["structure.intent"]
    request: dict


class AgentBrowserApprovalIntent(TypedDict):
    kind: Literal["browser.approve"]
    reference: str
    approve_writes: bool


class AgentInvitationFinalizeIntent(TypedDict):
    kind: Literal["workspace.invitation.finalize"]
    invite_id: str
    saved_grant_id: NotRequired[str]


AgentIntent: TypeAlias = AgentProtocolActionIntent | AgentBrowserApprovalIntent | AgentInvitationFinalizeIntent | AgentStructureIntent


class AgentContextError(RuntimeError):
    """Native context refusal, retaining safe recovery/effect-certainty details."""

    def __init__(self, envelope: dict):
        super().__init__(envelope["message"])
        self.envelope = envelope
        self.operation_id = envelope.get("operation_id")
        self.code = envelope["code"]
        self.layer = envelope.get("layer")
        self.effect_certainty = envelope.get("effect_certainty")
        self.continuation = envelope.get("continuation")
        self.stage = envelope.get("stage")
        self.server_code = envelope.get("server_code")
        self.http_status = envelope.get("http_status")
        self.constraint = envelope.get("constraint")
        self.retryability = envelope.get("retryability")
        self.recovery_hints = envelope.get("recovery_hints")


@dataclass(frozen=True, repr=False)
class AgentContext:
    """Pinned existing PRIVATE member context; no identity creation or enrollment.

    v1 retains encrypted-history replay and existing operation producers.
    Explicit v2 contexts execute and query backend-maintained structure with
    service and author proofs. They never load the legacy workspace journal.
    """

    _profile: str
    _expected_actor: str
    _expected_service: str
    _descriptor_json: str

    @property
    def descriptor(self) -> dict:
        """Return a safe descriptor copy, never keys or protected state paths."""
        return json.loads(self._descriptor_json)

    def _call(self, operation: str, request: dict | None = None,
              cancel_handle: KernelCancelHandle | None = None) -> dict:
        if request is not None:
            request = dict(request, expected_fingerprint=self.descriptor["fingerprint"])
        wire = None if request is None else json.dumps(
            request, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        result = json.loads(agent_context_json(operation, self._profile,
            self._expected_actor, self._expected_service, wire, cancel_handle))
        if result["ok"] is not True:
            raise AgentContextError(result)
        return result["value"]

    def discover(self, workspace_id: str, *, after: str | None = None, limit: int | None = None) -> dict:
        """Verified installed protocol/action index; permission summaries are advisory."""
        return self._call("discover", self._discovery_request(workspace_id, after, limit))

    @staticmethod
    def _discovery_request(workspace_id: str, after: str | None, limit: int | None) -> dict:
        query = {key: value for key, value in {"after": after, "limit": limit}.items() if value is not None}
        return {"workspace_id": workspace_id, "query": query}

    @staticmethod
    def _description_request(workspace_id: str, instance_id: str | None, action_id: str | None,
                             record_id: str | None, revision: int | None, object_ref: dict | None,
                             protocol_digest: str | None = None) -> dict:
        query = {key: value for key, value in {
            "instance_id": instance_id, "action_id": action_id, "record_id": record_id,
            "revision": revision, "object_ref": object_ref, "protocol_digest": protocol_digest,
        }.items() if value is not None}
        return {"workspace_id": workspace_id, "query": query}

    def describe(self, workspace_id: str, instance_id: str | None = None, *,
                 action_id: str | None = None, record_id: str | None = None,
                 revision: int | None = None, object_ref: dict | None = None,
                 protocol_digest: str | None = None) -> dict:
        """Describe one instance/action or exact record/object revision; no latest substitution."""
        return self._call("describe", self._description_request(
            workspace_id, instance_id, action_id, record_id, revision, object_ref, protocol_digest))

    async def discover_async(self, workspace_id: str, *, after: str | None = None, limit: int | None = None) -> dict:
        return await self._call_async("discover", self._discovery_request(workspace_id, after, limit))

    async def describe_async(self, workspace_id: str, instance_id: str | None = None, *,
                             action_id: str | None = None, record_id: str | None = None,
                             revision: int | None = None, object_ref: dict | None = None,
                             protocol_digest: str | None = None) -> dict:
        return await self._call_async("describe", self._description_request(
            workspace_id, instance_id, action_id, record_id, revision, object_ref, protocol_digest))

    def inspect(self, workspace_id: str) -> dict:
        return self._call("inspect", {"workspace_id": workspace_id})

    def request_access(self, workspace_id: str, selection: dict) -> dict:
        return self._call("request.access", {"workspace_id": workspace_id, "query": selection})

    def authorize_access(self, workspace_id: str, selection: dict) -> dict:
        return self._call("authorize.access", {"workspace_id": workspace_id, "query": selection})

    def publish_selected_record(self, workspace_id: str, selection: dict) -> dict:
        """Publish one verified selected record into an already-public Owner view."""
        return self._call("publish.record", {"workspace_id": workspace_id, "query": selection})

    async def publish_selected_record_async(self, workspace_id: str, selection: dict) -> dict:
        return await self._call_async("publish.record", {"workspace_id": workspace_id, "query": selection})

    def coordinate_content_keys(self, workspace_id: str) -> dict:
        return self._call("coordinate.keys", {"workspace_id": workspace_id, "query": {}})

    async def coordinate_content_keys_async(self, workspace_id: str) -> dict:
        return await self._call_async("coordinate.keys", {"workspace_id": workspace_id, "query": {}})

    def rotate_content_key(self, workspace_id: str, selection: dict) -> dict:
        return self._call("rotate.key", {"workspace_id": workspace_id, "query": selection})

    async def rotate_content_key_async(self, workspace_id: str, selection: dict) -> dict:
        return await self._call_async("rotate.key", {"workspace_id": workspace_id, "query": selection})

    def accept_content_keys(self, workspace_id: str, selection: dict) -> dict:
        return self._call("accept.keys", {"workspace_id": workspace_id, "query": selection})

    async def request_access_async(self, workspace_id: str, selection: dict) -> dict:
        return await self._call_async("request.access", {"workspace_id": workspace_id, "query": selection})

    async def authorize_access_async(self, workspace_id: str, selection: dict) -> dict:
        return await self._call_async("authorize.access", {"workspace_id": workspace_id, "query": selection})

    async def accept_content_keys_async(self, workspace_id: str, selection: dict) -> dict:
        return await self._call_async("accept.keys", {"workspace_id": workspace_id, "query": selection})

    def execute_structure_intent(self, workspace_id: str, intent: dict) -> dict:
        """v2: execute a selected backend intent without replaying workspace history."""
        return self._call("execute.structure", {"workspace_id": workspace_id, "intent": intent})

    async def execute_structure_intent_async(self, workspace_id: str, intent: dict) -> dict:
        return await self._call_async("execute.structure", {"workspace_id": workspace_id, "intent": intent})

    @staticmethod
    def _follow_request(workspace_id: str, operation: dict) -> dict:
        selected = dict(operation)
        if selected.get("kind") == "WORKSPACE_DELETE":
            return {"workspace_id": workspace_id, "intent": {"action": "structure.workspace.deletion.get",
                "workspace_id": selected.get("workspace_id", workspace_id), "body": {"command_id": selected["command_id"]}}}
        return {"workspace_id": workspace_id, "intent": {"action": "structure.maintenance.get",
            "workspace_id": selected.get("workspace_id", workspace_id), "instance_id": selected["instance_id"],
            "protocol_digest": selected["protocol_digest"], "body": {"job_id": selected["job_id"]}}}

    def follow_operation(self, workspace_id: str, operation: dict) -> dict:
        """Follow backend progress without importing or resubmitting the original mutation."""
        return self._call("follow.operation", self._follow_request(workspace_id, operation))

    async def follow_operation_async(self, workspace_id: str, operation: dict) -> dict:
        return await self._call_async("follow.operation", self._follow_request(workspace_id, operation))

    def operate(self, workspace_id: str, intent: AgentIntent, operation_id: str) -> dict:
        return self._call("operate", {"workspace_id": workspace_id,
            "intent": intent, "operation_id": operation_id})

    def recover(self, workspace_id: str, *, operation_id: str | None = None,
                command_id: str | None = None, recovery: dict | None = None) -> dict:
        request = self._recovery_request(workspace_id, operation_id, command_id)
        if recovery is not None:
            request["recovery"] = recovery
        return self._call("recover", request)

    @staticmethod
    def _recovery_request(workspace_id: str, operation_id: str | None,
                          command_id: str | None) -> dict:
        request = {"workspace_id": workspace_id}
        if operation_id is not None:
            request["operation_id"] = operation_id
        if command_id is not None:
            request["command_id"] = command_id
        return request

    def export_fixture(self, workspace_id: str, instance_ids: list[str], *,
                       time_ms: int, cached: bool = False) -> dict:
        """Export selected verified instances using this pinned existing identity."""
        request = {"instance_ids": instance_ids, "time_ms": time_ms, "cached": cached}
        result = self._call("workbench.export", {"workspace_id": workspace_id,
            "workbench_input": json.dumps(request, ensure_ascii=True, allow_nan=False)})
        return json.loads(result["result"]["workbench_json"])

    def apply_plan(self, workspace_id: str, plan: dict | None, operation_id: str) -> dict:
        """Revalidate a fixed plan and resume the same durable operation on retry."""
        request = {"operation_id": operation_id}
        if plan is not None:
            request["plan"] = plan
        result = self._call("workbench.apply", {"workspace_id": workspace_id,
            "workbench_input": json.dumps(request, ensure_ascii=True, allow_nan=False)})
        return json.loads(result["result"]["workbench_json"])

    async def export_fixture_async(self, workspace_id: str, instance_ids: list[str], *,
                                   time_ms: int, cached: bool = False) -> dict:
        request = {"instance_ids": instance_ids, "time_ms": time_ms, "cached": cached}
        result = await self._call_async("workbench.export", {"workspace_id": workspace_id,
            "workbench_input": json.dumps(request, ensure_ascii=True, allow_nan=False)})
        return json.loads(result["result"]["workbench_json"])

    async def apply_plan_async(self, workspace_id: str, plan: dict | None, operation_id: str) -> dict:
        request = {"operation_id": operation_id}
        if plan is not None:
            request["plan"] = plan
        result = await self._call_async("workbench.apply", {"workspace_id": workspace_id,
            "workbench_input": json.dumps(request, ensure_ascii=True, allow_nan=False)})
        return json.loads(result["result"]["workbench_json"])

    def resume_plan(self, workspace_id: str, operation_id: str) -> dict:
        """Explicitly continue the original protected saved plan; this can submit steps."""
        return self.apply_plan(workspace_id, None, operation_id)

    async def resume_plan_async(self, workspace_id: str, operation_id: str) -> dict:
        return await self.apply_plan_async(workspace_id, None, operation_id)

    def operations(self, workspace_id: str, *, after: str | None = None, limit: int | None = None,
                   scope: Literal["MINE", "WORKSPACE"] | None = None, view: Literal["OPEN", "HISTORY"] | None = None) -> dict:
        """v2: bounded backend operation page, MINE/OPEN by default."""
        return self._call("operations", self._operations_request(workspace_id, after, limit, scope, view))

    @staticmethod
    def _operations_request(workspace_id: str, after: str | None, limit: int | None, scope: str | None, view: str | None) -> dict:
        query = {key: value for key, value in {"after": after, "limit": limit, "scope": scope, "view": view}.items() if value is not None}
        return {"workspace_id": workspace_id, **({"query": query} if query else {})}

    @staticmethod
    def _event_request(workspace_id: str, **options) -> dict:
        return {"workspace_id": workspace_id,
                **{key: value for key, value in options.items() if value is not None}}

    def events_sync(self, workspace_id: str) -> dict:
        """Probe unchanged history or replay updates and enqueue receipts; not incremental sync."""
        return self._call("events.sync", {"workspace_id": workspace_id})

    def events_receive(self, workspace_id: str, consumer_id: str, *,
                       filter_version: str, lease_ms: int = 30000,
                       wait_ms: int = 0) -> dict:
        """Receive a durable lease. Requested wait budget is up to 60 seconds, with cooperative cancellation."""
        return self._call("events.receive", self._event_request(workspace_id,
            consumer_id=consumer_id, filter_version=filter_version, lease_ms=lease_ms, wait_ms=wait_ms))

    def events_ack(self, workspace_id: str, consumer_id: str, ack_token: str, *,
                   filter_version: str) -> dict:
        """Acknowledge delivery, never protocol task completion."""
        return self._call("events.ack", self._event_request(workspace_id,
            consumer_id=consumer_id, filter_version=filter_version, ack_token=ack_token))

    def events_status(self, workspace_id: str) -> dict:
        return self._call("events.status", {"workspace_id": workspace_id})

    async def events_sync_async(self, workspace_id: str) -> dict:
        return await self._call_async("events.sync", {"workspace_id": workspace_id})

    async def events_receive_async(self, workspace_id: str, consumer_id: str, *,
                             filter_version: str, lease_ms: int = 30000,
                             wait_ms: int = 0) -> dict:
        return await self._call_async("events.receive", self._event_request(workspace_id,
            consumer_id=consumer_id, filter_version=filter_version, lease_ms=lease_ms, wait_ms=wait_ms))

    async def events_ack_async(self, workspace_id: str, consumer_id: str, ack_token: str, *,
                              filter_version: str) -> dict:
        return await self._call_async("events.ack", self._event_request(workspace_id,
            consumer_id=consumer_id, filter_version=filter_version, ack_token=ack_token))

    async def events_status_async(self, workspace_id: str) -> dict:
        return await self._call_async("events.status", {"workspace_id": workspace_id})

    async def _call_async(self, operation: str, request: dict) -> dict:
        # Snapshot caller values before handing work to the native worker.
        request = json.loads(json.dumps(request, ensure_ascii=True, allow_nan=False))
        cancel = KernelCancelHandle()
        worker = asyncio.create_task(asyncio.to_thread(self._call, operation, request, cancel))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel.cancel()
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    cancel.cancel()
                except Exception:
                    break
            try:
                worker.result()
            except Exception:
                pass
            raise

    async def inspect_async(self, workspace_id: str) -> dict:
        return await self._call_async("inspect", {"workspace_id": workspace_id})

    async def operate_async(self, workspace_id: str, intent: AgentIntent, operation_id: str) -> dict:
        return await self._call_async("operate", {"workspace_id": workspace_id,
            "intent": intent, "operation_id": operation_id})

    async def recover_async(self, workspace_id: str, *, operation_id: str | None = None,
                            command_id: str | None = None, recovery: dict | None = None) -> dict:
        request = self._recovery_request(workspace_id, operation_id, command_id)
        if recovery is not None:
            request["recovery"] = recovery
        return await self._call_async("recover", request)

    async def operations_async(self, workspace_id: str, *, after: str | None = None, limit: int | None = None,
                               scope: Literal["MINE", "WORKSPACE"] | None = None, view: Literal["OPEN", "HISTORY"] | None = None) -> dict:
        return await self._call_async("operations", self._operations_request(workspace_id, after, limit, scope, view))


def open_context(*, profile: str | Path, expected_actor: str, expected_service: str) -> AgentContext:
    """Open an existing protected context offline, without creating local state."""
    context = AgentContext(str(profile), expected_actor, expected_service, "{}")
    value = context._call("open")
    return AgentContext(str(profile), expected_actor, expected_service,
                        json.dumps(value["context"], ensure_ascii=True, allow_nan=False))


__all__ += ["AgentContext", "AgentContextError", "AgentProtocolActionIntent", "AgentStructureIntent", "open_context"]


def bind_context(*, profile: str | Path, expected_actor: str, expected_service: str,
                 workspace_profiles: list[str | Path]) -> AgentContext:
    """Explicitly create only a new protected context reference from existing profiles.

    Existing target files are never overwritten; no identity or membership is created.
    """
    request = json.dumps({"workspace_profiles": [str(path) for path in workspace_profiles]},
                         ensure_ascii=True, allow_nan=False)
    result = json.loads(agent_context_json("bind", str(profile), expected_actor,
                                         expected_service, request, None))
    if result["ok"] is not True:
        raise AgentContextError(result)
    return open_context(profile=profile, expected_actor=expected_actor, expected_service=expected_service)


__all__ += ["bind_context"]


def bind_structure_context(*, profile: str | Path, expected_actor: str, expected_service: str,
                           origin: str, identity_path: str | Path, journal_path: str | Path,
                           workspace_ids: list[str], authority: str | None = None,
                           required_features: list[str] | None = None, allow_loopback_http: bool = False,
                           transport: TransportOptions | None = None) -> AgentContext:
    """Bind explicit backend execution to an existing identity, without legacy replay or enrollment."""
    config = {"schema": "peerwork.agent-context.v2", "execution_profile": "backend-structure-v1",
              "service_id": expected_service, "origin": origin, "identity_path": str(identity_path),
              "kernel_journal_path": str(journal_path), "workspaces": workspace_ids,
              "required_features": required_features or [], "allow_loopback_http": allow_loopback_http}
    if authority is not None:
        config["authority"] = authority
    if transport is not None:
        config["transport"] = _transport_config(transport)
    result = json.loads(agent_context_json("bind.structure", str(profile), expected_actor, expected_service,
                                         json.dumps(config, ensure_ascii=True, allow_nan=False), None))
    if result["ok"] is not True:
        raise AgentContextError(result)
    return open_context(profile=profile, expected_actor=expected_actor, expected_service=expected_service)


__all__ += ["bind_structure_context"]


__all__ += ["AgentBrowserApprovalIntent", "AgentIntent"]


class NavigationError(RuntimeError):
    """URL validation or verified anonymous changelog read failed."""
    def __init__(self, code: str, message: str, *, phase=None, retryable=False, recovery=None):
        self.code = code
        self.phase = phase
        self.retryable = retryable
        self.recovery = recovery
        super().__init__(message)


def _navigation(operation: str, value: dict, cancel_handle=None):
    result = json.loads(navigation_json(operation, json.dumps(value, ensure_ascii=True,
        allow_nan=False, separators=(",", ":")), cancel_handle))
    if result["ok"] is not True:
        raise NavigationError(result["code"], result["message"], phase=result.get("phase"), retryable=result.get("retryable", False), recovery=result.get("recovery"))
    return result["value"]


class WorkspaceUrls:
    """Generate current browser/API locators; PRIVATE is the default."""
    def __init__(self, *, browser_origin: str = "https://peerwork.dev",
                 control_origin: str = "https://api.peerwork.dev", allow_loopback_http: bool = False):
        self._origins = dict(browser_origin=browser_origin, control_origin=control_origin,
                             allow_loopback_http=allow_loopback_http)

    def build(self, workspace_id: str, *, visibility: Literal["PRIVATE", "PUBLIC"] = "PRIVATE",
              kind: str = "workspace", instance_id: str | None = None,
              record_id: str | None = None, entity_id: str | None = None, revision: int | None = None, workspace_alias: str | None = None) -> dict:
        return _navigation("url", dict(self._origins, workspace_id=workspace_id, workspace_alias=workspace_alias,
            visibility=visibility, kind=kind, instance_id=instance_id,
            record_id=record_id, entity_id=entity_id, revision=revision))

    def workspace(self, workspace_id: str, *, visibility: Literal["PRIVATE", "PUBLIC"] = "PRIVATE", workspace_alias: str | None = None) -> str:
        return self.build(workspace_id, visibility=visibility, workspace_alias=workspace_alias)["browser_url"]

    def instance(self, workspace_id: str, instance_id: str, *, visibility: Literal["PRIVATE", "PUBLIC"] = "PRIVATE", workspace_alias: str | None = None) -> str:
        return self.build(workspace_id, visibility=visibility, kind="instance", instance_id=instance_id, workspace_alias=workspace_alias)["browser_url"]

    def record(self, workspace_id: str, record_id: str, *, instance_id: str, revision: int, visibility: Literal["PRIVATE", "PUBLIC"] = "PRIVATE", workspace_alias: str | None = None) -> str:
        return self.build(workspace_id, visibility=visibility, kind="record", instance_id=instance_id, record_id=record_id, revision=revision, workspace_alias=workspace_alias)["browser_url"]


class ChangelogClient:
    """Anonymous owner-pinned PUBLIC changelog reader. No local identity is needed."""
    def __init__(self, *, source: dict | None = None):
        self.source = dict(source) if source is not None else self.official_source()

    @staticmethod
    def official_source() -> dict:
        return _navigation("changelog.source", {})["source"]

    def _read(self, _operation: str = "read", *, limit: int = 20, cursor: str | None = None,
              checkpoint: dict | None = None, cancel_handle=None) -> dict:
        return _navigation("changelog.read", dict(source=self.source, limit=limit,
            cursor=cursor, checkpoint=checkpoint), cancel_handle)

    def read(self, *, limit: int = 20, cursor: str | None = None, checkpoint: dict | None = None) -> dict:
        """Read current selected heads; reuse checkpoint for continuity and paging."""
        return self._read(limit=limit, cursor=cursor, checkpoint=checkpoint)

    async def read_async(self, *, limit: int = 20, cursor: str | None = None,
                         checkpoint: dict | None = None) -> dict:
        return await _run_cancelled_async(self._read, "read", limit=limit,
                                         cursor=cursor, checkpoint=checkpoint)

__all__ += ["WorkspaceUrls", "ChangelogClient", "NavigationError"]


class ReadViewError(RuntimeError):
    """No current-view result was produced; an error never means an empty page."""
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class AuthorizedViewRead(TypedDict):
    transport_metrics: dict[str, int]
    assurance: Literal["AUTHORIZED_STATE"]
    coverage: str
    checkpoint: dict
    root_hash: str
    floor: dict
    objects: list[dict]
    object: NotRequired[dict | None]
    next: dict | None
    metrics: dict


class PublicReadViewClient:
    """Opt-in PUBLIC state reads pinned to an Owner, service and workspace.

    Requires an explicitly adopted and published read view. No identity is created
    and no full-journal fallback occurs. Pass the returned floor for continuity;
    a page cursor remains bound to its original root and query.
    """
    def __init__(self, *, origin: str, workspace_id: str, owner_actor_id: str,
                 owner_key_id: str, audience: str, service_key: str,
                 accept_authorized_state: Literal[True],
                 transport: TransportOptions | None = None, allow_loopback_http: bool = False):
        self._source = dict(origin=origin, workspace_id=workspace_id,
            owner_actor_id=owner_actor_id, owner_key_id=owner_key_id,
            audience=audience, service_key=service_key,
            accept_authorized_state=accept_authorized_state,
            allow_loopback_http=allow_loopback_http)
        if transport is not None:
            self._source["transport"] = transport._json_value()

    def _read(self, _operation: str = "read", *, selection: dict,
              floor: dict | None = None, cancel_handle=None) -> AuthorizedViewRead:
        request = dict(self._source, selection=selection, floor=floor)
        result = json.loads(read_view_json(json.dumps(request, ensure_ascii=True,
            allow_nan=False, separators=(",", ":")), cancel_handle))
        if result["ok"] is not True:
            raise ReadViewError(result["code"], result["message"])
        return cast(AuthorizedViewRead, result["value"])

    def get(self, kind: str, object_id: str, *, floor: dict | None = None) -> AuthorizedViewRead:
        return self._read(selection=dict(kind="get", object_kind=kind, id=object_id), floor=floor)

    def list(self, instance_id: str, schema: str, *, limit: int = 20,
             cursor: dict | None = None, floor: dict | None = None) -> AuthorizedViewRead:
        return self._read(selection=dict(kind="list", instance_id=instance_id,
            schema=schema, limit=limit, cursor=cursor), floor=floor)

    async def get_async(self, kind: str, object_id: str, *, floor: dict | None = None) -> AuthorizedViewRead:
        return await _run_cancelled_async(self._read, "read",
            selection=dict(kind="get", object_kind=kind, id=object_id), floor=floor)

    async def list_async(self, instance_id: str, schema: str, *, limit: int = 20,
                         cursor: dict | None = None, floor: dict | None = None) -> AuthorizedViewRead:
        return await _run_cancelled_async(self._read, "read",
            selection=dict(kind="list", instance_id=instance_id, schema=schema,
                           limit=limit, cursor=cursor), floor=floor)


__all__ += ["PublicReadViewClient", "AuthorizedViewRead", "ReadViewError"]


class PrivateReadViewClient(PublicReadViewClient):
    """Bounded PRIVATE reads from an already active protected workspace profile.

    Owner/service pins and epoch keys come from protected native state. No history
    replay or key activation occurs. A successful read persists a separate view
    floor without changing the independently verified journal floor.
    """
    def __init__(self, origin: str, state_dir: str, identity_path: str,
                 workspace_id: str, *, accept_authorized_state: Literal[True],
                 owner_actor_id: str | None = None, owner_key_id: str | None = None,
                 authority: str | None = None, required_features: tuple[str, ...] = (),
                 allow_loopback_http: bool = False, transport: TransportOptions | None = None):
        profile = SecureReadClient(origin, state_dir, identity_path, workspace_id,
            owner_actor_id=owner_actor_id, owner_key_id=owner_key_id, authority=authority,
            required_features=required_features, allow_loopback_http=allow_loopback_http,
            transport=transport)
        self._profile = json.loads(json.dumps(profile._config, ensure_ascii=True, allow_nan=False))
        self._accept_authorized_state = accept_authorized_state

    def _read(self, _operation: str = "read", *, selection: dict,
              floor: dict | None = None, cancel_handle=None) -> AuthorizedViewRead:
        request = dict(profile=self._profile, accept_authorized_state=self._accept_authorized_state,
                       selection=selection, floor=floor)
        result = json.loads(private_read_view_json(json.dumps(request, ensure_ascii=True,
            allow_nan=False, separators=(",", ":")), cancel_handle))
        if result["ok"] is not True:
            raise ReadViewError(result["code"], result["message"])
        return cast(AuthorizedViewRead, result["value"])


__all__ += ["PrivateReadViewClient"]


class CurrentPageRead(TypedDict):
    assurance: Literal["SERVICE_STRUCTURE_SELECTION"]
    checkpoint: dict
    policy: dict
    floor: dict
    objects: list[dict]
    object: NotRequired[dict | None]
    next: dict | None
    metrics: dict
    transport_metrics: dict[str, int]


class CurrentPageClient:
    """Bounded current reads from an already active protected PRIVATE profile.

    The service selects current objects using the existing disclosed structure.
    Native code verifies original author signatures and decrypts content locally.
    This assurance is SERVICE_STRUCTURE_SELECTION, not complete historical replay.
    No Owner publisher, new key import, or journal replay is required.
    """
    def __init__(self, origin: str, state_dir: str, identity_path: str,
                 workspace_id: str, *, owner_actor_id: str | None = None,
                 owner_key_id: str | None = None, authority: str | None = None,
                 required_features: tuple[str, ...] = (), allow_loopback_http: bool = False,
                 transport: TransportOptions | None = None):
        profile = SecureReadClient(origin, state_dir, identity_path, workspace_id,
            owner_actor_id=owner_actor_id, owner_key_id=owner_key_id, authority=authority,
            required_features=required_features, allow_loopback_http=allow_loopback_http,
            transport=transport)
        self._profile = json.loads(json.dumps(profile._config, ensure_ascii=True, allow_nan=False))

    def _read(self, _operation: str = "read", *, query: dict,
              floor: dict | None = None, cancel_handle=None) -> CurrentPageRead:
        result = json.loads(current_page_json(json.dumps(dict(profile=self._profile,
            query=query, floor=floor), ensure_ascii=True, allow_nan=False,
            separators=(",", ":")), cancel_handle))
        if result["ok"] is not True:
            raise ReadViewError(result["code"], result["message"])
        return cast(CurrentPageRead, result["value"])

    def get(self, kind: str, object_id: str, *, floor: dict | None = None) -> CurrentPageRead:
        return self._read(query=dict(kind="get", object_kind=kind, id=object_id), floor=floor)

    def instances(self, *, limit: int = 20, cursor: dict | None = None,
                  floor: dict | None = None) -> CurrentPageRead:
        query = dict(kind="instances", limit=limit)
        if cursor is not None: query["cursor"] = cursor
        return self._read(query=query, floor=floor)

    @staticmethod
    def _records_query(instance_id: str, schema: str | None, limit: int, cursor: dict | None) -> dict:
        query = dict(kind="records", instance_id=instance_id, limit=limit)
        if schema is not None: query["schema"] = schema
        if cursor is not None: query["cursor"] = cursor
        return query

    def records(self, instance_id: str, schema: str | None = None, *, limit: int = 20,
                cursor: dict | None = None, floor: dict | None = None) -> CurrentPageRead:
        return self._read(query=self._records_query(instance_id, schema, limit, cursor), floor=floor)

    list = records

    async def get_async(self, kind: str, object_id: str, *, floor: dict | None = None) -> CurrentPageRead:
        return await _run_cancelled_async(self._read, "read",
            query=dict(kind="get", object_kind=kind, id=object_id), floor=floor)

    async def instances_async(self, *, limit: int = 20, cursor: dict | None = None,
                              floor: dict | None = None) -> CurrentPageRead:
        query = dict(kind="instances", limit=limit)
        if cursor is not None: query["cursor"] = cursor
        return await _run_cancelled_async(self._read, "read", query=query, floor=floor)

    async def records_async(self, instance_id: str, schema: str | None = None, *, limit: int = 20,
                            cursor: dict | None = None, floor: dict | None = None) -> CurrentPageRead:
        return await _run_cancelled_async(self._read, "read",
            query=self._records_query(instance_id, schema, limit, cursor), floor=floor)

    list_async = records_async


__all__ += ["CurrentPageClient", "CurrentPageRead"]


class OwnerGuardTimeResult(TypedDict):
    operation_id: str
    command_id: str
    workspace_id: str
    status: Literal["PENDING", "ACCEPTED", "ALREADY_ENABLED"]
    sequence: int | None
    head: str | None
    policy_hash: str | None


class OwnerWorkspaceGuardTimeClient:
    """Activate ALL_COMMITS using the existing protected Owner; no raw key input.

    Persist the caller's operation_id before enable. If PENDING or interrupted,
    resume that same ID; history recovers locally saved IDs without a new POST.
    """

    def __init__(self, owner_config: dict, workspace_id: str):
        self._config = dict(owner_config)
        self._workspace_id = workspace_id

    def _call(self, operation: str, input_value: dict,
              cancel_handle: KernelCancelHandle | None = None):
        result = json.loads(owner_guard_time_json(
            json.dumps(self._config, ensure_ascii=True, separators=(",", ":")),
            operation, json.dumps(input_value, ensure_ascii=True, separators=(",", ":")),
            cancel_handle))
        if result["ok"] is not True:
            raise OwnerWorkspaceError(result["code"], result["message"])
        return result["value"]

    def enable(self, *, expected_policy_hash: str, audience: str, service_key: str,
               disclosure: Literal["GUARD_WINDOW"], operation_id: str | None = None,
               required_producers: list[str] | None = None) -> OwnerGuardTimeResult:
        """Explicit Owner consent; pins must match authenticated discovery and the current policy."""
        value = dict(workspace_id=self._workspace_id, expected_policy_hash=expected_policy_hash,
            audience=audience, service_key=service_key, disclosure=disclosure)
        if operation_id is not None:
            value["operation_id"] = operation_id
        if required_producers is not None:
            value["required_producers"] = required_producers
        return cast(OwnerGuardTimeResult, self._call("enable", value))

    def resume(self, operation_id: str) -> OwnerGuardTimeResult:
        return cast(OwnerGuardTimeResult, self._call("resume",
            dict(workspace_id=self._workspace_id, operation_id=operation_id)))

    def history(self) -> list[OwnerGuardTimeResult]:
        """Protected local operations; PENDING is not proof of remote acceptance."""
        return cast(list[OwnerGuardTimeResult], self._call("history", dict(workspace_id=self._workspace_id)))

    async def enable_async(self, *, expected_policy_hash: str, audience: str, service_key: str,
                           disclosure: Literal["GUARD_WINDOW"], operation_id: str | None = None,
               required_producers: list[str] | None = None) -> OwnerGuardTimeResult:
        value = dict(workspace_id=self._workspace_id, expected_policy_hash=expected_policy_hash,
            audience=audience, service_key=service_key, disclosure=disclosure)
        if operation_id is not None:
            value["operation_id"] = operation_id
        if required_producers is not None:
            value["required_producers"] = required_producers
        return cast(OwnerGuardTimeResult, await _run_cancelled_async(self._call, "enable", input_value=value))

    async def resume_async(self, operation_id: str) -> OwnerGuardTimeResult:
        return cast(OwnerGuardTimeResult, await _run_cancelled_async(self._call, "resume",
            input_value=dict(workspace_id=self._workspace_id, operation_id=operation_id)))

    async def history_async(self) -> list[OwnerGuardTimeResult]:
        return cast(list[OwnerGuardTimeResult], await _run_cancelled_async(self._call, "history",
            input_value=dict(workspace_id=self._workspace_id)))

__all__ += ["OwnerWorkspaceGuardTimeClient", "OwnerGuardTimeResult"]


class ProtocolWorkbenchError(RuntimeError):
    """Local semantic diagnostics or a resumable online plan refusal."""
    def __init__(self, envelope: dict):
        super().__init__(envelope.get("message", envelope.get("code", "Protocol test failed")))
        self.envelope = envelope
        self.code = envelope["code"]
        self.stage = envelope.get("stage")
        self.server_code = envelope.get("server_code")
        self.http_status = envelope.get("http_status")
        self.step = envelope.get("step")
        self.action_id = envelope.get("action_id")
        self.constraint = envelope.get("constraint")
        self.effect_certainty = envelope.get("effect_certainty")
        self.retryability = envelope.get("retryability")


def _workbench(operation: str, request: dict, cancel_handle=None) -> dict:
    wire = json.dumps(request, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    envelope = json.loads(protocol_workbench_json(operation, wire, cancel_handle))
    if envelope["ok"] is not True:
        raise ProtocolWorkbenchError(envelope)
    return envelope["value"]


def protocol_compatibility(required_producers: list[str]) -> dict:
    """Local producer coverage; service and other writer versions need independent qualification."""
    return _workbench("compatibility", {"required_producers": required_producers})


def build_protocol_fixture(protocols: list[dict], *, actors: list[dict] | None = None,
                           seed: str | None = None, time_ms: int | None = None) -> dict:
    """Create synthetic local data without identity, network or workspace access."""
    request = {"schema": "peerwork.protocol-fixture.v1", "protocols": protocols}
    for name, value in (("actors", actors), ("seed", seed), ("time_ms", time_ms)):
        if value is not None:
            request[name] = value
    return _workbench("fixture", request)


def simulate_protocol(fixture: dict, steps: list[dict], *, seed: str | None = None) -> dict:
    """Run the real native evaluator offline. Results are never commit receipts."""
    request = {"schema": "peerwork.protocol-simulation.v1", "fixture": fixture, "steps": steps}
    if seed is not None:
        request["seed"] = seed
    return _workbench("simulate", request)


def plan_protocol_actions(fixture: dict, steps: list[dict], *, seed: str | None = None) -> dict:
    """Freeze semantic actions and intermediate dependencies after offline execution."""
    request = {"schema": "peerwork.protocol-simulation.v1", "fixture": fixture, "steps": steps}
    if seed is not None:
        request["seed"] = seed
    return _workbench("plan", request)


def export_protocol_fixture(profile: dict, instance_ids: list[str], *, time_ms: int,
                            cached: bool = False) -> dict:
    """Export selected decrypted state from verified replay; cached=True uses no HTTP."""
    return _workbench("export", {"profile": profile, "instance_ids": instance_ids,
                                 "time_ms": time_ms, "cached": cached})


def apply_protocol_plan(profile: dict, plan: dict | None, operation_id: str) -> dict:
    """Revalidate and resume the same explicit plan. Cross-instance steps are non-atomic."""
    return _workbench("apply", {"profile": profile, "operation_id": operation_id, **({} if plan is None else {"plan": plan})})


async def simulate_protocol_async(fixture: dict, steps: list[dict], *, seed: str | None = None) -> dict:
    return await asyncio.to_thread(simulate_protocol, fixture, steps, seed=seed)


async def export_protocol_fixture_async(profile: dict, instance_ids: list[str], *, time_ms: int,
                                       cached: bool = False) -> dict:
    return await _run_cancelled_async(_workbench, "export", request={
        "profile": profile, "instance_ids": instance_ids, "time_ms": time_ms, "cached": cached})


async def apply_protocol_plan_async(profile: dict, plan: dict | None, operation_id: str) -> dict:
    return await _run_cancelled_async(_workbench, "apply", request={
        "profile": profile, "operation_id": operation_id, **({} if plan is None else {"plan": plan})})


__all__ += ["ProtocolWorkbenchError", "build_protocol_fixture", "simulate_protocol",
            "simulate_protocol_async", "plan_protocol_actions", "export_protocol_fixture",
            "export_protocol_fixture_async", "apply_protocol_plan", "apply_protocol_plan_async"]

__all__ += ["AgentInvitationFinalizeIntent"]

__all__ += ["protocol_compatibility"]

def resume_protocol_plan(profile: dict, operation_id: str) -> dict:
    """Explicitly resume the exact native saved plan under its original operation ID."""
    return apply_protocol_plan(profile, None, operation_id)


async def resume_protocol_plan_async(profile: dict, operation_id: str) -> dict:
    return await apply_protocol_plan_async(profile, None, operation_id)


__all__ += ["resume_protocol_plan", "resume_protocol_plan_async"]


class OwnerWorkspaceMemberScopesClient:
    """Owner-only PRIVATE scope replacement; keys and signing remain native-owned."""
    def __init__(self, owner_config: dict, workspace_id: str):
        self._config = dict(owner_config)
        self._workspace_id = workspace_id

    def _call(self, operation: str, input_value: dict,
              cancel_handle: KernelCancelHandle | None = None):
        result = json.loads(owner_member_scopes_json(json.dumps(self._config, ensure_ascii=True),
            operation, json.dumps(dict(workspace_id=self._workspace_id, **input_value), ensure_ascii=True), cancel_handle))
        if result["ok"] is not True:
            error = OwnerWorkspaceError(result["code"], result["message"])
            error.diagnostic = result.get("diagnostic")
            raise error
        return result["value"]

    def inspect(self, actor_id: str) -> dict:
        return self._call("inspect", dict(actor_id=actor_id))

    def set(self, actor_id: str, *, expected_policy_hash: str, scopes: list[dict], operation_id: str | None = None) -> dict:
        value = dict(actor_id=actor_id, expected_policy_hash=expected_policy_hash, scopes=scopes)
        if operation_id is not None: value["operation_id"] = operation_id
        return self._call("set", value)

    def recover(self, operation_id: str) -> dict:
        return self._call("recover", dict(operation_id=operation_id))

    def retry_saved(self, operation_id: str) -> dict:
        return self._call("retry", dict(operation_id=operation_id))

    def history(self) -> list[dict]:
        return self._call("history", {})

    async def inspect_async(self, actor_id: str) -> dict:
        return await _run_cancelled_async(self._call, "inspect", input_value=dict(actor_id=actor_id))

    async def set_async(self, actor_id: str, *, expected_policy_hash: str, scopes: list[dict], operation_id: str | None = None) -> dict:
        value = dict(actor_id=actor_id, expected_policy_hash=expected_policy_hash, scopes=scopes)
        if operation_id is not None: value["operation_id"] = operation_id
        return await _run_cancelled_async(self._call, "set", input_value=value)

    async def recover_async(self, operation_id: str) -> dict:
        return await _run_cancelled_async(self._call, "recover", input_value=dict(operation_id=operation_id))

    async def retry_saved_async(self, operation_id: str) -> dict:
        return await _run_cancelled_async(self._call, "retry", input_value=dict(operation_id=operation_id))

    async def history_async(self) -> list[dict]:
        return await _run_cancelled_async(self._call, "history", input_value={})

__all__ += ["OwnerWorkspaceMemberScopesClient"]


def publication_body(text: str) -> dict:
    """Encode an explicitly public body, without making a network request."""
    import base64
    if not isinstance(text, str):
        raise TypeError("Public body must be text")
    data = text.encode("utf-8", errors="strict")
    if len(data) > 65536:
        raise ValueError("CONTENT_TOO_LARGE: public body exceeds 65536 UTF-8 bytes")
    encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    return {"format": "PUBLIC_UTF8_BASE64", "chunks": [encoded[i:i+8192] for i in range(0, len(encoded), 8192)]}


class PublicationReader:
    """Anonymous selected PUBLIC pages with Owner pins and no journal fallback."""
    def __init__(self, *, control_origin: str, browser_origin: str, workspace_id: str, owner_actor_id: str, owner_key_id: str, audience: str | None = None, service_key: str | None = None, transport: TransportOptions | None = None, allow_loopback_http: bool = False):
        self._source = dict(control_origin=control_origin, browser_origin=browser_origin, workspace_id=workspace_id, owner_actor_id=owner_actor_id, owner_key_id=owner_key_id, audience=audience, service_key=service_key, allow_loopback_http=allow_loopback_http)
        if transport is not None:
            self._source["transport"] = _transport_config(transport)
        self._checkpoint = None

    def _read(self, kind: str, *, instance_id: str | None = None, record_id: str | None = None, limit: int = 20, cursor: str | None = None, checkpoint: dict | None = None, order: str = "RECORD_ID_ASC", cancel_handle=None) -> dict:
        value = _navigation("publication.read", dict(source=self._source, kind=kind, instance_id=instance_id, record_id=record_id, limit=limit, cursor=cursor, checkpoint=checkpoint if checkpoint is not None else self._checkpoint, order=order), cancel_handle)
        if self._checkpoint is not None and value["checkpoint"]["publication_revision"] < self._checkpoint["publication_revision"]:
            raise NavigationError("PUBLIC_CHECKPOINT_CHANGED", "Public view regressed below the observed revision")
        self._checkpoint = value["checkpoint"]
        return value

    def workspace(self, **options) -> dict:
        return self._read("WORKSPACE", **options)

    def list(self, **options) -> dict:
        return self._read("ENTRIES", **options)

    def get(self, record_id: str, **options) -> dict:
        return self._read("ENTRY", record_id=record_id, **options)

    async def workspace_async(self, **options) -> dict:
        return await _run_cancelled_async(self._read, "WORKSPACE", **options)

    async def list_async(self, **options) -> dict:
        return await _run_cancelled_async(self._read, "ENTRIES", **options)

    async def get_async(self, record_id: str, **options) -> dict:
        return await _run_cancelled_async(self._read, "ENTRY", record_id=record_id, **options)

__all__ += ["PublicationReader", "publication_body"]
