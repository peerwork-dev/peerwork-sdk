export interface TransportConfig { requestTimeoutMs: number; additionalRootPemFiles: string[] }
export interface ClientConfig { origin: string; stateDir: string; transport?: TransportConfig }
/** Explicit HTTP settings. Certificate files are read only by the native layer. */
export interface TransportOptions {
  requestTimeoutMs?: number;
  additionalRootPemFiles?: string[];
}
/** Read-only explicit > PEERWORK_CONFIG > OS protected user config; rejects selected failures. */
export declare function loadConfig(path?: string): Promise<ClientConfig>;
/** Experimental native kernel command client; secure-agent replay remains incomplete. */
export declare function version(): string;
export interface CapabilityManifest {
  backend_structure_execution: boolean;
  backend_current_state_reads: boolean;
  protocol_role_bundles: boolean;
  backend_durable_recovery: boolean;
  legacy_online_modes: 'RETIRED';
  protocol_offline_simulation: boolean;
  protocol_verified_export: boolean;
  protocol_plan_apply: boolean;
  guarded_invitation_finalize: boolean;
  producer_compatibility_report: boolean;
  workspace_url_generation: boolean;
  anonymous_changelog_read: boolean;
  anonymous_publication_read: boolean;
  public_authorized_state_read: boolean;
  private_authorized_state_read: boolean;
  private_system_current_page_read: boolean;
  owner_guard_time_enable: boolean;
  owner_member_scopes: boolean;
  private_install_auto_transport: boolean;
  private_install_reviewed_recovery: boolean;
  private_time_add_guard_windows: boolean;
  version: string;
  status: string;
  wire_canonicalization: boolean;
  signed_artifact_verification: boolean;
  receipt_verification: boolean;
  verified_public_workspace_reads: boolean;
  verified_workspace_reads: boolean;
  safe_actions: boolean;
  durable_recovery: boolean;
}
export declare function capabilities(): CapabilityManifest;
export interface IdentityInfo { actor_id: string; key_id: string }
/** Creates protected local identity state without service enrollment. */
export declare function createIdentity(path: string): Promise<IdentityInfo>;
/** Opens local identity state and returns public IDs only. */
export declare function openIdentity(path: string): Promise<IdentityInfo>;
/** Imports a raw 32-byte seed file into new protected identity state. */
export declare function importIdentitySeedFile(path: string, seedFile: string): Promise<IdentityInfo>;
/** Imports a PKCS#8 Ed25519 PEM file into new protected identity state. */
export declare function importLegacyIdentityPem(path: string, pemFile: string): Promise<IdentityInfo>;
/** Import a legacy Owner PEM into identity.state selected by an Owner config. */
export declare function importLegacyOwnerIdentity(configFile: string, pemFile: string): Promise<IdentityInfo>;
export interface KernelAccessOptions {
  origin: string;
  journalPath: string;
  identityPath: string;
  requiredFeatures?: string[];
  /** Only for local development with a loopback origin. */
  allowLoopbackHttp?: boolean;
  /** Defaults to SHA-256 of the local actor ID, matching WorkspaceClient. */
  authority?: string;
  transport?: TransportOptions;
  signal?: AbortSignal;
}
export interface PendingIntent { command_id: string; intent_digest: string; created_at_ms: number }
export interface StorageCapacity {limit_bytes:number;write_limit_bytes:number;used_bytes:number;remaining_write_bytes:number;limit_objects:number;write_limit_objects:number;used_objects:number;remaining_write_objects:number;percent_used:number;status:'OK'|'WARNING'|'CRITICAL';warning_percent:number;critical_percent:number;security_headroom_bytes:number;usage_basis:'COMMITTED_LOGICAL_ROWS'}
export interface StorageWarning {code:'WORKSPACE_STORAGE_NEAR_LIMIT';severity:'WARNING'|'CRITICAL';workspace_id:string;used_bytes:number;write_limit_bytes:number;remaining_write_bytes:number;percent_used:number}
export interface AcceptedResult {
  warnings?:StorageWarning[];
  key_history?: {job_id: string; through_epoch: number; state: 'READY' | 'PENDING' | 'UNAVAILABLE'; code: string | null};
  browser_approval_reference?: string;
  opened_contents?: OpenedStructureBody[];
  command_id: string;
  workspace_id: string | null;
  protocol_digest: string | null;
  instance_id: string | null;
  event_sequence: number | null;
  revision: number | null;
  produced_record_ids: string[];
  catalog: CatalogAcceptedResult | null;
  /** Verified service-maintained structure; does not assert independent history replay. */
  structure?: BackendStructureResult;
}
export interface OpenedStructureBody {
  record_id: string; revision: number; source_command_id: string; record_index: number; key_id: string | null;
  state: 'OPENED' | 'NO_CONTENT' | 'KEY_UNAVAILABLE' | 'AUTHENTICATION_FAILED' | 'BODY_INVALID' | 'KEY_STATE_INVALID' | 'UNSUPPORTED_ENCODING';
  text: string | null; assurance: 'AUTHOR_SIGNATURE_AND_AEAD' | 'AUTHOR_PUBLIC_SIGNATURE' | null;
}
export interface StructureMaintenanceResult {
  job_id: string; workspace_id: string; instance_id: string; unsettled: boolean; kind: 'CURRENT_RECORDS'; actor_id: string; membership_id: string;
  command_id: string; intent_digest: string; protocol_digest: string;
  base_revision: number; base_event_revision: number; source_generation: string; target_generation: string;
  deadline_at: number; created_at: number; completed_at: number | null; activation_sequence: number | null;
  state: 'BUILDING' | 'CLEANUP' | 'DONE'; phase: 'HEADS' | 'CLEANUP' | 'DONE';
  status: 'ORDERED' | 'APPLIED' | 'REJECTED_NO_EFFECT' | 'VERIFICATION_BLOCKED';
  scanned_records: number; scanned_heads: number; evidence_digest: string;
  error_code: string | null; cleanup_pending: boolean;
  source?: {actor_id: string; command_id: string; intent_digest: string; author_intent: string} | null;
}
export interface StructureOperationRef { job_id: string; instance_id: string; protocol_digest: string; workspace_id?: string }
export type StructureListedOperation = (StructureMaintenanceResult & {source_key: string; source_verification: 'VERIFIED'}) | (StructureOperationRef & {
  workspace_id: string; actor_id: string; command_id: string; intent_digest: string; kind: 'CURRENT_RECORDS'; unsettled: boolean;
  source_key: string; source_verification: 'BLOCKED'; status: 'VERIFICATION_BLOCKED'; observed_status: string;
  error_code: 'STRUCTURE_MAINTENANCE_SOURCE_INVALID'; recovery: 'INSPECT_SELECTED_OPERATION';
});
export interface BackendStructureResult {
  package_digest?: string;
  activated?: boolean;
  bundle_header?: ProtocolBundleHeader;
  resources?: Record<string, {path: string; sha256: string; bytes: number; media_type: string; content: string}>;
  runtime?: {actor_id: string; role: string; grant_id: string; granted_actions: string[]; tools: {name: string; action: string; input_schema: Record<string, unknown>}[]; instructions_resource: string; context: string[]};

  capacity?:StorageCapacity;
  warnings?:StorageWarning[];
  workspace_alias?:string|null;
  deletion?: WorkspaceDeletionProgress;
  deletions?: WorkspaceDeletionProgress[];
  owner_id?: string;
  delivery?: {epoch: number; publication_id: string; revision: number; status: 'PENDING' | 'COMPLETE'};
  content_key_head?: {workspace_id: string; key_id: string; epoch: number; revision: number; rotation_required: boolean; exposure_tracked?: boolean; rotate_before: number | null; owner_id: string; command_id: string; intent_digest: string; usable?: boolean; author_intent?: string} | null;
  effect_certainty?: 'COMMITTED' | 'NOT_APPLIED';
  error?: {phase: string; code: string; http_status?: number; retryable: boolean; recovery: string};
  maintenance?: StructureMaintenanceResult;
  operations?: StructureListedOperation[];
  name?: string;
  visibility?: 'PRIVATE';
  workspace_revision?: number;
  activation?: {actor_id: string; intent_digest: string; authorization: string; accepted_at: number};
  membership?: {role: 'OWNER' | 'MEMBER'; membership_id?: string; expires_at?: number | null};
  profile: 'backend-structure-v1';
  assurance: 'BACKEND_CURRENT_STATE';
  workspace_id: string | null;
  instance_id?: string;
  protocol_digest?: string;
  revision?: number;
  event_revision?: number;
  state?: unknown;
  members?: {membership_id: string; actor_id: string; role: string; state: 'ACTIVE' | 'REVOKED'; created_at: number; revoked_at: number | null}[];
  instance?: {instance_id: string; protocol_digest: string; revision: number; event_revision: number; state: unknown; manifest: unknown};
  instances?: {instance_id: string; protocol_digest: string; revision: number; event_revision: number; created_at: number; protocol_name?: string; protocol_version?: string}[];
  records?: {record_id: string; entity_id: string; revision: number; created_at?:number; schema: string; structure: unknown; sealed_content: unknown; source: StructureRecordSource; source_key: string}[];
  events?: {sequence: number; instance_id: string | null; kind: string; record_id: string | null; actor_id: string; created_at: number; summary: Record<string, unknown>; source_key: string}[];
  sources?: Record<string, {actor_id: string; command_id: string; intent_digest: string; author_intent: string} | null>;
  frontier?: Record<string, number>;
  next_cursor?: string | null;
  checkpoint?: number;
  observer_checkpoint?: number;
  consistency?: 'LIVE_KEYSET' | 'IF_UNCHANGED';
  publication_revision?: number;
  publication_state?: 'PUBLIC' | 'WITHDRAWN';
  created_at?: number;
  member_actor_id?: string;
  membership_id?: string;
  membership_state?: 'ACTIVE' | 'REVOKED';
  grant_id?: string;
  grant_actor_id?: string;
  grant_revision?: number;
  grant_state?: 'ACTIVE' | 'REVOKED';
  grant?: Record<string, unknown> | null;
  manifest?: unknown;
  structure?: unknown;
  sealed_content?: ({algorithm: 'A256GCM'; key_id: string; nonce: string; aad_digest: string} & ({ciphertext: string; ciphertext_chunks?: never} | {ciphertext_chunks: string[]; ciphertext?: never})) | null;
  source?: StructureRecordSource;
  author_intent?: string;
  produced_record_ids?: string[];
  status?: 'APPLIED' | 'REJECTED_NO_EFFECT' | 'NOT_FOUND' | 'ORDERED' | 'COMMITTED_RESULT_UNAVAILABLE';
  recovery?: 'RESUBMIT_EXACT_INTENT' | 'RESUBMIT_SAME_INTENT';
  response?: {command_id: string; receipt: string; result: BackendStructureResult};
}
export type CatalogAcceptedResult =
  | { kind: 'namespace_claim'; namespace: string }
  | { kind: 'upload_begin'; upload_id: string; state: 'STAGING'; expires_at: number }
  | { kind: 'upload_chunk'; upload_id: string; index: number; received_bytes: number; state: 'STAGING' | 'READY' }
  | { kind: 'package_publish'; namespace: string; package_id: string; version: string; bundle_digest: string; published: number };
export interface TsMigrationReport { pending_count: number; accepted_count: number }
export interface StructureIntentRequest {
  /** Encrypted locally before any submission; never included as plaintext in the signed wire. */
  plaintext_contents?: {record_index: number; text: string}[];
  action: 'structure.protocol.register' | 'structure.protocol.resolve' | 'structure.protocol.resource.get' | 'structure.workspace.delete' | 'structure.workspace.deletion.get' | 'structure.workspace.deletions.read' | 'structure.record.withdraw' | 'structure.publication.set' | 'structure.publication.entry.set' | 'structure.access.approval.get' | 'structure.access.end' | 'structure.instance.resolve' | 'structure.access.authorize' | 'structure.content-key.set' | 'structure.content-key.get' | 'structure.content-key.deliver' | 'structure.content-key.delivery.get' | 'structure.content-keys.read' | 'structure.workspace.create' | 'structure.workspace.get' | 'structure.adopt' | 'structure.action' | 'structure.instance.get' | 'structure.record.get' | 'structure.operation.get'
    | 'structure.member.set' | 'structure.grant.set' | 'structure.grant.revoke' | 'structure.grant.get'
    | 'structure.members.read' | 'structure.instances.read' | 'structure.records.read' | 'structure.events.read'
    | 'structure.maintenance.rebuild' | 'structure.maintenance.get' | 'structure.maintenance.cancel' | 'structure.operations.read' | 'structure.content-key.history.deliver' | 'structure.content-key.history.get' | 'structure.content-key.history.jobs.read' | 'structure.publication.entry.withdraw' | 'structure.publication.policy.get' | 'structure.publication.policy.set' | 'structure.publication.prepare.get';
  body: Record<string, unknown>;
  /** Choose command_id or idempotency_key. Reuse it with identical business fields to recover. */
  command_id?: string;
  idempotency_key?: string;
  workspace_id?: string | null;
  instance_id?: string | null;
  protocol_digest?: string | null;
  expected_workspace_revision?: number | null;
  expected_instance_revision?: number | null;
  exact_input_refs?: Record<string, unknown>[];
}
export type StructureIntentOutcome = {state: 'ACCEPTED' | 'REJECTED' | 'COMMITTED'; result: AcceptedResult} | {state: 'COMPLETED'; command_id: string; result: AcceptedResult} | {
  state: 'PENDING'; command_id: string; code: string; phase: string; retryable: boolean; effect_certainty: 'NOT_SUBMITTED' | 'COMMITTED' | 'UNKNOWN';
  recovery: 'RESUME_SAME_INTENT' | 'NEW_READ' | 'OBSERVE_SAME_OPERATION' | 'CONTINUE_KEY_ROTATION';
};
export interface AccessWriteSelection {instance_id: string; protocol_digest: string; action_id: string}
export interface DeviceAccessRequest {workspace_id: string; label: string; kind?: 'AGENT' | 'BROWSER'; write?: AccessWriteSelection | null}
export interface DeviceAccessApproval {
  include_history?: boolean;
  workspace_id: string; request_jws: string; mode?: 'SESSION' | 'KEYS_ONLY'; ttl_ms?: number | null;
  deliver_content_keys?: boolean; follow_current_key?: boolean; key_ids?: string[]; expected_workspace_revision?: number | null;
  selected_write?: (AccessWriteSelection & {protocol_roles?: string[]; capabilities?: string[]}) | null;
}
export interface ContentKeyAcceptance {
  workspace_id: string; owner_id: string; key_ids: string[];
  current_key_id?: string | null; expected_current_key_id?: string | null;
}
export interface KernelSession extends IdentityInfo {
  origin: string;
  /** Saves an exact signed request but performs no POST. */
  prepare(command: Record<string, unknown>, options?: {uploadChunk?: Buffer | Uint8Array; signal?: AbortSignal}): Promise<PendingIntent>;
  pending(options?: {signal?: AbortSignal}): Promise<PendingIntent[]>;
  /** Local, LIVE keyset page; verifies at most 32 unresolved packets. */
  pendingPage(options?: {after?: string; preparationsAfter?: string; limit?: number; signal?: AbortSignal}): Promise<{items: PendingIntent[]; next_after: string | null; consistency: 'LIVE_KEYSET'; preparations: {items: {command_id: string; workspace_id: string | null; kind: 'INTENT' | 'ACCESS' | 'PUBLICATION'; phase: 'PREPARATION'; effect_certainty: 'NOT_SUBMITTED'; recovery: 'RESUME_SAME_INTENT'}[]; next_after: string | null; consistency: 'LIVE_KEYSET'}}>;
  /** Explicit legacy local index maintenance, resumable by calling again. */
  buildPendingIndex(options?: {signal?: AbortSignal}): Promise<{complete: boolean; scanned_rows: number}>;
  /** Owner-publish a fresh key epoch; repeats reconcile the original command. */
  coordinateContentKeys(selection: {workspace_id: string}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  rotateContentKey(selection: {workspace_id: string; idempotency_key: string}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  /** Explicit local key creation only; does not grant access or deliver it to other readers. */
  ensureLocalContentKey(workspaceId: string, options?: {signal?: AbortSignal}): Promise<{workspace_id: string; key_id: string}>;
  requestAccess(selection: DeviceAccessRequest, options?: {signal?: AbortSignal}): Promise<{profile: 'backend-structure-v1'; workspace_id: string; actor_id: string; request_id: string; recipient_key_id: string; expires_at: number; request_jws: string; state: 'AWAITING_OWNER_APPROVAL'}>;
  /** Owner self-service migration; backend validates and activates without an operator. */
  migrateArchive(selection: {workspace_id: string; idempotency_key: string; checkpoint_path?: string; state_dir?: string; plan_path?: string; read_only_snapshot?: boolean; name?: string}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  publishSelectedRecord(selection: PublicationSnapshotSelection, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  authorizeAccess(selection: DeviceAccessApproval, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  acceptContentKeys(selection: ContentKeyAcceptance, options?: {signal?: AbortSignal}): Promise<{profile: 'backend-structure-v1'; workspace_id: string; state: 'IMPORTED'; key_ids: string[]; current_key_id: string | null; source_count: number}>;
  status(commandId: string, options?: {signal?: AbortSignal}): Promise<{state: 'NOT_FOUND' | 'PENDING'} | {state: 'ACCEPTED' | 'REJECTED' | 'COMMITTED'; result: AcceptedResult}>;
  submitSaved(commandId: string, options?: {signal?: AbortSignal}): Promise<AcceptedResult>;
  /** Obtains signed service time, signs/saves/submits intent and verifies its outcome. Never replays workspace history. */
  executeStructureIntent(intent: StructureIntentRequest, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  resumeStructureIntent(commandId: string, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  /** Imports a quiesced TypeScript client store and retains a verified online backup. */
  migrateTsStore(sourcePath: string, backupPath: string, trustedSignerKeyIds: string[], options?: {signal?: AbortSignal}): Promise<TsMigrationReport>;
}
export declare function openKernel(options: KernelAccessOptions): Promise<KernelSession>;

export interface SecureSnapshotOptions {
  origin: string;
  kernelJournalPath: string;
  readStatePath: string;
  lifecyclePath: string;
  identityPath: string;
  workspaceId: string;
  authority: string;
  /** Explicit trust pins; persisted locally on first lifecycle open. */
  ownerActorId: string;
  ownerKeyId: string;
  requiredFeatures?: string[];
  allowLoopbackHttp?: boolean;
  /** Canonical signed artifact bytes retained for replay; default 64 MiB. */
  maxReplayArtifactBytes?: number;
  /** Maximum restored signed commits; default 102400. */
  maxReplayCommits?: number;
  transport?: TransportOptions;
  signal?: AbortSignal;
}
export interface VerifiedSecureWorkspace {
  origin: string;
  workspace_id: string;
  sequence: number;
  head: string | null;
  policy_hash: string;
  structure_status: 'UNSTRUCTURED' | 'ACTIVE';
  objects: unknown[];
  operations: unknown[];
  recoveries: unknown[];
}
/** Advanced pinned-snapshot read. A completed snapshot does not refresh. */
export declare function readSecureSnapshot(options: SecureSnapshotOptions): Promise<VerifiedSecureWorkspace>;
export interface SecureReadOptions {
  origin: string;
  stateDir: string;
  identityPath: string;
  workspaceId: string;
  /** Required together at first contact; saved pins are used on later reads. */
  ownerActorId?: string;
  ownerKeyId?: string;
  /** Defaults to SHA-256 of the local actor ID. */
  authority?: string;
  requiredFeatures?: string[];
  allowLoopbackHttp?: boolean;
  /** Retained canonical signed artifacts; default 64 MiB. */
  maxReplayArtifactBytes?: number;
  /** Maximum restored signed commits; default 102400. */
  maxReplayCommits?: number;
  transport?: TransportOptions;
  signal?: AbortSignal;
}
/** Fetches the latest verified supported active history; failed refresh rejects. */
export declare function readSecureWorkspace(options: SecureReadOptions): Promise<VerifiedSecureWorkspace>;
/** Read verified PRIVATE state, recovering a protected direct grant when needed. */
export declare function readSecurePrivateWorkspace(options: SecureReadOptions): Promise<VerifiedSecureWorkspace>;

export interface SecureOwnerWorkspaceOptions {
  origin: string;
  stateDir: string;
  allowLoopbackHttp?: boolean;
  maxReplayArtifactBytes?: number;
  /** Maximum restored signed commits; default 102400. */
  maxReplayCommits?: number;
  transport?: TransportOptions;
}
export interface SecureOwnerWorkspaceInput {
  name: string;
  visibility: 'PUBLIC' | 'PRIVATE';
  structured?: boolean;
  keepEncrypted?: unknown[];
  coordinationVersion?: 1 | 2;
}
export interface OwnerCoordinationEnableInput {
  /** Omission defaults to v1; request v2 explicitly for the supported v1 upgrade. */
  version?: 1 | 2;
  /** Omitted: Owner for new install, no participant check when already enabled.
   * [] explicitly requests Owner and is checked on the already-enabled path too. */
  participants?: string[];
}
export interface OwnerCoordinationProgress {
  status: 'PENDING' | 'ACCEPTED';
  workspace_id: string;
  version: 1 | 2;
  protocol_digest: string;
  instance_id: string;
  begin_command_id: string | null;
  step_command_id: string | null;
  step_action_id: string | null;
  sequence: number | null;
  head: string | null;
  policy_hash: string | null;
}
export interface SecureOwnerWorkspaceResult {
  status: 'PENDING' | 'CREATED_LOCAL' | 'CREATED';
  command_id: string;
  workspace_id: string;
  visibility: 'PUBLIC' | 'PRIVATE';
  sequence: number | null;
  head: string | null;
}
export interface HistoricalOwnerAttachmentInput {
  workspaceId: string;
  protectedTsStatePath: string;
  protectedTsIntentDbPath: string;
  protectedOwnerPkcs8Path: string;
  expectedOwnerActorId: string;
  expectedOwnerKeyId: string;
  /** Opt in to exact recovery of one saved legacy Owner ACTION; stop the old client first. */
  recoverPendingAction?: boolean;
  /** Explicitly retain this exact legacy ACTION unresolved; requires recoverPendingAction. */
  retainPendingActionCommandId?: string;
  /** Exact inspected workspace command IDs to retain without submitting. */
  kernelPendingCommandIds?: string[];
  /** Required for selected IDs; obtain from inspectKernelPending. */
  expectedKernelIntentDbDigest?: string;
  /** Select one inspected saved package-stage command; attach does not POST it. */
  selectedPendingPackageStageCommandId?: string;
  /** Select an inspected original stage marker with no saved signed packet. */
  selectedOrphanPackageStageCommandId?: string;
  /** Required with either selected stage ID; digest of the whole TS state file. */
  expectedTsStateDigest?: string;
}
export interface HistoricalCoordinationIntent {
  marker_key: string; input_hash: string; action: string;
  status: "ARCHIVED_COMPLETED" | "RETAINED_UNRESOLVED" | "RETIRED_LOCAL";
  proof_sequence: number | null; proof_commit_hash: string | null;
}
export interface HistoricalOwnerAttachmentResult {
  coordination_intents: HistoricalCoordinationIntent[];
  attach_id: string;
  workspace_id: string;
  provenance: 'HISTORICAL_TS_OWNER';
  status: 'PREPARED' | 'ATTACHED_RESTRICTED' | 'ATTACHED';
  owner_actor_id: string;
  owner_key_id: string;
  sequence: number | null;
  head: string | null;
  selected_kernel_count: number;
  retained_other_kernel_count: number;
  pending_action_command_id: string | null;
  pending_action_status: 'RETAINED_UNRESOLVED' | 'ACCEPTED' | null;
  pending_package_stage_command_id: string | null;
  pending_package_stage_status: 'PENDING_UNRESOLVED' | 'PART_ACCEPTED_CONTINUATION_PENDING' | 'ACCEPTED' | null;
  pending_package_stage_id: string | null;
  /** Selected retained packet ID; completed maps have no packet and use the historical BEGIN ID. */
  pending_direct_install_command_id: string | null;
  pending_direct_install_instance_id: string | null;
  pending_direct_install_status: 'PENDING_UNRESOLVED' | 'BEGIN_ACCEPTED_CONTINUATION_PENDING' | 'ACCEPTED' | null;
  object_stage_intent_marker_hash?: string;
  pending_object_stage_command_id: string | null;
  pending_object_stage_instance_id: string | null;
  pending_object_stage_status: 'PENDING_UNRESOLVED' | 'STAGE_ACCEPTED_INSTALL_PENDING' | 'NATIVE_BEGIN_CONTINUATION_PENDING' | 'ACCEPTED' | null;
  pending_object_stage_native_begin_command_id: string | null;
  orphan_package_stage_command_id: string | null;
  orphan_package_stage_status: 'ORPHAN_NO_PACKET' | 'REPLAN_SELECTED_UNVERIFIED' | 'ORPHAN_REPLANNED' | null;
  orphan_replan_stage_id: string | null;
  orphan_replan_command_id: string | null;
}
export interface HistoricalObjectStageIntentCandidate {
  workspace_id: string; instance_id: string; marker_hash: string;
  original_command_id: string | null; original_options_hash: string;
  protocol_digest: string; part_count: number;
}
export interface HistoricalObjectStageIntentInventory {
  ts_state_digest: string; marker_hash: string; instance_id: string;
  source_id: string; protocol_digest: string; accepted_parts: number; part_count: number;
}
export interface HistoricalObjectStagePendingInventory {
  ts_state_digest: string;
  /** Original selected stage command, distinct from the later native BEGIN. */
  command_id: string;
  instance_id: string;
  source_id: string;
  protocol_digest: string;
  part_index: number;
  part_count: number;
  original_commit_hash: string;
  original_options_hash: string;
  status: 'PENDING_UNRESOLVED' | 'APPLIED_IN_SIGNED_REPLAY';
}
export interface HistoricalDirectInstallPendingInventory {
  ts_state_digest: string;
  /** Caller-selected retained BEGIN/PAGE/END packet ID. */
  command_id: string;
  instance_id: string;
  intent_hash: string;
  original_commit_hash: string;
  status: 'PENDING_UNRESOLVED' | 'APPLIED_IN_SIGNED_REPLAY';
}
/** A selected completed map verified against its signed END and current authority. */
export interface HistoricalDirectInstallCompletedInventory {
  ts_state_digest: string;
  instance_id: string;
  intent_hash: string;
  begin_command_id: string;
  begin_commit_hash: string;
  end_sequence: number;
  protocol_digest: string;
  status: 'COMPLETED_IN_SIGNED_REPLAY';
}
export interface HistoricalPackageStagePendingInventory {
  ts_state_digest: string;
  command_id: string;
  source_id: string;
  source_sha256: string;
  source_sequence: number;
  part_index: number;
  part_count: number | null;
  original_commit_hash: string | null;
  status: 'PENDING_UNRESOLVED' | 'APPLIED_IN_SIGNED_REPLAY';
}
export interface HistoricalPackageStageOrphanInventory {
  ts_state_digest: string;
  command_id: string;
  source_id: string;
  source_sha256: string;
  source_sequence: number;
  part_index: number;
  part_count: number | null;
  status: 'ORPHAN_NO_PACKET' | 'APPLIED_IN_SIGNED_REPLAY';
}
export interface HistoricalKernelCommandStatus {
  command_id: string;
  intent_digest: string;
  expires_at_ms: number;
  status: 'PENDING' | 'RETAINED_UNRESOLVED' | 'EXPIRED_UNRESOLVED' | 'ACCEPTED';
  last_http_status: number | null;
}
export interface HistoricalKernelPendingInventory {
  intent_db_digest: string;
  commands: HistoricalKernelCommandStatus[];
  retained_other_pending_count: number;
  retained_nonworkspace_pending_count: number;
}
export interface OwnerFormatTransitionInput {
  workspaceId: string;
  transition: 'UPGRADE_WIRE_V3' | 'RAISE_PRIVATE_CEILING_TWO';
  commandId?: string;
  issuedAtMs?: number;
}
export interface OwnerFormatTransitionResult {
  command_id: string;
  workspace_id: string;
  transition: 'UPGRADE_WIRE_V3' | 'RAISE_PRIVATE_CEILING_TWO';
  status: 'PENDING' | 'ACCEPTED';
  sequence: number | null;
  policy_hash: string | null;
}
export interface OwnerGuardTimeResult {
  operation_id: string;
  command_id: string;
  workspace_id: string;
  status: 'PENDING' | 'ACCEPTED' | 'ALREADY_ENABLED';
  sequence: number | null;
  head: string | null;
  policy_hash: string | null;
}
export interface OwnerGuardTimeEnableInput {
  requiredProducers?: string[];
  expectedPolicyHash: string;
  audience: string;
  serviceKey: string;
  disclosure: 'GUARD_WINDOW';
  operationId?: string;
}
export declare class OwnerWorkspaceGuardTimeClient {
  /** Bound to the selected protected Owner; use owner.guardTime(workspaceId). */
  private constructor();
  enable(input: OwnerGuardTimeEnableInput, options?: {signal?: AbortSignal}): Promise<OwnerGuardTimeResult>;
  resume(operationId: string, options?: {signal?: AbortSignal}): Promise<OwnerGuardTimeResult>;
  /** Local protected history; does not refresh remote acceptance. */
  history(options?: {signal?: AbortSignal}): Promise<OwnerGuardTimeResult[]>;
}
export interface SecureOwnerWorkspaceSession {
  memberScopes(workspaceId: string): OwnerWorkspaceMemberScopesClient;
  guardTime(workspaceId: string): OwnerWorkspaceGuardTimeClient;
  prepare(input: SecureOwnerWorkspaceInput, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  create(input: SecureOwnerWorkspaceInput, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  resume(commandId: string, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  /** Protected local history; CREATED_LOCAL rows may be reconciled by resume. */
  operations(options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult[]>;
  /** Advances at most one saved step; PENDING requires original-BEGIN recovery. */
  enableCoordination(workspaceId: string, input?: OwnerCoordinationEnableInput, options?: {signal?: AbortSignal}): Promise<OwnerCoordinationProgress>;
  resumeCoordination(workspaceId: string, beginCommandId: string, options?: {signal?: AbortSignal}): Promise<OwnerCoordinationProgress>;
  /** Local protected operation history; does not refresh remote acceptance. */
  coordinationOperations(workspaceId: string, options?: {signal?: AbortSignal}): Promise<OwnerCoordinationProgress[]>;
  /** Attach a protected existing Owner after exact local and remote proofs. */
  attach(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Read-only verified source inventory; no attach row or command POST. */
  inspectKernelPending(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalKernelPendingInventory>;
  /** Read-only inspection; no attach row or package-stage POST. */
  inspectPendingPackageStage(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStagePendingInventory>;
  /** Verify complete source material for a saved nonzero part; no attach row or POST. */
  inspectPendingMultipartPackageStage(input: HistoricalOwnerAttachmentInput, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStagePendingInventory>;
  /** Import one inspected multipart stage without POST; use its returned stage ID after signed completion. */
  attachPendingMultipartPackageStage(input: HistoricalOwnerAttachmentInput, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Explicit recovery of one selected original ADMIN stage packet. */
  recoverPendingPackageStage(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Redacted source candidates only; full options/material and signed replay are required by inspect/attach. */
  objectStageIntentCandidates(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalObjectStageIntentCandidate[]>;
  /** Select workspace from input, instance_id from original options, exact marker hash from candidates. No POST. */
  inspectObjectStageIntent(input: HistoricalOwnerAttachmentInput, markerHash: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalObjectStageIntentInventory>;
  attachObjectStageIntent(input: HistoricalOwnerAttachmentInput, markerHash: string, expectedTsStateDigest: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Explicit recovery; marker hash is not an original command ID. */
  recoverObjectStageIntent(attachId: string, markerHash: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Verify the selected final object-stage packet and full author material; no attach or POST. */
  inspectPendingObjectStage(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalObjectStagePendingInventory>;
  /** Protect the inspected plan without POST; keep its original stage ID for recovery. */
  attachPendingObjectStage(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, expectedTsStateDigest: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Explicitly reconcile the original stage and authorize its distinct native BEGIN/continuation. */
  recoverPendingObjectStage(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Verify one retained BEGIN/PAGE/END packet against explicit options and full source material; no attach row or POST. */
  inspectPendingDirectInstallBegin(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalDirectInstallPendingInventory>;
  /** Import exactly the inspected retained BEGIN/PAGE/END packet without POST; later continuation is explicit. */
  attachPendingDirectInstallBegin(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, expectedTsStateDigest: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Recover only this selected exact BEGIN/PAGE/END packet from protected attachment history. */
  recoverPendingDirectInstallBegin(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Generic name for exact retained BEGIN/PAGE/END inspection; command_id is the selected packet ID. */
  inspectPendingDirectInstallPacket(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalDirectInstallPendingInventory>;
  /** Attach the selected packet with the full inspected TS state digest; never submit a replacement packet. */
  attachPendingDirectInstallPacket(input: HistoricalOwnerAttachmentInput, selectedCommandId: string, expectedTsStateDigest: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** The ID is the selected retained packet, distinct from the installer's original BEGIN ID. */
  recoverPendingDirectInstallPacket(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Verify the caller-selected completed instance and signed END; no install POST. */
  inspectCompletedDirectInstall(input: HistoricalOwnerAttachmentInput, selectedInstanceId: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalDirectInstallCompletedInventory>;
  /** Import the inspected completed map; no retained packet or imported install operation is created. */
  attachCompletedDirectInstall(input: HistoricalOwnerAttachmentInput, selectedInstanceId: string, expectedTsStateDigest: string, optionsJson: string, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Read-only verification of an original stage marker without a signed packet. */
  inspectOrphanPackageStage(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStageOrphanInventory>;
  /** Verify complete material for an orphaned nonzero part; no attach row or POST. */
  inspectMultipartOrphanPackageStage(input: HistoricalOwnerAttachmentInput, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStageOrphanInventory>;
  /** Import an inspected orphaned nonzero part without POST; replan remains explicit. */
  attachMultipartOrphanPackageStage(input: HistoricalOwnerAttachmentInput, materialJson: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Explicitly plan one new stage; omit material only to resume a saved replan. */
  replanOrphanPackageStage(attachId: string, originalCommandId: string, materialJson?: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Protected local status only. */
  kernelCommandStatus(attachId: string, options?: {signal?: AbortSignal}): Promise<HistoricalKernelCommandStatus[]>;
  /** Explicit retry of one retained original signed JWS. */
  recoverKernelCommand(attachId: string, commandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalKernelCommandStatus>;
  /** Retain one exact signed legacy Owner ACTION without submitting or resolving it. */
  retainPendingAction(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  resumeAttachment(attachId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Retire a retained packetless local marker; sends no message or cancellation. */
  retireCoordinationIntent(attachId: string, markerKey: string, expectedInputHash: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Protected local PREPARED/ATTACHED history; PREPARED is not accepted. */
  attachments(options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult[]>;
  submitFormatTransition(input: OwnerFormatTransitionInput, options?: {signal?: AbortSignal}): Promise<OwnerFormatTransitionResult>;
  resumeFormatTransition(workspaceId: string, commandId: string, options?: {signal?: AbortSignal}): Promise<OwnerFormatTransitionResult>;
  /** Protected local PENDING/ACCEPTED history; PENDING is not accepted. */
  formatTransitions(workspaceId: string, options?: {signal?: AbortSignal}): Promise<OwnerFormatTransitionResult[]>;
  read(workspaceId: string, options?: {signal?: AbortSignal}): Promise<VerifiedSecureWorkspace>;
  /** Derive action authority and saved intent paths from verified protected Owner history. */
  publicActions(workspaceId: string): SecurePublicActionSession;
  privateActions(workspaceId: string): SecurePublicActionSession;
  /** Install a caller-selected closure into a created PUBLIC workspace. */
  publicInstaller(workspaceId: string): SecurePublicPackageInstaller;
  /** Save verified PRIVATE package parts; STAGED is not installed/ACTIVE. */
  privatePackageStager(workspaceId: string): SecurePrivatePackageStager;
  /** Install a staged PRIVATE package using protected Owner authority. */
  privatePackageInstaller(workspaceId: string): SecurePrivatePackageInstaller;
  publicAdmission(workspaceId: string): SecureOwnerAdmissionSession;
  /** PRIVATE Owner admission derives protected workspace keys and paths from creation history. */
  privateAdmission(workspaceId: string): SecureOwnerAdmissionSession;
}
export declare function openSecureOwnerWorkspaces(options: SecureOwnerWorkspaceOptions): SecureOwnerWorkspaceSession;

export interface PublicCatalogOptions {
  origin: string;
  allowLoopbackHttp?: boolean;
  /** Advisory listing response budget; default 8 MiB. */
  maxListingBytes?: number;
  transport?: TransportOptions;
}
export interface PublicCatalogListing {
  catalog_origin: string;
  listing_canonical_json: string;
  listing: unknown;
}
export interface InspectedPublicPackage {
  catalog_origin: string;
  bundle_digest: string;
  summary_canonical_json: string;
  bundle_canonical_json: string;
  summary: unknown;
  bundle: unknown;
}
export interface PublicCatalogSession {
  /** Advisory search metadata; select and inspect an exact digest before use. */
  search(query: string, options?: {after?: string; limit?: number; signal?: AbortSignal}): Promise<PublicCatalogListing>;
  /** Checks package schema and exact digest, not external publisher trust. */
  inspectExact(digest: string, options?: {signal?: AbortSignal}): Promise<InspectedPublicPackage>;
}
export declare function openPublicCatalog(options: PublicCatalogOptions): PublicCatalogSession;

export interface SecureActionReceipt {
  command_id: string;
  commit_hash: string;
  sequence: number;
  actor_id: string;
  instance_id: string;
  action_id: string;
  effects: unknown[];
}
export type SecureActionResult =
  | { status: 'PENDING'; command_id: string; workspace_id: string; action_id: string; sequence: null; commit_hash: null; receipt: null }
  | { status: 'ACCEPTED'; command_id: string; workspace_id: string; action_id: string; sequence: number; commit_hash: string; receipt: SecureActionReceipt };
export interface PendingSecureAction {
  command_id: string;
  actor_id: string;
  origin: string;
  workspace_id: string;
  action_id: string;
  request_sha256: string;
  commit_hash: string;
}
export interface SecureActionOptions {
  exactInputRefs?: unknown[];
  /** Advanced deterministic allocation control; omission uses native OS randomness. */
  allocations?: unknown[];
  commandId?: string;
  issuedAtMs?: number;
  /** Required for PRIVATE workspaces with ALL_COMMITS guard-time policy; reuse the same ID after a lost response/restart. */
  operationId?: string;
  signal?: AbortSignal;
}
export interface SecurePublicActionSession {
  submit(actionId: string, instanceId: string, body: unknown, options?: SecureActionOptions): Promise<SecureActionResult>;
  reconcile(commandId: string, options?: { signal?: AbortSignal }): Promise<SecureActionResult>;
  retrySaved(commandId: string, options?: { signal?: AbortSignal }): Promise<SecureActionResult>;
  /** Recover generated command IDs from protected local state without a journal GET. */
  pending(options?: { signal?: AbortSignal }): Promise<PendingSecureAction[]>;
}
/** Uses a protected latest-read profile; an uncertain POST stays PENDING until signed replay. */
export declare function openSecurePublicActions(options: SecureReadOptions): SecurePublicActionSession;
/** Member PRIVATE actions; never falls back to Owner history or plaintext commands. */
export declare function openSecurePrivateActions(options: SecureReadOptions): SecurePublicActionSession;

export interface RecipientEnrollmentOptions {
  origin: string;
  stateDir: string;
  allowLoopbackHttp?: boolean;
  transport?: TransportOptions;
}
export interface RecipientEnrollmentResult {
  status: 'LOCAL' | 'REGISTRATION_PENDING' | 'PUBLICATION_PENDING' | 'PUBLISHED' | 'PUBLISHED_LOCAL';
  actor_id: string;
  signing_key_id: string;
  encryption_key_id: string;
  certificate_digest: string;
  registration_command_id: string | null;
  directory_entry_hash: string | null;
}
export interface RecipientKeyUpdateResult {
  status: 'PENDING' | 'PUBLISHED';
  update_id: string;
  mode: 'ROTATE' | 'RENEW';
  previous_certificate_hash: string;
  certificate_digest: string;
  directory_version: number;
  directory_head: string;
}
export interface LegacyRecipientImportInput {
  protectedTsStatePath: string;
  expectedActorId: string;
  expectedSigningKeyId: string;
  expectedSourceDigest: string;
}
export interface LegacyRecipientImportResult {
  status: 'IMPORTED' | 'ALREADY_IMPORTED';
  actor_id: string;
  signing_key_id: string;
  certificate_digest: string;
  historical_certificates: number;
  source_digest: string;
}
export interface SecureRecipientEnrollmentSession {
  /** Protected local key creation only; no network or membership grant. */
  createLocal(): Promise<RecipientEnrollmentResult>;
  /** Credential-only pinned import; no network, membership or pending-operation import. */
  importLegacyKeys(input: LegacyRecipientImportInput): Promise<LegacyRecipientImportResult>;
  /** Reuses protected exact registration/publication bytes after uncertain replies. */
  publish(options?: { signal?: AbortSignal }): Promise<RecipientEnrollmentResult>;
  /** Local progress only; a pending status is not directory acceptance. */
  pending(): Promise<RecipientEnrollmentResult | null>;
  /** Exact signed public certificate; this alone does not prove publication. */
  certificateJson(): Promise<string>;
  /** Exact successor key/entry is protected before POST; an omitted ID is locally discoverable. */
  updateKey(mode: 'ROTATE' | 'RENEW', expectedCertificateHash: string, options?: { updateId?: string; signal?: AbortSignal }): Promise<RecipientKeyUpdateResult>;
  retryKeyUpdate(updateId: string, options?: { signal?: AbortSignal }): Promise<RecipientKeyUpdateResult>;
  /** Protected local IDs; PENDING is not directory publication. */
  pendingKeyUpdates(): Promise<RecipientKeyUpdateResult[]>;
  /** Protected local history, including previously reconciled PUBLISHED IDs. */
  keyUpdates(): Promise<RecipientKeyUpdateResult[]>;
}
export declare function openSecureRecipientEnrollment(options: RecipientEnrollmentOptions): SecureRecipientEnrollmentSession;

export interface SecureIdentityDirectoryOptions extends RecipientEnrollmentOptions {
  /** Protected reader identity; defaults to stateDir/identity.state. */
  identityPath?: string;
}
export interface VerifiedIdentityCertificate {
  actor_id: string;
  signing_key_id: string;
  directory_version: number;
  directory_head: string;
  /** Signed public certificate; this is not a membership grant. */
  certificate_json: string;
}
export interface SecureIdentityDirectorySession {
  /** Explicit peer actor/key pins are required before first contact. */
  lookup(actorId: string, signingKeyId: string, options?: { signal?: AbortSignal }): Promise<VerifiedIdentityCertificate>;
}
export declare function openSecureIdentityDirectory(options: SecureIdentityDirectoryOptions): SecureIdentityDirectorySession;

export interface AdmissionOfferResult {
  status: 'PENDING';
  invite_id: string;
  workspace_id: string;
  offer_hash: string;
}
export interface AdmissionDeliveryResult {
  status: 'PENDING' | 'AUTHORIZED';
  invite_id: string;
  grant_id: string;
  workspace_id: string;
  grant_hash: string;
}
export interface InvitationDecisionResult {
  status: 'PENDING';
  invite_id: string;
  workspace_id: string;
  decision_hash: string;
}
export interface InvitationReceiveResult {
  status: 'PENDING' | 'READY';
  invite_id: string;
  workspace_id: string;
  receipt_hash: string;
}
export interface PendingAdmissionOffer { invite_id: string; workspace_id: string; offer_hash: string; observed_responses: number }
export interface PendingAdmissionDelivery { grant_id: string; workspace_id: string; grant_hash: string; observed_responses: number }
export interface PendingInvitationDecision { invite_id: string; workspace_id: string; decision_hash: string; observed_responses: number }
export interface PendingInvitationReceipt { invite_id: string; grant_id: string; workspace_id: string; receipt_hash: string; observed_responses: number }
export interface SecureOwnerAdmissionSession {
  offer(recipientCertificateJson: string, scopes: unknown[], options?: { message?: string; inviteId?: string; issuedAtMs?: number; expiresAtMs?: number; signal?: AbortSignal }): Promise<AdmissionOfferResult>;
  retryOffer(inviteId: string, options?: { signal?: AbortSignal }): Promise<AdmissionOfferResult>;
  pendingOffers(): Promise<PendingAdmissionOffer[]>;
  deliver(inviteId: string, options?: { signal?: AbortSignal }): Promise<AdmissionDeliveryResult>;
  retryDelivery(grantId: string, options?: { signal?: AbortSignal }): Promise<AdmissionDeliveryResult>;
  pendingDeliveries(): Promise<PendingAdmissionDelivery[]>;
}
export declare function openSecurePublicAdmission(options: SecureReadOptions): SecureOwnerAdmissionSession;
export interface SecureInvitationOptions extends RecipientEnrollmentOptions {
  workspaceId: string;
  ownerActorId: string;
  ownerKeyId: string;
  authority?: string;
  requiredFeatures?: string[];
  maxReplayArtifactBytes?: number;
  /** Maximum restored signed commits; default 102400. */
  maxReplayCommits?: number;
}
export interface SecureInvitationSession {
  decide(inviteId: string, decision: 'ACCEPT' | 'DECLINE', options?: { signal?: AbortSignal }): Promise<InvitationDecisionResult>;
  retryDecision(inviteId: string, options?: { signal?: AbortSignal }): Promise<InvitationDecisionResult>;
  pendingDecisions(): Promise<PendingInvitationDecision[]>;
  receive(inviteId: string, options?: { signal?: AbortSignal }): Promise<InvitationReceiveResult>;
  retryReceive(inviteId: string, options?: { signal?: AbortSignal }): Promise<InvitationReceiveResult>;
  pendingReceipts(): Promise<PendingInvitationReceipt[]>;
}
export declare function openSecureInvitation(options: SecureInvitationOptions): SecureInvitationSession;

/** Exact locally selected package closure; digest validation does not prove publisher origin. */
export type PackageJsonValue = null | boolean | number | string | PackageJsonValue[] | { [key: string]: PackageJsonValue };
export interface PublicPackageInstallSelection {
  closureJson: string;
  /** Explicit compiler parameters; omission retains package defaults. */
  bindings?: Record<string, PackageJsonValue>;
  expectedPackageId: string;
  expectedPackageVersion: string;
  expectedPackageDigest: string;
  expectedProtocolDigest: string;
  instanceId: string;
  entrypoint: string;
  grantsJson: string;
}
export interface PublicInstallBeginResult {
  status: 'PENDING';
  command_id: string;
  workspace_id: string;
  package_id: string;
  package_version: string;
  package_digest: string;
  protocol_digest: string;
  instance_id: string;
  commit_hash: string;
}
export interface PublicInstallProgress {
  status: 'PENDING' | 'ACCEPTED';
  begin_command_id: string;
  step_command_id: string;
  step_action_id: 'secure.structure.begin' | 'secure.structure.page' | 'secure.structure.end';
  workspace_id: string;
  package_digest: string;
  protocol_digest: string;
  instance_id: string;
  commit_hash: string;
}
export interface PendingPublicInstall {
  begin_command_id: string;
  pending_step_id: string;
  pending_action_id: 'secure.structure.begin' | 'secure.structure.page' | 'secure.structure.end';
  workspace_id: string;
  package_id: string;
  package_version: string;
  package_digest: string;
  protocol_digest: string;
  instance_id: string;
}
export interface SecurePublicPackageInstaller {
  begin(selection: PublicPackageInstallSelection, options?: { commandId?: string; issuedAtMs?: number; signal?: AbortSignal }): Promise<PublicInstallBeginResult>;
  continueInstall(beginCommandId: string, options?: { signal?: AbortSignal }): Promise<PublicInstallProgress>;
  /** Lists protected pending IDs locally; it does not prove service acceptance. */
  pending(options?: { signal?: AbortSignal }): Promise<PendingPublicInstall[]>;
}
export declare function openSecurePublicPackageInstaller(options: SecureReadOptions): SecurePublicPackageInstaller;

export interface PrivatePackageStageResult {
  status: 'PENDING' | 'STAGED';
  stage_id: string;
  workspace_id: string;
  source_id: string;
  root_package_digest: string;
  protocol_digest: string;
  part_count: number;
  applied_parts: number;
  pending_command_id: string | null;
}
export interface SavedPrivatePackageStage {
  stage_id: string;
  workspace_id: string;
  source_id: string;
  root_package_digest: string;
  protocol_digest: string;
  part_count: number;
  saved_steps: number;
  locally_verified_complete: boolean;
}
export interface SecurePrivatePackageStager {
  stage(materialJson: string, expectedRootPackageDigest: string, expectedProtocolDigest: string,
    options?: {stageId?: string; commandId?: string; issuedAtMs?: number; signal?: AbortSignal}): Promise<PrivatePackageStageResult>;
  continueStage(stageId: string, options?: {signal?: AbortSignal}): Promise<PrivatePackageStageResult>;
  /** Local protected history, including completed stages; no fresh service status. */
  stages(options?: {signal?: AbortSignal}): Promise<SavedPrivatePackageStage[]>;
}
export interface PrivatePackageInstallSelection {
  stageId: string;
  instanceId: string;
  entrypoint: string;
  grantsJson: string;
  disclose?: PrivateFieldDisclosure[];
}
export interface PrivateFieldDisclosure {
  schema: string;
  fields: string[];
}
export interface PrivateDirectInstallSelection {
  closureJson: string;
  bindings?: Record<string, PackageJsonValue>;
  disclose?: PrivateFieldDisclosure[];
  expectedRootPackageDigest: string;
  expectedProtocolDigest: string;
  instanceId: string;
  entrypoint: string;
  grantsJson: string;
}
export interface PrivatePackageInstallProgress {
  status: 'PENDING' | 'ACCEPTED';
  begin_command_id: string;
  step_command_id: string;
  step_action_id: 'secure.protocol-object.stage' | 'secure.structure.begin' | 'secure.structure.page' | 'secure.structure.end';
  workspace_id: string;
  protocol_digest: string;
  instance_id: string;
  commit_hash: string;
}
export interface SavedPrivatePackageInstall {
  begin_command_id: string;
  source_kind: 'DIRECT' | 'STAGED';
  stage_id?: string;
  workspace_id: string;
  instance_id: string;
  protocol_digest: string;
  locally_saved: boolean;
  recovered_by?: string;
  phase?: 'OBJECT_STAGING';
  saved_steps?: number;
}
/** Redacted replay evidence only; never an install or action receipt. */
export interface PrivateInstallDiagnostic {
  schema: 'peerwork.install-diagnostic.v1';
  begin_command_id: string;
  verified: boolean;
  submitted: false;
  prior_sequence?: number;
  fresh_sequence?: number;
  structure_state?: string;
  begin_in_verified_history?: boolean;
  code?: 'VERIFICATION_FAILED';
  stage?: string;
  class?: string;
  check?: string;
  sequence?: number | null;
}
export interface PrivateInstallRecoveryPlan {
  schema: 'peerwork.install-recovery-plan.v1';
  original_begin_id: string;
  review_hash: string;
  recovery?: {v: 1; reason: 'INVALID_ENCRYPTED_OPERATION'; base: Record<string, PackageJsonValue>; through: Record<string, PackageJsonValue>; excluded_root: string};
  target_structure_hash?: string;
  new_begin_required?: true;
  submitted: false;
  status?: 'RECOVERED' | 'PENDING';
  operation_id?: string;
}
export interface PrivateInstallRecoveryProgress {
  schema: 'peerwork.install-recovery-progress.v1';
  original_begin_id: string;
  operation_id: string;
  status: 'PENDING' | 'ACCEPTED';
  phase: 'RECOVERY' | 'SNAPSHOT' | 'ACTIVE';
  new_begin_required: true;
}
export interface SecurePrivatePackageInstaller {
  begin(selection: PrivatePackageInstallSelection,
    options?: {commandId?: string; issuedAtMs?: number; signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  /** Select raw package closure JSON directly; no source parts are staged. */
  beginDirect(selection: PrivateDirectInstallSelection,
    options?: {commandId?: string; issuedAtMs?: number; signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  continueInstall(beginCommandId: string, options?: {signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  /** Read-only full replay; never signs or POSTs, or advances the ACTIVE slot. */
  diagnose(beginCommandId: string, options?: {signal?: AbortSignal}): Promise<PrivateInstallDiagnostic>;
  recoveryPlan(beginCommandId: string, options?: {signal?: AbortSignal}): Promise<PrivateInstallRecoveryPlan>;
  /** Explicit Owner review; repeat the exact IDs/hash after PENDING or an uncertain response. */
  recoverInvalid(beginCommandId: string, options: {expectedReviewHash: string; operationId: string; signal?: AbortSignal}): Promise<PrivateInstallRecoveryProgress>;
  /** Local saved BEGIN IDs; listing does not establish service acceptance or ACTIVE status. */
  installs(options?: {signal?: AbortSignal}): Promise<SavedPrivatePackageInstall[]>;
}


export interface ObservationEvidence { status: 'unknown'|'claimed'|'checked'; reference: string|null; }
export interface ObservationRelease { catalog_origin:string; namespace:string|null; package_id:string; version:string; bundle_digest:string; }
export type ObservationAudience = 'official_seed'|'operator_synthetic'|'external_evidenced'|'unknown';
export type ObservationOutcome = 'pass'|'fail'|'pending'|'unverified';
/** Closed native schema. Epoch milliseconds must be safe integers; refs are obs:kind:32hex. */
export interface AcquisitionEvent {
  event_id:string; occurred_at:number; environment:'production'|'staging'|'local_test';
  audience_class:ObservationAudience; principal_ref:string|null; principal_binding:ObservationEvidence;
  external_status_evidence?:ObservationEvidence|null;
  newness:'proved_new'|'first_observed'|'existing'|'unknown'; newness_evidence:ObservationEvidence;
  journey_id:string; task_ref:string|null; logical_operation_id:string; attempt_id:string;
  event_type:'qualified_start'|'discovery_observed'|'release_verified'|'adoption_selected'|'install_accepted'|
    'task_outcome_verified'|'publish_requested'|'publish_accepted'|'release_visible'|'share_reference_observed'|
    'attempt_finished'|'coverage_ended'|'correction'|'withdrawal';
  outcome:ObservationOutcome; attempt_class:'first_attempt'|'recovery'|'redundant'|'unknown';
  evidence:ObservationEvidence; observer:string; observer_version:string;
  release?:ObservationRelease|null; protocol_digest?:string|null; protocol_ref?:string|null; instance_ref?:string|null;
  association_evidence?:ObservationEvidence|null; adoption_branch?:'new_install'|'existing_install'|null;
  acceptance_predicate_ref?:string|null; signed_result_evidence?:ObservationEvidence|null;
  enrollment_timing_evidence?:ObservationEvidence|null;
  source_channel?:'mcp_search'|'agent_entry'|'canonical_share'|'repository_release'|'direct'|'unknown'|null;
  source_ref?:string|null; source_evidence?:ObservationEvidence|null; referrer_principal_ref?:string|null;
  referrer_audience_class?:ObservationAudience|null; referrer_binding?:ObservationEvidence|null;referrer_external_status_evidence?:ObservationEvidence|null;
  distinct_controller_evidence?:ObservationEvidence|null; publisher_principal_ref?:string|null;
  /** Closed native finite vocabulary; unsupported application errors use UNCLASSIFIED. */
  error_code?:string|null; active_execution_ms?:number|null; external_wait_ms?:number|null; calls?:number|null; tokens?:number|null;
  cost?:{amount_microunits:number;unit:string;basis_ref:string}|null;
  observation_end?:number|null; coverage?:'complete'|'lost'|'unknown'|null; run_kind?:'natural_agent'|'scripted'|'unknown'|null;
  workflow_outcome?:ObservationOutcome|null; supersedes?:string|null;
  client_ref?:string|null;client_version?:string|null;model_ref?:string|null;model_version?:string|null;
  instruction_ref?:string|null;instruction_version?:string|null;variant_ref?:string|null;
  source_release?:ObservationRelease|null;lineage_evidence?:ObservationEvidence|null;
}
/** Deliberate local observer attestation; not independent controller/truth verification. */
export interface ExternalPrincipalAttestation {
  attestation_id:string;principal_ref:string;binding_evidence_ref:string;external_status_evidence_ref:string;
  observer:string;observer_version:string;statement:'observer_checked_external_principal_binding';
  evidence_basis:'consented_controller_grouping'|'public_controller_evidence';
}
export interface AcquisitionAppendResult {
  event_id:string;disposition:'APPENDED'|'DUPLICATE'|'CONFLICT';observed_at:number;payload_sha256:string;records:number;
}
export interface AcquisitionRecordedObservation {event:AcquisitionEvent;observed_at:number;payload_sha256:string;}
export interface AcquisitionRecordedAttestation {attestation:ExternalPrincipalAttestation;observed_at:number;payload_sha256:string;}
export interface AcquisitionScorecardWindow {from:number;to_exclusive:number;as_of:number;}
export interface AcquisitionMetric {
  id:string;value:unknown|null;numerator:number|null;denominator:number|null;
  mature_cohort_size:number;pending:number;lost:number;unknown:number;details:unknown;
}
export interface AcquisitionScorecard {
  definition_version:number;window:AcquisitionScorecardWindow;window_complete:boolean;snapshot_sha256:string;
  visible_observations:number;excluded_synthetic_seed:number;unknown_audience_binding:number;
  conflicting_events:number;metrics:AcquisitionMetric[];coverage_scope:string;
}
export interface AcquisitionStoredScorecard {generated_at:number;scorecard:AcquisitionScorecard;}
/** Transient source bytes and minimized progress/read fields; never exported/stored as event fields. */
export interface AcquisitionInstallObservation {
  event:AcquisitionEvent;closure_json:string;bindings_json?:string|null;
  expected_package_id:string;expected_package_version:string;expected_package_digest:string;expected_protocol_digest:string;
  selected_instance_id:string;result_package_digest:string|null;result_protocol_digest:string;result_instance_id:string;
  result_status:'SELECTED'|'ACTIVE'|'ACCEPTED';result_step_action_id:string|null;result_commit_hash:string|null;
}
export interface AcquisitionObservations {
  append(event:AcquisitionEvent):Promise<AcquisitionAppendResult>;
  attestExternalPrincipal(attestation:ExternalPrincipalAttestation):Promise<AcquisitionAppendResult>;
  attestations():Promise<AcquisitionRecordedAttestation[]>;
  export():Promise<AcquisitionRecordedObservation[]>;
  snapshots():Promise<AcquisitionStoredScorecard[]>;
  scorecard(window:AcquisitionScorecardWindow):Promise<AcquisitionStoredScorecard>;
  recordCatalogResult(event:AcquisitionEvent,result:InspectedPublicPackage):Promise<AcquisitionAppendResult>;
  recordInstallResult(input:AcquisitionInstallObservation):Promise<AcquisitionAppendResult>;
  /** Caller supplies the selected instance from its signed read; accepted DTO alone does not prove task acceptance. */
  recordActionResult(event:AcquisitionEvent,selectedInstanceId:string,resultInstanceId:string,result:SecureActionResult):Promise<AcquisitionAppendResult>;
}
/** Explicit absolute protected local path. No SDK operation creates an observer implicitly. */
export declare function openAcquisitionObservations(options:{path:string;maxRecords?:number;maxStoreBytes?:number}):AcquisitionObservations;

/** Redacted generic Kernel runtime failure. Argument shape errors retain TypeError. */
export class KernelError extends Error { constructor(code: string, message: string, details?: Record<string, unknown> | null); readonly code: string; readonly details: Record<string, unknown> | null; readonly httpStatus?: number; readonly serverCode?: string; readonly phase?: string; readonly retryable?: boolean; readonly recovery?: string; }


export interface AgentContextDescriptor {
  schema: string; service_id: string; origin: string; actor_id: string;
  key_id: string; workspaces: string[]; fingerprint: string;
  execution_profile?: 'backend-structure-v1';
}
export interface AgentContextResult {
  key_history?: AcceptedResult['key_history'];
  browser_approval_reference?: string;
  opened_contents?: OpenedStructureBody[];
  schema: 'peerwork.agent-result.v1'; context: AgentContextDescriptor;
  status: string; operation_id?: string | null; result?: unknown; continuation?: unknown;
  command_id?: string; observation_command_id?: string;
}
export interface AgentProtocolActionIntent {
  document_times?:DocumentTimeSelection[];
  plaintext_contents?: {record_index: number; text: string}[];
  kind: 'protocol.action'; instance_id: string; action_id: string;
  values: unknown; refs?: unknown[];
  /** Required by backend-execution v2 contexts; no implicit revision rebase. */
  protocol_digest?: string; expected_instance_revision?: number;
  contents?: {record_index: number; body: NonNullable<BackendStructureResult['sealed_content']>}[];
}
export interface AgentStructureIntent { kind: 'structure.intent'; request: StructureIntentRequest }
export interface AgentBrowserApprovalIntent {
  kind: 'browser.approve'; reference: string; approve_writes: boolean;
}
export interface AgentInvitationFinalizeIntent { kind: 'workspace.invitation.finalize'; invite_id: string; saved_grant_id?: string }
export type AgentIntent = AgentProtocolActionIntent | AgentBrowserApprovalIntent | AgentInvitationFinalizeIntent | AgentStructureIntent;
export interface AgentContext {
  requestAccess(workspaceId: string, selection: Omit<DeviceAccessRequest, 'workspace_id'>, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  authorizeAccess(workspaceId: string, selection: Omit<DeviceAccessApproval, 'workspace_id'>, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  publishSelectedRecord(workspaceId: string, selection: Omit<PublicationSnapshotSelection, 'workspace_id'>, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  coordinateContentKeys(workspaceId: string, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  rotateContentKey(workspaceId: string, selection: {idempotency_key: string}, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  acceptContentKeys(workspaceId: string, selection: Omit<ContentKeyAcceptance, 'workspace_id'>, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  readonly descriptor: AgentContextDescriptor;
  /** Bounded verified installed index; authority summaries are advisory. */
  discover(workspaceId: string, options?: {after?: string; limit?: number; signal?: AbortSignal}): Promise<AgentContextResult>;
  describe(workspaceId: string, options: {
    instanceId?: string; protocolDigest?: string; actionId?: string; recordId?: string; revision?: number;
    objectRef?: {kind: string; id: string; revision: number}; signal?: AbortSignal;
  }): Promise<AgentContextResult>;
  inspect(workspaceId: string, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  /** v2: workspace-scoped backend intent, signed and verified without journal replay. */
  executeStructureIntent(workspaceId: string, intent: StructureIntentRequest,
    options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  /** Read-only follow from a fresh device/state directory; never resubmits the original mutation. */
  followOperation(workspaceId: string, operation: StructureOperationRef | WorkspaceDeletionRef, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  operate(workspaceId: string, intent: AgentIntent, operationId: string,
    options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  recover(workspaceId: string, options: {operationId?: string; commandId?: string; recovery?: {mode: 'reconcile' | 'safe'; maxSubmissions?: 0 | 1}; signal?: AbortSignal}): Promise<AgentContextResult>;
  exportFixture(workspaceId: string, options: {instanceIds: string[]; timeMs: number; cached?: boolean; signal?: AbortSignal}): Promise<ProtocolFixture>;
  applyPlan(workspaceId: string, plan: ProtocolActionPlan | undefined, operationId: string, options?: {signal?: AbortSignal}): Promise<Record<string, unknown>>;
  resumePlan(workspaceId: string, operationId: string, options?: {signal?: AbortSignal}): Promise<Record<string, unknown>>;
  /** v2: bounded current operation page; MINE/OPEN by default, no local history scan. */
  operations(workspaceId: string, options?: {after?: string; limit?: number; scope?: 'MINE' | 'WORKSPACE'; view?: 'OPEN' | 'HISTORY'; signal?: AbortSignal}): Promise<AgentContextResult>;
  /** Probe unchanged history; full verified replay on updates. Action receipts only, not incremental sync. */
  eventsSync(workspaceId: string, options?: {signal?: AbortSignal}): Promise<AgentContextResult>;
  /** Requested native wait budget up to 60000ms with cooperative cancellation; delivery is not task completion. */
  eventsReceive(workspaceId: string, consumerId: string, options: {
    filterVersion: string; leaseMs?: number; waitMs?: number; signal?: AbortSignal;
  }): Promise<AgentContextResult>;
  eventsAck(workspaceId: string, consumerId: string, ackToken: string, options: {
    filterVersion: string; signal?: AbortSignal;
  }): Promise<AgentContextResult>;
  eventsStatus(workspaceId: string, options?: {
    signal?: AbortSignal;
  }): Promise<AgentContextResult>;
}
/** PRIVATE member adapter with action-receipt delivery and native browser approval. */
export declare function openContext(options: {
  profilePath: string; expectedActor: string; expectedService: string; signal?: AbortSignal;
}): Promise<AgentContext>;
export class AgentContextError extends Error {
  readonly server_code?: string; readonly http_status?: number;
  readonly code: string; readonly layer?: string; readonly effect_certainty?: string;
  readonly operation_id?: string; readonly continuation?: unknown; readonly envelope: Record<string, unknown>;
  readonly stage?: string; readonly constraint?: string; readonly retryability?: string; readonly recovery_hints?: unknown;
}

export declare function bindContext(options: {
  profilePath: string; expectedActor: string; expectedService: string;
  workspaceProfiles: string[]; signal?: AbortSignal;
}): Promise<AgentContext>;
/** v2 reference binding is offline and never creates an identity or membership. */
export declare function bindStructureContext(options: {
  profilePath: string; expectedActor: string; expectedService: string; origin: string;
  identityPath: string; journalPath: string; workspaceIds: string[]; authority?: string;
  requiredFeatures?: string[]; allowLoopbackHttp?: boolean; transport?: TransportOptions; signal?: AbortSignal;
}): Promise<AgentContext>;


export interface WorkspaceLinkOptions {
  /** Registered alias returned by a verified workspace create/get result. No lookup or access grant. */
  workspaceAlias?:string|null;
  visibility?: 'PRIVATE' | 'PUBLIC'; kind?: 'workspace' | 'instance' | 'record';
  instanceId?: string | null; recordId?: string | null; entityId?: string | null; revision?: number | null;
}
export interface WorkspaceLink {
  execution_profile:'backend-structure-v1'; browser_url:string; commands_url:string; context_endpoint:string; public_read_endpoint:string; browser_origin:string; control_origin:string;
  workspace_id: string; workspace_alias:string|null; visibility: 'PRIVATE' | 'PUBLIC'; kind: string;
}
export declare class WorkspaceUrls {
  constructor(options?: {browserOrigin?:string;controlOrigin?:string;allowLoopbackHttp?:boolean});
  build(workspaceId:string,options?:WorkspaceLinkOptions):Promise<WorkspaceLink>;
  workspace(workspaceId:string,options?:WorkspaceLinkOptions):Promise<string>;
  instance(workspaceId:string,instanceId:string,options?:WorkspaceLinkOptions):Promise<string>;
  record(workspaceId:string,recordId:string,options:WorkspaceLinkOptions & {instanceId:string;revision:number}):Promise<string>;
}
export interface ChangelogSource {
  origin:string; browser_origin:string; control_origin:string; workspace_id:string;
  owner_actor_id:string; owner_key_id:string; instance_id:string|null;
  allow_loopback_http?:boolean; transport?:{request_timeout_ms?:number;additional_root_pem_files?:string[]};
}
export interface ChangelogCheckpoint {
  profile:'backend-structure-v1';control_origin:string;workspace_id:string;owner_actor_id:string;owner_key_id:string;audience:string;service_key:string;publication_revision:number;
}
export interface ChangelogEntry {record_id:string;revision:number;instance_id:string;title:string;body:string;author_actor_id:string|null;created_at:number|null;source_signer_actor_id:string;attribution_assurance:'OWNER_ATTESTED_CONVERSION'|'OWNER_ATTESTED_RECORD_SOURCE'|'AUTHOR_SIGNED_PUBLIC_ACTION';document_time?:DocumentTime|null;document_time_assurance?:'AUTHOR_SIGNATURE'|'PUBLISHER_ATTESTATION'|null;submitted_at?:number;published_at:number;url:string}
export interface ChangelogRead {source:ChangelogSource;checkpoint:ChangelogCheckpoint;entries:ChangelogEntry[];next_cursor:string|null;verification:'OWNER_PUBLICATION_SIGNATURES'|'AUTHOR_AND_OWNER_POLICY_SIGNATURES';freshness:'SERVICE_CURRENT_SELECTION';identity_required:false;metrics:{discovery_requests:number;public_requests:number;history_reads:0}}
export declare class ChangelogClient {
  constructor(options?:{source?:ChangelogSource});
  static officialSource():Promise<ChangelogSource>;
  read(options?:{limit?:number;cursor?:string|null;checkpoint?:ChangelogCheckpoint|null;signal?:AbortSignal}):Promise<ChangelogRead>;
}


export interface ReadViewFloor {
  root_hash:string;root_number:number;generation:number;
  checkpoint:{v:1;workspace_id:string;owner_id:string;owner_key:string;sequence:number;head:string|null;policy_hash:string};
}
export interface ReadViewCursor {v:1;root_hash:string;query_hash:string;after:string}
export interface AuthorizedViewRead {
  assurance:'AUTHORIZED_STATE';coverage:string;checkpoint:ReadViewFloor['checkpoint'];
  root_hash:string;floor:ReadViewFloor;objects:Array<Record<string,unknown>>;
  object?:Record<string,unknown>|null;next:ReadViewCursor|null;metrics:Record<string,number|string>;
  transport_metrics:{requests:number;response_bytes:number};
}
export declare class ReadViewError extends Error {readonly code:string}
/** Requires explicit workspace adoption; never reads the complete journal as fallback. */
export declare class PublicReadViewClient {
  constructor(options:{origin:string;workspaceId:string;ownerActorId:string;ownerKeyId:string;
    audience:string;serviceKey:string;acceptAuthorizedState:true;
    transport?:TransportOptions;allowLoopbackHttp?:boolean});
  get(kind:string,id:string,options?:{floor?:ReadViewFloor|null;signal?:AbortSignal}):Promise<AuthorizedViewRead>;
  list(instanceId:string,schema:string,options?:{limit?:number;cursor?:ReadViewCursor|null;
    floor?:ReadViewFloor|null;signal?:AbortSignal}):Promise<AuthorizedViewRead>;
}

/** Current PRIVATE reads use only already-active protected profile keys and pins. */
export declare class PrivateReadViewClient {
  constructor(options:Omit<SecureReadOptions,'signal'|'maxReplayArtifactBytes'|'maxReplayCommits'> & {acceptAuthorizedState:true});
  get(kind:string,id:string,options?:{floor?:ReadViewFloor|null;signal?:AbortSignal}):Promise<AuthorizedViewRead>;
  list(instanceId:string,schema:string,options?:{limit?:number;cursor?:ReadViewCursor|null;floor?:ReadViewFloor|null;signal?:AbortSignal}):Promise<AuthorizedViewRead>;
}


export interface CurrentPageFloor {sequence:number;head:string;policy_hash:string}
export interface CurrentPageCursor {v:1;sequence:number;head:string;query_hash:string;after:string}
export interface CurrentPageRead {
  assurance:'SERVICE_STRUCTURE_SELECTION';checkpoint:ReadViewFloor['checkpoint'];policy:Record<string,unknown>;
  floor:CurrentPageFloor;objects:Array<Record<string,unknown>>;object?:Record<string,unknown>|null;
  next:CurrentPageCursor|null;metrics:Record<string,number>;
  transport_metrics:{requests:number;response_bytes:number};
}
export interface CurrentPageOptions {floor?:CurrentPageFloor|null;signal?:AbortSignal}
export interface CurrentPageListOptions extends CurrentPageOptions {limit?:number;cursor?:CurrentPageCursor|null}
/** Existing active protected profile required; no Owner publisher or journal fallback. */
export declare class CurrentPageClient {
  constructor(options:Omit<SecureReadOptions,'signal'|'maxReplayArtifactBytes'|'maxReplayCommits'>);
  get(kind:'workspaces'|'instances'|'protocols'|'records',id:string,options?:CurrentPageOptions):Promise<CurrentPageRead>;
  instances(options?:CurrentPageListOptions):Promise<CurrentPageRead>;
  records(instanceId:string,schema?:string,options?:CurrentPageListOptions):Promise<CurrentPageRead>;
  list(instanceId:string,schema?:string,options?:CurrentPageListOptions):Promise<CurrentPageRead>;
}
export declare function openCurrentPages(options:ConstructorParameters<typeof CurrentPageClient>[0]):CurrentPageClient;

/** Offline fixture and results never establish production authorization or acceptance. */
export type ProtocolFixture = Record<string, unknown>;
export interface ProtocolTestStep { instance_id: string; action_id: string; body?: unknown; expected_instance_revision?: number; exact_input_refs?: unknown[]; allocations?: unknown[]; actor_id?: string; time_ms?: number }
export interface ProtocolSimulationResult { schema: 'peerwork.protocol-simulation-result.v1'; simulated: true; authoritative: false; assumptions: string[]; steps: Array<Record<string, unknown>>; fixture: ProtocolFixture; fixture_digest: string; input_fixture_digest: string }
export interface ProtocolActionPlan { schema: 'peerwork.protocol-plan.v1'; engine_version: string; fixture: ProtocolFixture; steps: ProtocolTestStep[]; plan_digest: string; simulated: true; authoritative: false }
export class ProtocolWorkbenchError extends Error { readonly envelope: Record<string, unknown>; readonly code: string; readonly stage?: string; readonly step?: number; readonly action_id?: string; readonly constraint?: string; readonly effect_certainty?: string; readonly retryability?: string }
export function buildProtocolFixture(options: {protocols: Array<{instance_id: string; manifest: unknown; state?: unknown}>; actors?: Array<Record<string, unknown>>; seed?: string; timeMs?: number; signal?: AbortSignal}): Promise<ProtocolFixture>;
export function simulateProtocol(options: {fixture: ProtocolFixture; steps: ProtocolTestStep[]; seed?: string; signal?: AbortSignal}): Promise<ProtocolSimulationResult>;
export function planProtocolActions(options: {fixture: ProtocolFixture; steps: ProtocolTestStep[]; seed?: string; signal?: AbortSignal}): Promise<ProtocolActionPlan>;
export function exportProtocolFixture(options: {profile: SecureReadOptions; instanceIds: string[]; timeMs: number; cached?: boolean; signal?: AbortSignal}): Promise<ProtocolFixture>;
export function applyProtocolPlan(options: {profile: SecureReadOptions; plan?: ProtocolActionPlan; operationId: string; signal?: AbortSignal}): Promise<Record<string, unknown>>;

export function protocolCompatibility(options: {requiredProducers: string[]; signal?: AbortSignal}): Promise<Record<string, unknown>>;

export function resumeProtocolPlan(options: {profile: SecureReadOptions; operationId: string; signal?: AbortSignal}): Promise<Record<string, unknown>>;


export interface MemberScope {
  instance_id: string | null;
  actions: string[];
  protocol_roles: string[];
  capabilities: string[];
  expires_at?: number | null;
}
export interface MemberScopeInspection {
  workspace_id: string; actor_id: string; role: string; read: true;
  scopes: MemberScope[]; policy_hash: string;
  checkpoint: {v: number; workspace_id: string; owner_id: string; owner_key: string;
    sequence: number; head: string | null; policy_hash: string};
  instances: {instance_id: string; protocol_digest: string; entrypoint: string | null;
    actions: string[]; protocol_roles: string[]; capabilities: string[];
    role_conflicts: string[][]; historical_role_conflicts: string[][]}[];
}
export interface MemberScopeUpdateResult {
  operation_id: string; command_id: string; workspace_id: string;
  status: 'PENDING' | 'ACCEPTED' | 'UNCHANGED' | 'SUPERSEDED';
  sequence: number | null; head: string | null; policy_hash: string | null;
}
export declare class OwnerWorkspaceMemberScopesClient {
  private constructor();
  inspect(actorId: string, options?: {signal?: AbortSignal}): Promise<MemberScopeInspection>;
  /** Replaces the entire target list. Use [] to revoke writes while preserving membership/keys. */
  set(actorId: string, input: {expectedPolicyHash: string; scopes: MemberScope[]; operationId?: string},
    options?: {signal?: AbortSignal}): Promise<MemberScopeUpdateResult>;
  /** Reconcile from authenticated journal without submitting anything. */
  recover(operationId: string, options?: {signal?: AbortSignal}): Promise<MemberScopeUpdateResult>;
  retrySaved(operationId: string, options?: {signal?: AbortSignal}): Promise<MemberScopeUpdateResult>;
  /** Local protected history; does not refresh acceptance. */
  history(options?: {signal?: AbortSignal}): Promise<MemberScopeUpdateResult[]>;
}
export interface OwnerCheckpointPreparation {
  status: 'PREPARED_OFFLINE';
  workspace_id: string;
  conversion_id: string;
  pages: number;
  records: number;
  mapping_digest: string;
  preparation_digest: string;
  output_path: string;
  network_requests: 0;
  reused?: boolean;
  body_key_status: 'AVAILABLE' | 'NOT_REQUIRED' | 'UNAVAILABLE' | 'INTEGRITY_FAILED';
  body_key_recovery_needed?: boolean;
}
/** Select mapped structure and encrypt bodies from a protected JSONL current
 * export. No network requests, history replay or source identity changes. */
export function prepareOwnerCheckpoint(options: {
  identityPath: string; expectedActor: string; origin: string; audience: string;
  sourcePath: string; planPath: string; outputPath: string; contentKeysPath?: string;
  allowLoopbackHttp?: boolean;
}): Promise<OwnerCheckpointPreparation>;

/** Pause all Owner operations before inspecting the selected ACTIVE cache.
 * Writes a protected local field/type report, never returns business values. */
export function inspectOwnerCache(options: {
  stateDir: string; workspaceId: string; reportPath: string; expectedActor?: string;cacheSelection?:'ACTIVE'|'RECOVERY'|'INSTALL';refreshSource?:boolean;
}): Promise<{
  status: 'LOCAL_REVIEW_READY'; mapping_confirmed: false; network_requests: number|null;source_refresh_requested:boolean;
  identity_copied: false; original_cache_unchanged: true;
  protocol_count: number; instance_count: number; record_count: number;
  source_frontier: {sequence: number; head: string | null; policy_hash: string};
  report_path: string; report_sha256: string;
}>;

/** Unreleased offline conversion candidate; pause selected Owner operations. */
export function planOwnerCheckpointFromCache(options: {
 stateDir:string;workspaceId:string;expectedActor:string;cacheSelection?:'ACTIVE'|'RECOVERY'|'INSTALL';refreshSource?:boolean;snapshotSha256:string;name:string;planPath:string;
}):Promise<{status:'POLICY_MAPPING_READY';policy:'BODY_ENCRYPTED_STRUCTURE_READABLE';instance_count:number;
 schema_count:number;encrypted_body_field_count:number;required_backend_features:string[];plan_path:string;
 plaintext_body_persisted:false;network_requests:number|null;source_refresh_requested:boolean;source_frontier:Record<string,unknown>}>;
/** No plaintext source snapshot or identity copy is created. */
export function prepareOwnerCheckpointFromCache(options: {
 stateDir:string;workspaceId:string;expectedActor:string;cacheSelection?:'ACTIVE'|'RECOVERY'|'INSTALL';refreshSource?:boolean;planPath:string;outputPath:string;origin:string;audience:string;allowLoopbackHttp?:boolean;
}):Promise<Omit<OwnerCheckpointPreparation,'network_requests'> & {network_requests:number|null;source_refresh_requested:boolean;source_mode:'VERIFIED_OWNER_CACHE_MEMORY';plaintext_source_persisted:false;identity_copied:false;
 context_binding:{execution_profile:'backend-structure-v1';expected_actor:string;authority:string;audience:string;workspace_ids:string[]}}>;

export interface PublicationBody {format:'PUBLIC_UTF8_BASE64';chunks:string[]}
/** Explicit public body, <=65536 UTF-8 bytes; no network side effects. */
export declare function publicationBody(text:string):PublicationBody;

export interface PublicationRead {result:{kind:'WORKSPACE'|'ENTRIES'|'ENTRY';workspace_id:string;entries?:(Record<string,unknown>&{record_id:string;instance_id:string;text:string;url:string})[];next_cursor?:string|null;[key:string]:unknown};checkpoint:ChangelogCheckpoint;assurance:'PUBLISHER_SIGNATURE_AND_SERVICE_SELECTION';identity_required:false;metrics:{discovery_requests:number;public_requests:number;history_reads:0}}
export interface PublicationReadOptions {instanceId?:string|null;limit?:number;cursor?:string|null;checkpoint?:ChangelogCheckpoint|null;order?:'RECORD_ID_ASC'|'PUBLISHED_DESC';signal?:AbortSignal}
export declare class PublicationReader {
 constructor(options:{controlOrigin:string;browserOrigin:string;workspaceId:string;ownerActorId:string;ownerKeyId:string;audience?:string;serviceKey?:string;transport?:TransportOptions;allowLoopbackHttp?:boolean});
 workspace(options?:Omit<PublicationReadOptions,'instanceId'|'cursor'>):Promise<PublicationRead>;
 list(options?:PublicationReadOptions):Promise<PublicationRead>;
 get(recordId:string,options?:Omit<PublicationReadOptions,'cursor'>):Promise<PublicationRead>;
}

export interface PublicationSnapshotSelection {
  workspace_id: string; instance_id: string; protocol_digest: string; record_id: string; revision: number;
  idempotency_key: string; expected_publication_revision?: number | null; title: string;
  disclosure: 'PUBLISH_SELECTED_CONTENT'; body: {from: 'RECORD'} | {from: 'TEXT'; text: string};
}

/** Atomically execute a granted protocol action and explicitly publish selected outputs. */
export interface PublicActionIntent extends StructureIntentRequest {
 action:'structure.action'; instance_id:string; protocol_digest:string; expected_instance_revision:number;
 plaintext_contents?:never;
 body:{action_id:string;structure:unknown;document_times?:DocumentTimeSelection[];publication:{policy_revision:number;disclosure:'PUBLISH_ACTION_AND_SELECTED_RECORDS';entries:{record_index:number;title:string;body:PublicationBody}[]}};
}

export interface PublicActionPolicyIntent extends StructureIntentRequest {
 action:'structure.publication.policy.set';instance_id:string;protocol_digest:string;
 body:{state:'ACTIVE'|'DISABLED';expected_policy_revision:number;actions:string[];disclosure:'ALLOW_AUTHOR_SIGNED_ACTION_PUBLICATION'};
}
export interface PublicEntryWithdrawal extends StructureIntentRequest {
 action:'structure.publication.entry.withdraw';instance_id:string;protocol_digest:string;
 body:{record_id:string;expected_publication_revision:number};
}

/** Withdraw one immutable version. Author or Owner; never selects an older head.
 * This removes online access and publication, while retaining signed evidence. */
export interface RecordWithdrawal extends StructureIntentRequest {
 action:'structure.record.withdraw';instance_id:string;protocol_digest:string;
 expected_instance_revision:number;
 body:{record_id:string;revision:number};
}

/** One Owner authorization closes access and schedules bounded backend purge.
 * Native execute/resume waits for signed completion within the shared budget. */
export interface WorkspaceDeletion extends StructureIntentRequest {
 action:'structure.workspace.delete';workspace_id:string;expected_workspace_revision:number;
 body:{confirm_workspace_id:string};
}

export interface WorkspaceDeletionProgress {
 workspace_id:string;owner_id:string;command_id:string;intent_digest:string;
 job_id:string;kind:'WORKSPACE_DELETE';base_revision:number;created_at:number;
 status:'ORDERED'|'APPLIED'|'VERIFICATION_BLOCKED';phase:string;removed_rows:number;
 completed_at:number|null;error_code:string|null;
 backups:'NOT_TRACKED';independent_copies:'NOT_RECALLABLE';
 source?:{actor_id:string;command_id:string;intent_digest:string;author_intent:string}|null;
 source_verification?:'VERIFIED'|'BLOCKED';
}

/** A fresh Owner Context follows this backend task without the original journal. */
export interface WorkspaceDeletionRef {kind:'WORKSPACE_DELETE';command_id:string;workspace_id?:string}

/** Author claims about the imported document, separate from service admission. */
export interface DocumentTime {created_at:string|null;updated_at:string|null}
export interface DocumentTimeSelection {record_index:number;created_at?:string|null;updated_at?:string|null}
export interface StructureRecordSource {actor_id:string;command_id:string;intent_digest:string;record_index:number;document_time?:DocumentTime;assurance?:string;legacy_source?:Record<string,unknown>}
export interface DocumentImportAction extends StructureIntentRequest {
 action:'structure.action';instance_id:string;protocol_digest:string;expected_instance_revision:number;
 body:{action_id:string;structure:unknown;document_times:DocumentTimeSelection[];publication?:never};
}

export interface ProtocolBundle {
  format: 'peerwork.protocol-bundle.v1';
  metadata: {package_id: string; version: string; description: string; license: string; credits: {name: string; url: string}[]};
  manifest: Record<string, unknown>;
  roles: Record<string, {instructions: string; tools: {name: string; action: string}[]; context: ('goal' | 'selected_state' | 'updates')[]}>;
  resources: Record<string, {media_type: 'text/markdown' | 'text/plain' | 'application/json'; text: string}>;
  dependencies: {package_digest: string}[];
}
export type ProtocolSelection = {workspace_id: string} & ({instance_id: string; package_digest?: never} | {package_digest: string; instance_id?: never});
/** Explicit client selection, not a host conversation or a new identity. */
export interface ProtocolSessionBinding {
  expected_origin: string; expected_actor: string; workspace_id: string; instance_id: string;
  protocol_digest: string; package_digest: string; role: string;
}
export interface ProtocolActionRequest {
  tool?: string; action_id?: string; values: Record<string, unknown>;
  expected_revision: number; operation_id: string;
  plaintext_contents?: {record_index: number; text: string}[];
}
/** Keep the same prepared input for retries; never refresh its CAS revision. */
export interface PreparedProtocolAction {
  format: 'peerwork.protocol-action.v1'; binding: ProtocolSessionBinding; intent: StructureIntentRequest;
}
export interface ProtocolAgentContext {
  binding: ProtocolSessionBinding; instructions: string;
  tools: {name: string; action: string; input_schema: Record<string, unknown>}[];
  context_sources: string[]; assurance: 'BACKEND_CURRENT_STATE';
}
export declare class ProtocolSessionError extends Error {code: string}
export interface ProtocolSession {
  readonly binding: ProtocolSessionBinding;
  describe(options?: {signal?: AbortSignal}): Promise<{outcome: StructureIntentOutcome; context: ProtocolAgentContext | null}>;
  state(options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  records(selection?: {limit?: number; cursor?: string; schema?: string; consistency?: 'LIVE' | 'IF_UNCHANGED'}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  updates(selection?: {limit?: number; cursor?: string; after_sequence?: number}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  record(reference: {record_id: string; revision: number}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  prepareAction(request: ProtocolActionRequest): PreparedProtocolAction;
  submit(prepared: PreparedProtocolAction, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  /** Resume the identical prepared intent through native durable recovery. */
  resume(prepared: PreparedProtocolAction, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  action(request: ProtocolActionRequest, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
}
export declare function protocolSession(kernel: KernelSession, binding: ProtocolSessionBinding): ProtocolSession;
export declare function inspectProtocolBundle(bundle: ProtocolBundle): {package_digest: string; protocol_digest: string; bundle_header: ProtocolBundleHeader; submitted: false};
export declare function protocols(kernel: KernelSession): {
  inspect(selection: ProtocolSelection & {include_resources?: boolean}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  role(selection: {workspace_id: string; instance_id: string; role: string}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  register(selection: {workspace_id: string; bundle: ProtocolBundle; idempotency_key: string}, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  adopt(selection: {workspace_id: string; idempotency_key: string; bootstrap_grant?: Record<string, unknown>} & ({bundle: ProtocolBundle; package_digest?: never} | {package_digest: string; bundle?: never}), options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
  resume(commandId: string, options?: {signal?: AbortSignal}): Promise<StructureIntentOutcome>;
};

export interface ProtocolBundleHeader extends Omit<ProtocolBundle, 'resources'> {
  protocol_digest: string;
  resources: Record<string, {sha256: string; bytes: number; media_type: string}>;
}
