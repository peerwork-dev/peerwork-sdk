/** Experimental native kernel command client; secure-agent replay remains incomplete. */
export declare function version(): string;
export interface CapabilityManifest {
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
export interface KernelAccessOptions {
  origin: string;
  journalPath: string;
  identityPath: string;
  requiredFeatures?: string[];
  /** Only for local development with a loopback origin. */
  allowLoopbackHttp?: boolean;
  /** Defaults to SHA-256 of the local actor ID, matching WorkspaceClient. */
  authority?: string;
  signal?: AbortSignal;
}
export interface PendingIntent { command_id: string; intent_digest: string; created_at_ms: number }
export interface AcceptedResult {
  command_id: string;
  workspace_id: string | null;
  protocol_digest: string | null;
  instance_id: string | null;
  event_sequence: number | null;
  revision: number | null;
  produced_record_ids: string[];
  catalog: CatalogAcceptedResult | null;
}
export type CatalogAcceptedResult =
  | { kind: 'namespace_claim'; namespace: string }
  | { kind: 'upload_begin'; upload_id: string; state: 'STAGING'; expires_at: number }
  | { kind: 'upload_chunk'; upload_id: string; index: number; received_bytes: number; state: 'STAGING' | 'READY' }
  | { kind: 'package_publish'; namespace: string; package_id: string; version: string; bundle_digest: string; published: number };
export interface TsMigrationReport { pending_count: number; accepted_count: number }
export interface KernelSession extends IdentityInfo {
  origin: string;
  /** Saves an exact signed request but performs no POST. */
  prepare(command: Record<string, unknown>, options?: {uploadChunk?: Buffer | Uint8Array; signal?: AbortSignal}): Promise<PendingIntent>;
  pending(options?: {signal?: AbortSignal}): Promise<PendingIntent[]>;
  status(commandId: string, options?: {signal?: AbortSignal}): Promise<{state: 'NOT_FOUND' | 'PENDING'} | {state: 'ACCEPTED'; result: AcceptedResult}>;
  submitSaved(commandId: string, options?: {signal?: AbortSignal}): Promise<AcceptedResult>;
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
}
export interface SecureOwnerWorkspaceInput {
  name: string;
  visibility: 'PUBLIC' | 'PRIVATE';
  structured?: boolean;
  keepEncrypted?: unknown[];
  coordinationVersion?: 1 | 2;
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
export interface HistoricalOwnerAttachmentResult {
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
  pending_package_stage_status: 'PENDING_UNRESOLVED' | 'ACCEPTED' | null;
  orphan_package_stage_command_id: string | null;
  orphan_package_stage_status: 'ORPHAN_NO_PACKET' | 'REPLAN_SELECTED_UNVERIFIED' | 'ORPHAN_REPLANNED' | null;
  orphan_replan_stage_id: string | null;
  orphan_replan_command_id: string | null;
}
export interface HistoricalPackageStagePendingInventory {
  ts_state_digest: string;
  command_id: string;
  source_id: string;
  source_sha256: string;
  source_sequence: number;
  status: 'PENDING_UNRESOLVED' | 'APPLIED_IN_SIGNED_REPLAY';
}
export interface HistoricalPackageStageOrphanInventory {
  ts_state_digest: string;
  command_id: string;
  source_id: string;
  source_sha256: string;
  source_sequence: number;
  status: 'ORPHAN_NO_PACKET';
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
export interface SecureOwnerWorkspaceSession {
  prepare(input: SecureOwnerWorkspaceInput, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  create(input: SecureOwnerWorkspaceInput, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  resume(commandId: string, options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult>;
  /** Protected local history; CREATED_LOCAL rows may be reconciled by resume. */
  operations(options?: {signal?: AbortSignal}): Promise<SecureOwnerWorkspaceResult[]>;
  /** Attach a protected existing Owner after exact local and remote proofs. */
  attach(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Read-only verified source inventory; no attach row or command POST. */
  inspectKernelPending(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalKernelPendingInventory>;
  /** Read-only inspection; no attach row or package-stage POST. */
  inspectPendingPackageStage(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStagePendingInventory>;
  /** Explicit recovery of one selected original ADMIN stage packet. */
  recoverPendingPackageStage(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Read-only verification of an original stage marker without a signed packet. */
  inspectOrphanPackageStage(input: HistoricalOwnerAttachmentInput, options?: {signal?: AbortSignal}): Promise<HistoricalPackageStageOrphanInventory>;
  /** Explicitly plan one new stage; omit material only to resume a saved replan. */
  replanOrphanPackageStage(attachId: string, originalCommandId: string, materialJson?: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  /** Protected local status only. */
  kernelCommandStatus(attachId: string, options?: {signal?: AbortSignal}): Promise<HistoricalKernelCommandStatus[]>;
  /** Explicit retry of one retained original signed JWS. */
  recoverKernelCommand(attachId: string, commandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalKernelCommandStatus>;
  /** Retain one exact signed legacy Owner ACTION without submitting or resolving it. */
  retainPendingAction(attachId: string, expectedCommandId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
  resumeAttachment(attachId: string, options?: {signal?: AbortSignal}): Promise<HistoricalOwnerAttachmentResult>;
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

export interface RecipientEnrollmentOptions {
  origin: string;
  stateDir: string;
  allowLoopbackHttp?: boolean;
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
export interface SecureRecipientEnrollmentSession {
  /** Protected local key creation only; no network or membership grant. */
  createLocal(): Promise<RecipientEnrollmentResult>;
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
  step_action_id: 'secure.structure.begin' | 'secure.structure.page' | 'secure.structure.end';
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
}
export interface SecurePrivatePackageInstaller {
  begin(selection: PrivatePackageInstallSelection,
    options?: {commandId?: string; issuedAtMs?: number; signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  /** Select raw package closure JSON directly; no source parts are staged. */
  beginDirect(selection: PrivateDirectInstallSelection,
    options?: {commandId?: string; issuedAtMs?: number; signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  continueInstall(beginCommandId: string, options?: {signal?: AbortSignal}): Promise<PrivatePackageInstallProgress>;
  /** Local saved BEGIN IDs; listing does not establish service acceptance or ACTIVE status. */
  installs(options?: {signal?: AbortSignal}): Promise<SavedPrivatePackageInstall[]>;
}
