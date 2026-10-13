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
  updateKey(mode: 'ROTATE' | 'RENEW', expectedCertificateHash: string, options?: { updateId?: string }): Promise<RecipientKeyUpdateResult>;
  retryKeyUpdate(updateId: string): Promise<RecipientKeyUpdateResult>;
  /** Protected local IDs; PENDING is not directory publication. */
  pendingKeyUpdates(): Promise<RecipientKeyUpdateResult[]>;
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

export interface PublicOfferResult {
  status: 'PENDING';
  invite_id: string;
  workspace_id: string;
  offer_hash: string;
}
export interface PublicDeliveryResult {
  status: 'PENDING' | 'AUTHORIZED';
  invite_id: string;
  grant_id: string;
  workspace_id: string;
  grant_hash: string;
}
export interface PublicDecisionResult {
  status: 'PENDING';
  invite_id: string;
  workspace_id: string;
  decision_hash: string;
}
export interface PublicReceiveResult {
  status: 'PENDING' | 'READY';
  invite_id: string;
  workspace_id: string;
  receipt_hash: string;
}
export interface PendingPublicOffer { invite_id: string; workspace_id: string; offer_hash: string; observed_responses: number }
export interface PendingPublicDelivery { grant_id: string; workspace_id: string; grant_hash: string; observed_responses: number }
export interface PendingPublicDecision { invite_id: string; workspace_id: string; decision_hash: string; observed_responses: number }
export interface PendingPublicReceipt { invite_id: string; grant_id: string; workspace_id: string; receipt_hash: string; observed_responses: number }
export interface SecurePublicAdmissionSession {
  offer(recipientCertificateJson: string, scopes: unknown[], options?: { message?: string; inviteId?: string; issuedAtMs?: number; expiresAtMs?: number; signal?: AbortSignal }): Promise<PublicOfferResult>;
  retryOffer(inviteId: string, options?: { signal?: AbortSignal }): Promise<PublicOfferResult>;
  pendingOffers(): Promise<PendingPublicOffer[]>;
  deliver(inviteId: string, options?: { signal?: AbortSignal }): Promise<PublicDeliveryResult>;
  retryDelivery(grantId: string, options?: { signal?: AbortSignal }): Promise<PublicDeliveryResult>;
  pendingDeliveries(): Promise<PendingPublicDelivery[]>;
}
export declare function openSecurePublicAdmission(options: SecureReadOptions): SecurePublicAdmissionSession;
export interface SecurePublicDecisionOptions extends RecipientEnrollmentOptions {
  workspaceId: string;
  ownerActorId: string;
  ownerKeyId: string;
  authority?: string;
  requiredFeatures?: string[];
  maxReplayArtifactBytes?: number;
}
export interface SecurePublicDecisionSession {
  decide(inviteId: string, decision: 'ACCEPT' | 'DECLINE', options?: { signal?: AbortSignal }): Promise<PublicDecisionResult>;
  retryDecision(inviteId: string, options?: { signal?: AbortSignal }): Promise<PublicDecisionResult>;
  pendingDecisions(): Promise<PendingPublicDecision[]>;
  receive(inviteId: string, options?: { signal?: AbortSignal }): Promise<PublicReceiveResult>;
  retryReceive(inviteId: string, options?: { signal?: AbortSignal }): Promise<PublicReceiveResult>;
  pendingReceipts(): Promise<PendingPublicReceipt[]>;
}
export declare function openSecurePublicDecision(options: SecurePublicDecisionOptions): SecurePublicDecisionSession;

/** Exact locally selected package closure; digest validation does not prove publisher origin. */
export interface PublicPackageInstallSelection {
  closureJson: string;
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
