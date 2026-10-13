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
