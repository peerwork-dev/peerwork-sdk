/** Versioned wire types. No server secrets and no Node dependencies in this module. */
import type {SecureRecovery} from './workspace-secure-recovery.js';
import type {StructureEnvelope,StructurePolicy} from './workspace-structure-contract.js';
export type SecureJson = null | boolean | number | string | SecureJson[] | {[key: string]: SecureJson};
export type SecureSigned<T> = {payload: T; signature: string};
export type SecureEncryptionKey = {kty: 'EC'; crv: 'P-256'; x: string; y: string};
export type SecureKeyCertificate = SecureSigned<{
  v: 1; actor_id: string; signing_key: string; encryption_key: SecureEncryptionKey;
  encryption_key_id: string; issued_at: number; expires_at: number;
}>;
export type SecureCiphertext = {v: 1; alg: 'A256GCM'; nonce: string; chunks: string[]};
/** Public, self-authenticated certificate history. Display names are not identity proofs. */
export type SecureDirectoryEntry = SecureSigned<{
  v: 1; actor_id: string; signing_key: string; version: number;
  previous: string | null; certificate: SecureKeyCertificate; issued_at: number;
}>;
export type SecureAdmissionReceipt = SecureSigned<{
  v: 1; workspace_id: string; invite_id: string; actor_id: string; signing_key: string;
  grant_hash: string; policy_hash: string; epoch: number; checkpoint: SecureCheckpoint; issued_at: number;
}>;
export type SecureKeyBox = {v: 1; suite: 'DHKEM-P256-HKDF-SHA256/HKDF-SHA256/A256GCM'; enc: string; chunks: string[]};
export type SecureScope = {instance_id: string | null; actions: string[]; protocol_roles: string[]; capabilities: string[]; expires_at?: number | null};
export type SecureMember = {actor_id: string; certificate: SecureKeyCertificate; role: 'OWNER' | 'MEMBER'; scopes: SecureScope[]};
export type SecurePolicy = SecureSigned<{
  v: 1 | 2 | 3; workspace_id: string; owner_id: string; signing_key: string;
  version: number; previous_policy: string | null; effective_sequence: number;
  visibility: 'PUBLIC' | 'PRIVATE'; epoch: number; members: SecureMember[]; issued_at: number;
  structure?: StructurePolicy;
  /** Required only by v3; authenticated independently of encrypted content. */
  protocol_format_ceiling?: 1 | 2;
  structure_mode?: 'NONE' | 'STRUCTURED';
}>;
export type SecureDelegation = SecureSigned<{
  v: 1; workspace_id: string; actor_id: string; signing_key: string;
  device: SecureKeyCertificate; request_id: string; scope: SecureScope[]; read: boolean;
  origin: string; audience: string; issued_at: number; expires_at: number;
}>;
export type SecureCommitContext = {
  v: 1 | 2 | 3; workspace_id: string; sequence: number; previous: string | null;
  policy_hash: string; epoch: number; actor_id: string; signing_key: string;
  command_id: string; action_id: string; instance_id: string | null;
  issued_at: number; delegation: SecureDelegation | null;
  structure?: StructureEnvelope;
  /** Required only by v3; also included in PRIVATE AES-GCM AAD. */
  protocol_format_ceiling?: 1 | 2;
  recovery?: SecureRecovery;
  /** Only owner-signed legacy private conversion authorization may exclude active members. */
  conversion_excluded_members?: string[];
  migration?: {source_checkpoint: SecureCheckpoint | null; source_root: string;
    source_items: {kind: string; id: string; revision: number}[]};
};
/** The entire context is AES-GCM AAD. The signature also covers mode and body. */
export type SecureCommit = SecureSigned<SecureCommitContext & (
  {mode: 'PUBLIC'; body: SecureJson} | {mode: 'PRIVATE'; body: SecureCiphertext}
)>;
export type SecureCheckpoint = {
  v: 1; workspace_id: string; owner_id: string; owner_key: string;
  sequence: number; head: string | null; policy_hash: string;
};
export type SecureKeyring = {v: 1; workspace_id: string; keys: {epoch: number; key: string}[]};
export type SecureInvitation = SecureSigned<{
  v: 1; invite_id: string; workspace_id: string; actor_id: string; signing_key: string;
  recipient: SecureKeyCertificate; policy_hash: string; scopes: SecureScope[];
  issued_at: number; expires_at: number; message: SecureKeyBox;
}>;
export type SecureInviteDecision = SecureSigned<{
  v: 1; invite_id: string; workspace_id: string; actor_id: string; signing_key: string;
  offer_hash: string; decision: 'ACCEPT' | 'DECLINE'; issued_at: number;
}>;
export type SecureInvitationCancellation = SecureSigned<{
  v: 1; invite_id: string; workspace_id: string; actor_id: string; signing_key: string;
  offer_hash: string; issued_at: number;
}>;
export type SecureKeyGrant = SecureSigned<{
  v: 1; grant_id: string; workspace_id: string; actor_id: string; signing_key: string;
  recipient: SecureKeyCertificate; policy_hash: string; epoch: number;
  invite_id: string | null; acceptance_hash: string | null;
  delegation: SecureDelegation | null; issued_at: number; box: SecureKeyBox;
}>;
/** Content object identifiers and all values occur inside the encrypted operation. */
export type SecureObject = {
  kind: string; id: string; revision: number; value: SecureJson;
  provenance: 'AUTHOR_SIGNED' | 'LEGACY_OWNER_ATTESTED';
};
export type SecureOperation = {
  v: 1; kind: 'BOOTSTRAP' | 'MIGRATE' | 'ACTION' | 'ADMIN';
  input: SecureJson; objects: SecureObject[];
};
export type SecureJournalPage = {
  workspace_id: string; state: 'ACTIVE' | 'SEALING'; visibility: 'PUBLIC' | 'PRIVATE';
  policies: SecurePolicy[]; commits: SecureCommit[]; checkpoint: SecureCheckpoint;
  next: number | null;
};
export const SECURE_DOMAINS = Object.freeze({
  certificate: 'peerwork.secure.key-certificate.v1', policy: 'peerwork.secure.policy.v1',
  policyV2: 'peerwork.secure.policy.v2', commitV2: 'peerwork.secure.commit.v2',
  policyV3: 'peerwork.secure.policy.v3', commitV3: 'peerwork.secure.commit.v3',
  commit: 'peerwork.secure.commit.v1', delegation: 'peerwork.secure.device-delegation.v1',
  invitation: 'peerwork.secure.invitation.v1', decision: 'peerwork.secure.invite-decision.v1',
  inviteCancel: 'peerwork.secure.invite-cancel.v1',
  directory: 'peerwork.secure.identity-directory.v1', admissionReceipt: 'peerwork.secure.admission-receipt.v1',
  intake: 'peerwork.secure.admission-intake.v1', intakeClose: 'peerwork.secure.admission-intake-close.v1',
  application: 'peerwork.secure.application.v1', applicationDecision: 'peerwork.secure.application-decision.v1',
  grant: 'peerwork.secure.key-grant.v1', checkpoint: 'peerwork.secure.checkpoint.v1',
  admissionBrowserRequest: 'peerwork.admission-browser.request.v1',
  admissionBrowserGrant: 'peerwork.admission-browser.grant.v1',
  configurationDelivery: 'peerwork.configuration-delivery.v1',
  configurationReceipt: 'peerwork.configuration-receipt.v1',
  admissionBrowserProof: 'peerwork.admission-browser.proof.v1',
  admissionBrowserRevoke: 'peerwork.admission-browser.revoke.v1',
});
/** Semantic version is authenticated twice: dedicated domain and signed payload. */
export function secureArtifactDomain(domain:string,payload:unknown):string{
 if(payload&&typeof payload==='object'&&'v' in payload&&payload.v===3){
  if(domain===SECURE_DOMAINS.policy)return SECURE_DOMAINS.policyV3;
  if(domain===SECURE_DOMAINS.commit)return SECURE_DOMAINS.commitV3;
 }
 if(payload&&typeof payload==='object'&&'v' in payload&&payload.v===2){
  if(domain===SECURE_DOMAINS.policy)return SECURE_DOMAINS.policyV2;
  if(domain===SECURE_DOMAINS.commit)return SECURE_DOMAINS.commitV2;
 }
 return domain;
}
export const SECURE_LIMITS = Object.freeze({
  commitBytes: 196_608, objectBytes: 98_304, journalPage: 50,
  workspaceBytes: 32 * 1024 * 1024, secureTotalBytes: 512 * 1024 * 1024, members: 128, policies: 1024,
  invitationLifetime: 7 * 86_400_000, invitationScopes: 128,
  invitationsPerWorkspace: 256, invitationBytesPerWorkspace: 32 * 1024 * 1024,
  invitationsTotal: 8192, invitationTotalBytes: 256 * 1024 * 1024,
  invitationRetention: 90 * 86_400_000,
  certificateLifetime: 366 * 86_400_000,
});
