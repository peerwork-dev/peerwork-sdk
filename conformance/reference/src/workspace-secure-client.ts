import {hydrateProtocolInstallOperation} from './workspace-protocol-object-install.js';
import type {ProtocolObjectSourceProof} from './workspace-protocol-object-source.js';
import {FORMAT_RAISE_ACTION,raisesProtocolFormat,validateProtocolFormatPolicy,validateProtocolFormatRaiseContext,validateProtocolFormatRaiseOperation} from './workspace-secure-format-transition.js';
import {validateMemberKeyTransition,validateMemberKeyOperation} from './workspace-secure-member-keys.js';
import {validateFieldPolicyOperation} from './workspace-secure-field-policy.js';
import {validateMemberScopeTransition,validateMemberScopeOperation,validateMemberScopePermissions} from './workspace-secure-permissions.js';
import {validateStructureInstall} from './workspace-secure-install.js';
import {replayCoordination,coordinationSnapshot,CoordinationError} from './workspace-coordination.js';
import type {CoordinationItem,CoordinationState} from './workspace-coordination-contract.js';
import {validateRecoveryDirective,validateV3RecoveryRange,recoveryRange,activeRecoveryMarkers,type SecureRecovery,type SecureRecoveryNotice} from './workspace-secure-recovery.js';
import {validateStructuredPolicyShape,validateStructuredCommitShape,validateV3PolicyShape,validateV3CommitShape,validateStructurePolicy,structureDelta,validateStructureEnvelope,createStructureBindingVerifier,verifyHistoricalProtocolBindings,applyStructureDelta,structureEqual,applyStructureCommit,structureSnapshotData,projectStructureRecords,projectStructureHeads} from './workspace-structure.js';
import {emptyStructureState,type StructureEnvelope,type StructureState,type StructureRecord,type StructureHead,type StructurePolicy} from './workspace-structure-contract.js';
/** Verifying client. Callers must persist the returned checkpoint atomically with local state. */
import type {SecureCheckpoint, SecureCommit, SecureCommitContext, SecureDelegation, SecureInvitation, SecureInviteDecision, SecureInvitationCancellation, SecureJson, SecureKeyCertificate, SecureKeyGrant, SecureKeyring, SecureMember, SecureObject, SecureOperation, SecurePolicy, SecureScope, SecureSigned} from './workspace-secure-contract.js';
import {SECURE_DOMAINS as D, SECURE_LIMITS as L,secureArtifactDomain} from './workspace-secure-contract.js';
import {encodeCanonicalJson, encodeBase64Url, decodeBase64Url, sha256, signCanonical, verifyCanonical, sealContent, unsealContent, hpkeSeal, hpkeOpen, importRecipientPublicKey, type SigningIdentity} from './workspace-secure-crypto.js';

import {inflateSecureFragments} from './workspace-secure-migration.js';
import {assertProtocolFormatCeiling,assertProtocolFormatCeilingOne} from './workspace-secure-format-ceiling.js';

export class SecureClientError extends Error { constructor(public code:string){super(code);} }
/** Only authenticated content/semantic failures carry a recoverable sequence. */
export class SecureContentError extends SecureClientError {
 constructor(code:string,readonly sequence:number,readonly prior:SecureCheckpoint){super(code);}
}

const fail=(code:string):never=>{throw new SecureClientError(code);};
function requireSecure(ok:unknown,code:string):asserts ok{if(!ok)fail(code);}
const integer=(n:unknown,min=0)=>typeof n==='number'&&Number.isSafeInteger(n)&&n>=min;
const token=(s:unknown)=>typeof s==='string'&&/^[A-Za-z0-9_-]{43}$/.test(s);
const digest=(s:unknown)=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const structuredPolicy=(policy:SecurePolicy)=>policy.payload.v===2||policy.payload.v===3&&policy.payload.structure_mode==='STRUCTURED';
export const secureEqual=(a:unknown,b:unknown)=>new TextDecoder().decode(encodeCanonicalJson(a))===new TextDecoder().decode(encodeCanonicalJson(b));
export async function secureHash(value:unknown):Promise<string>{return [...await sha256(encodeCanonicalJson(value))].map(b=>b.toString(16).padStart(2,'0')).join('');}
export function secureToken():string{return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));}
export async function secureActorId(key:string):Promise<string>{const prefix=new TextEncoder().encode('peerwork.identity.v1\0'),raw=decodeBase64Url(key);requireSecure(raw.length===32,'INVALID_SIGNING_KEY');const bytes=new Uint8Array(prefix.length+raw.length);bytes.set(prefix);bytes.set(raw,prefix.length);return encodeBase64Url(await sha256(bytes));}
export async function signSecure<T>(identity:SigningIdentity,domain:string,payload:T):Promise<SecureSigned<T>>{return {payload,signature:await signCanonical(secureArtifactDomain(domain,payload),payload as unknown as SecureJson,identity.privateKey)};}
export async function verifySecure(artifact:SecureSigned<unknown>,domain:string,key:string):Promise<void>{requireSecure(artifact&&Object.keys(artifact).length===2&&Object.hasOwn(artifact,'payload')&&Object.hasOwn(artifact,'signature')&&await verifyCanonical(secureArtifactDomain(domain,artifact.payload),artifact.payload as SecureJson,artifact.signature,key),'SIGNATURE_INVALID');}
export async function verifySecureCertificate(cert:SecureKeyCertificate,at?:number):Promise<void>{
 const p=cert?.payload;requireSecure(p?.v===1&&token(p.actor_id)&&token(p.signing_key)&&integer(p.issued_at)&&integer(p.expires_at,1)&&p.expires_at>p.issued_at&&p.expires_at-p.issued_at<=L.certificateLifetime,'CERTIFICATE_INVALID');
 requireSecure(await secureActorId(p.signing_key)===p.actor_id,'CERTIFICATE_IDENTITY_MISMATCH');await verifySecure(cert,D.certificate,p.signing_key);
 requireSecure(p.encryption_key?.kty==='EC'&&p.encryption_key.crv==='P-256'&&token(p.encryption_key.x)&&token(p.encryption_key.y)&&Object.keys(p.encryption_key).length===4,'CERTIFICATE_KEY_INVALID');
 requireSecure(p.encryption_key_id===encodeBase64Url(await sha256(encodeCanonicalJson(p.encryption_key))),'CERTIFICATE_KEY_MISMATCH');
 if(at!==undefined)requireSecure(integer(at)&&at>=p.issued_at&&at<p.expires_at,'CERTIFICATE_EXPIRED');
 await crypto.subtle.importKey('jwk',p.encryption_key,{name:'ECDH',namedCurve:'P-256'},false,[]).catch(()=>fail('CERTIFICATE_KEY_INVALID'));
}
function validateScopes(scopes:SecureScope[]):void{
 requireSecure(Array.isArray(scopes)&&scopes.length<=128,'SCOPE_INVALID');
 for(const s of scopes){requireSecure(s&&(s.instance_id===null||token(s.instance_id))&&Object.keys(s).every(k=>['instance_id','actions','protocol_roles','capabilities','expires_at'].includes(k))&&(s.expires_at===undefined||s.expires_at===null||integer(s.expires_at,1)),'SCOPE_INVALID');for(const list of [s.actions,s.protocol_roles,s.capabilities])requireSecure(Array.isArray(list)&&list.length<=64&&new Set(list).size===list.length&&list.every(x=>typeof x==='string'&&x.length>0&&x.length<=120),'SCOPE_INVALID');}
}
export function permitsSecure(member:SecureMember,actionId:string,instanceId:string|null):boolean{return member.scopes.some(s=>(s.instance_id===null||s.instance_id===instanceId)&&s.actions.includes(actionId));}
export async function verifyPolicyChain(policies:SecurePolicy[],workspaceId:string):Promise<Map<string,SecurePolicy>>{
 requireSecure(token(workspaceId)&&Array.isArray(policies)&&policies.length>0&&policies.length<=L.policies,'POLICY_MISSING');
 const byHash=new Map<string,SecurePolicy>();let previous:SecurePolicy|undefined,previousHash:string|null=null;
 for(const policy of policies){const p=policy?.payload;requireSecure((p?.v===1||p?.v===2||p?.v===3)&&p.workspace_id===workspaceId&&token(p.owner_id)&&token(p.signing_key)&&p.version===(previous?.payload.version??0)+1&&p.previous_policy===previousHash&&integer(p.effective_sequence,1)&&integer(p.epoch)&&integer(p.issued_at)&&['PUBLIC','PRIVATE'].includes(p.visibility),'POLICY_INVALID');
  if(p.v===3)validateV3PolicyShape(policy);
  validateProtocolFormatPolicy(previous,policy);
  if(structuredPolicy(policy)){if(p.v===2)validateStructuredPolicyShape(policy);requireSecure(p.structure,'STRUCTURE_POLICY_REQUIRED');validateStructurePolicy(p.structure);}else requireSecure(!p.structure,'STRUCTURE_VERSION_REQUIRED');
  requireSecure(!previous||!structuredPolicy(previous)||structuredPolicy(policy),'STRUCTURE_DOWNGRADE_DENIED');
  requireSecure(!previous||previous.payload.v!==3||p.v===3,'WIRE_DOWNGRADE_DENIED');
  requireSecure(await secureActorId(p.signing_key)===p.owner_id,'OWNER_KEY_MISMATCH');await verifySecure(policy,D.policy,p.signing_key);
  requireSecure(Array.isArray(p.members)&&p.members.length>0&&p.members.length<=L.members&&new Set(p.members.map(m=>m.actor_id)).size===p.members.length,'MEMBERS_INVALID');
  for(const member of p.members){requireSecure(token(member.actor_id)&&['OWNER','MEMBER'].includes(member.role)&&member.certificate.payload.actor_id===member.actor_id,'MEMBERS_INVALID');validateScopes(member.scopes);await verifySecureCertificate(member.certificate,p.issued_at);}
  requireSecure(p.members.filter(m=>m.role==='OWNER').length===1&&p.members.find(m=>m.actor_id===p.owner_id)?.role==='OWNER'&&p.members.find(m=>m.actor_id===p.owner_id)?.certificate.payload.signing_key===p.signing_key,'OWNER_MISSING');
  requireSecure(p.visibility==='PRIVATE'?p.epoch>=1:p.epoch===0,'EPOCH_INVALID');
  if(p.structure?.coordination)requireSecure(p.members.some(m=>m.actor_id===p.structure!.coordination!.coordinator),'COORDINATION_COORDINATOR_NOT_MEMBER');
  if(previous){const before=previous.payload;requireSecure(p.owner_id===before.owner_id&&p.signing_key===before.signing_key&&p.effective_sequence>before.effective_sequence&&p.issued_at>=before.issued_at&&p.epoch>=before.epoch,'POLICY_CHAIN_INVALID');requireSecure(!(before.visibility==='PRIVATE'&&p.visibility==='PUBLIC'),'PUBLICATION_UNSUPPORTED');
   const removed=before.members.some(m=>!p.members.some(n=>n.actor_id===m.actor_id&&secureEqual(n.certificate.payload.encryption_key,m.certificate.payload.encryption_key)));
   if(p.visibility==='PRIVATE'&&(removed||before.visibility==='PUBLIC'))requireSecure(p.epoch>before.epoch,'ROTATION_REQUIRED');
  }else requireSecure(p.effective_sequence===1,'GENESIS_INVALID');
  previousHash=await secureHash(policy);byHash.set(previousHash,policy);previous=policy;
 }
 return byHash;
}
export async function resolveSecureAuthor(context:SecureCommitContext,policy:SecurePolicy):Promise<SecureMember>{
 requireSecure(await secureActorId(context.signing_key)===context.actor_id,'AUTHOR_KEY_MISMATCH');
 if(context.delegation===null){const member=policy.payload.members.find(m=>m.actor_id===context.actor_id);requireSecure(member&&member.certificate.payload.signing_key===context.signing_key,'AUTHOR_NOT_MEMBER');return {...member,scopes:member.scopes.filter(s=>s.expires_at==null||s.expires_at>context.issued_at)};}
 const d=context.delegation.payload;requireSecure(d?.v===1&&d.workspace_id===context.workspace_id&&d.device.payload.actor_id===context.actor_id&&d.device.payload.signing_key===context.signing_key&&integer(d.issued_at)&&integer(d.expires_at,1)&&context.issued_at>=d.issued_at&&context.issued_at<d.expires_at,'DELEGATION_INVALID');
 const foundPrincipal=policy.payload.members.find(m=>m.actor_id===d.actor_id),principal=foundPrincipal?{...foundPrincipal,scopes:foundPrincipal.scopes.filter(s=>s.expires_at==null||s.expires_at>context.issued_at)}:undefined;requireSecure(principal&&principal.certificate.payload.signing_key===d.signing_key,'DELEGATOR_NOT_MEMBER');
 await verifySecure(context.delegation,D.delegation,d.signing_key);await verifySecureCertificate(d.device,context.issued_at);validateScopes(d.scope);
 requireSecure(d.scope.some(s=>(s.expires_at==null||s.expires_at>context.issued_at)&&(s.instance_id===null||s.instance_id===context.instance_id)&&s.actions.includes(context.action_id))&&permitsSecure(principal,context.action_id,context.instance_id),'DELEGATION_SCOPE_DENIED');
 return {...principal,role:'MEMBER',scopes:d.scope.filter(s=>s.expires_at==null||s.expires_at>context.issued_at).map(s=>({...s,protocol_roles:s.protocol_roles.filter(x=>principal.scopes.some(g=>(g.instance_id===null||g.instance_id===context.instance_id)&&g.protocol_roles.includes(x))),capabilities:s.capabilities.filter(x=>principal.scopes.some(g=>(g.instance_id===null||g.instance_id===context.instance_id)&&g.capabilities.includes(x)))}))};
}
export function commitContext(commit:SecureCommit):SecureCommitContext {const {mode:_mode,body:_body,...context}=commit.payload;return context;}
async function importEpoch(keyring:SecureKeyring|undefined,workspaceId:string,epoch:number):Promise<CryptoKey>{requireSecure(keyring?.v===1&&keyring.workspace_id===workspaceId,'KEYRING_REQUIRED');const key=keyring.keys.find(k=>k.epoch===epoch);requireSecure(key&&decodeBase64Url(key.key).length===32,'EPOCH_KEY_MISSING');return crypto.subtle.importKey('raw',decodeBase64Url(key.key) as Uint8Array<ArrayBuffer>,{name:'AES-GCM'},false,['encrypt','decrypt']);}
export function newSecureKeyring(workspaceId:string,epoch=1):SecureKeyring{return {v:1,workspace_id:workspaceId,keys:[{epoch,key:secureToken()}]};}
export function rotateSecureKeyring(keyring:SecureKeyring,epoch:number):SecureKeyring{requireSecure(integer(epoch,1)&&keyring.keys.every(k=>k.epoch<epoch),'EPOCH_INVALID');return {...keyring,keys:[...keyring.keys,{epoch,key:secureToken()}]};}
/** Derived only from successfully replayed signed installation commits; not a service receipt. */
export type VerifiedProtocolInstallation={instance_id:string;protocol_digest:string;entrypoint:string;source:SecureCheckpoint;command_id:string;object_source?:ProtocolObjectSourceProof};
export type VerifiedActionEffect={record_id:string;revision:number;schema_ref:string;entity_id:string|null};
export type VerifiedActionReceipt={command_id:string;commit_hash:string;sequence:number;actor_id:string;instance_id:string;action_id:string;effects:VerifiedActionEffect[]};
export type SecureVerifiedJournal={synchronization?:{mode:'DELTA_TRANSFER'|'FULL_TRANSFER';pages:number;downloaded_commits:number;downloaded_policies:number;cached_commits:number;cache_status:'SAVED'|'NOT_PRIVATE'|'CAPACITY'|'WRITE_FAILED';verification:'FULL_REPLAY'|'INCREMENTAL_REPLAY';replayed_commits:number;reused_commits:number;replay_cache_retained:boolean;coverage:'COMPLETE_THROUGH_CHECKPOINT';freshness:'SERVER_OBSERVATION'};installations?:VerifiedProtocolInstallation[];checkpoint:SecureCheckpoint;policy:SecurePolicy;operations:SecureOperation[];objects:SecureObject[];trust:'PINNED'|'UNPINNED';legacy:boolean;coordination?:CoordinationItem[];recoveries:SecureRecoveryNotice[];structure?:{state:'ACTIVE'|'SEEDING';records:StructureRecord[];heads:StructureHead[];snapshot?:StructureEnvelope['snapshot']}};
/** Historical anchors exist only on a completed verification result, never service-labelled objects. */
const verifiedCheckpointHistory=new WeakMap<SecureVerifiedJournal,{base:SecureCheckpoint;hashes:Map<number,string>;policies:{sequence:number;hash:string}[]}>();
const verifiedActionHistory=new WeakMap<SecureVerifiedJournal,VerifiedActionReceipt[]>();
/** A receipt exists only for an ACTION in this journal's fully replayed signed commits. */
export function verifiedJournalAction(journal:SecureVerifiedJournal,commandId:string):VerifiedActionReceipt|undefined{
 const receipts=verifiedActionHistory.get(journal);requireSecure(receipts,'VERIFIED_ACTION_JOURNAL_REQUIRED');
 const found=receipts.find(receipt=>receipt.command_id===commandId);return found?structuredClone(found):undefined;
}
export function verifiedJournalCheckpoint(journal:SecureVerifiedJournal,sequence:number):SecureCheckpoint{
 const history=verifiedCheckpointHistory.get(journal);requireSecure(history&&integer(sequence,1)&&sequence<=history.base.sequence&&history.hashes.has(sequence),'VERIFIED_CHECKPOINT_REQUIRED');
 const policy=history.policies.filter(p=>p.sequence<=sequence).at(-1);requireSecure(policy,'VERIFIED_CHECKPOINT_REQUIRED');return {...history.base,sequence,head:history.hashes.get(sequence)!,policy_hash:policy.hash};
}
async function restoreSealedPublicHistory(commits:SecureCommit[],policies:Map<string,SecurePolicy>,workspaceId:string,keyring?:SecureKeyring):Promise<{commits:SecureCommit[];source?:SecureCheckpoint}>{
 if(!commits.length||commits[0]!.payload.sequence===1)return {commits};
 const first=commits[0]!,source=first.payload.migration?.source_checkpoint;requireSecure(source&&source.workspace_id===workspaceId&&source.sequence===first.payload.sequence-1&&source.head===first.payload.previous,'ARCHIVED_HISTORY_MISSING');
 const archiveObjects:SecureObject[]=[];const originals=new Map<number,SecureCommit>();let prior:string|null=source.head,sequence=source.sequence;
 for(const commit of commits){const p=commit.payload;if(!p.migration)break;const policy=policies.get(p.policy_hash);requireSecure(policy&&p.workspace_id===workspaceId&&p.mode==='PRIVATE'&&p.sequence===sequence+1&&p.previous===prior&&p.actor_id===policy.payload.owner_id&&p.signing_key===policy.payload.signing_key&&p.delegation===null&&p.epoch===policy.payload.epoch&&secureEqual(p.migration.source_checkpoint,source),'ARCHIVE_CONTEXT_INVALID');
  await verifySecure(commit,D.commit,p.signing_key);const raw=await unsealContent(await importEpoch(keyring,workspaceId,p.epoch),p.body,commitContext(commit)),operation=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)) as SecureOperation;requireSecure(operation.kind==='MIGRATE'&&Array.isArray(operation.objects)&&new TextDecoder('utf-8',{fatal:true}).decode(raw)===new TextDecoder().decode(encodeCanonicalJson(operation)),'ARCHIVE_OPERATION_INVALID');
  archiveObjects.push(...operation.objects);
  sequence=p.sequence;prior=await secureHash(commit);
 }
  for(const object of await inflateSecureFragments(archiveObjects)){if(object.kind!=='secure_commits')continue;let original=object.value as unknown as SecureCommit; // Migration exports may retain the row's exact artifact bytes.
   if(object.value&&typeof object.value==='object'&&!Array.isArray(object.value)&&typeof object.value.artifact==='string')original=JSON.parse(object.value.artifact);
   const n=original?.payload?.sequence;requireSecure(integer(n,1)&&n<=source.sequence&&original.payload.workspace_id===workspaceId&&original.payload.mode==='PUBLIC'&&!originals.has(n),'ARCHIVE_RECORD_INVALID');originals.set(n,original);
  }
 requireSecure(originals.size===source.sequence,'ARCHIVED_HISTORY_INCOMPLETE');return {commits:[...originals.entries()].sort((a,b)=>a[0]-b[0]).map(([,c])=>c).concat(commits),source};
}
/** Authenticate the complete control history without trusting or decrypting content. */
export async function verifyJournalHeaders(input:Parameters<typeof verifyJournal>[0]):Promise<Map<number,string>>{
 const byHash=await verifyPolicyChain(input.policies,input.workspaceId),genesis=input.policies[0]!.payload,latest=input.policies.at(-1)!,restored=await restoreSealedPublicHistory(input.commits,byHash,input.workspaceId,input.keyring),hashes=new Map<number,string>(),ids=new Set<string>();let head:string|null=null,sequence=0;
 const owner=input.trustedOwner??(input.pinned?{actorId:input.pinned.owner_id,key:input.pinned.owner_key}:undefined);if(owner)requireSecure(owner.actorId===genesis.owner_id&&owner.key===genesis.signing_key,'PINNED_OWNER_MISMATCH');
 for(const commit of restored.commits){const p=commit?.payload;requireSecure(p&&(p.v===1||p.v===2||p.v===3)&&p.workspace_id===input.workspaceId&&p.sequence===sequence+1&&p.previous===head&&integer(p.issued_at)&&token(p.actor_id)&&token(p.signing_key)&&token(p.command_id)&&typeof p.action_id==='string'&&p.action_id.length>0&&p.action_id.length<=120&&(p.instance_id===null||token(p.instance_id))&&encodeCanonicalJson(commit).byteLength<=L.commitBytes,'COMMIT_CONTEXT_INVALID');
  requireSecure(!ids.has(p.command_id),'COMMIT_REPLAY');ids.add(p.command_id);const policy=byHash.get(p.policy_hash),active=input.policies.filter(q=>q.payload.effective_sequence<=p.sequence).at(-1);requireSecure(policy&&policy===active&&policy.payload.epoch===p.epoch&&policy.payload.visibility===p.mode&&policy.payload.v===p.v,'COMMIT_POLICY_INVALID');if(p.v===2)validateStructuredCommitShape(commit);if(p.v===3)validateV3CommitShape(commit,policy);
  await verifySecure(commit,D.commit,p.signing_key);const author=await resolveSecureAuthor(commitContext(commit),policy);requireSecure(author.role==='OWNER'&&p.instance_id===null||permitsSecure(author,p.action_id,p.instance_id),'AUTHOR_SCOPE_DENIED');
  head=await secureHash(commit);sequence=p.sequence;hashes.set(sequence,head);
 }
 requireSecure(latest.payload.effective_sequence<=Math.max(1,sequence)&&secureEqual(input.checkpoint,{v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head,policy_hash:await secureHash(latest)}),'JOURNAL_TRUNCATED_OR_HEAD_INVALID');
 if(input.pinned){const pin=input.pinned,policy=input.policies.filter(p=>p.payload.effective_sequence<=Math.max(1,pin.sequence)).at(-1);requireSecure(pin.workspace_id===input.workspaceId&&integer(pin.sequence)&&pin.sequence<=sequence&&(pin.sequence===0?pin.head===null:pin.head===hashes.get(pin.sequence)),'ROLLBACK_OR_FORK_DETECTED');requireSecure(policy&&await secureHash(policy)===pin.policy_hash,'POLICY_ROLLBACK');}
 return hashes;
}

export type SecureJournalInput={workspaceId:string;policies:SecurePolicy[];commits:SecureCommit[];checkpoint:SecureCheckpoint;pinned?:SecureCheckpoint;trustedOwner?:{actorId:string;key:string};keyring?:SecureKeyring;validateOperation?:(operation:SecureOperation,context:SecureCommitContext,policy:SecurePolicy,objects:SecureObject[])=>Promise<void>};
/** Internal replay state is never accepted from serialized or caller-labelled objects. */
type JournalReplayState={workspaceId:string;rawCount:number;sequence:number;previous:string|null;objects:Map<string,SecureObject>;operations:SecureOperation[];actionReceipts:VerifiedActionReceipt[];commandIds:Set<string>;roleHistory:Map<string,Set<string>>;legacy:boolean;migrationRoot?:string;migrationSource?:SecureCheckpoint|null;migrationFormat?:1|2|3;migrationDone:boolean;migrationItems:{kind:string;id:string;revision:number}[];migrationObjects:SecureObject[];priorMode?:'PUBLIC'|'PRIVATE';structure?:StructureState;expectedSnapshot?:{records:StructureRecord[];heads:StructureHead[]};hashes:Map<number,string>;recoveries:SecureRecoveryNotice[];installations:VerifiedProtocolInstallation[];coordinationState?:CoordinationState};
export async function verifyJournal(input:SecureJournalInput,recoveryProbes=new Map<number,SecureContentError>(),recoveryDepth=0):Promise<SecureVerifiedJournal>{return verifyJournalInternal(input,recoveryProbes,recoveryDepth);}
const HISTORICAL_PROTOCOL_VALIDATOR_REVISION=4;
/** One bounded, process-local replay entry. No cache input or serialized trust labels are accepted. */
export function createJournalVerifier(options:{maxBytes?:number}={}){
 const maxBytes=options.maxBytes??L.workspaceBytes;requireSecure(integer(maxBytes)&&maxBytes<=L.workspaceBytes,'VERIFIER_CACHE_LIMIT_INVALID');
 type Entry={state:JournalReplayState;prefixHash:string;policyHash:string;keyHash:string;validator:SecureJournalInput['validateOperation'];historicalProtocolValidatorRevision:number};
 let entry:Entry|undefined,generation=0,tail=Promise.resolve();
 return {
  clear(){generation++;entry=undefined;},
  verify(input:SecureJournalInput):Promise<{journal:SecureVerifiedJournal;replay:{mode:'FULL_REPLAY'|'INCREMENTAL_REPLAY';replayed_commits:number;reused_commits:number;retained:boolean}}>{
   // Own the artifacts before the first await; later caller mutation cannot change the verified cut.
   const {validateOperation,...data}=input,owned:SecureJournalInput={...structuredClone(data),...(validateOperation?{validateOperation}:{})},epoch=generation;
   const run=tail.then(async()=>{
    const prior=epoch===generation?entry:undefined,[policyHash,keyHash]=await Promise.all([secureHash(owned.policies),secureHash(owned.keyring??null)]);
    let resume:JournalReplayState|undefined;
    if(prior&&prior.historicalProtocolValidatorRevision===HISTORICAL_PROTOCOL_VALIDATOR_REVISION&&prior.state.workspaceId===owned.workspaceId&&prior.validator===validateOperation&&prior.policyHash===policyHash&&prior.keyHash===keyHash&&owned.commits.length>=prior.state.rawCount){
     const suffix=owned.commits.slice(prior.state.rawCount);
     // A new recovery can invalidate earlier semantics; a conversion can replace the archive.
     if(!suffix.some(c=>c.payload.recovery||c.payload.migration)&&await secureHash(owned.commits.slice(0,prior.state.rawCount))===prior.prefixHash)resume=structuredClone(prior.state);
    }
    let captured:JournalReplayState|undefined;
    const journal=await verifyJournalInternal(owned,new Map(),0,resume,state=>{captured=state;},true);
    let retained=false;
    if(epoch===generation&&captured){
     const bytes=new TextEncoder().encode(JSON.stringify(captured,(_key,value)=>value instanceof Map||value instanceof Set?[...value]:value)).byteLength;
     if(bytes<=maxBytes){const prefixHash=await secureHash(owned.commits);if(epoch===generation){entry={state:structuredClone(captured),prefixHash,policyHash,keyHash,validator:validateOperation,historicalProtocolValidatorRevision:HISTORICAL_PROTOCOL_VALIDATOR_REVISION};retained=true;}}
     else entry=undefined;
    }
    return {journal,replay:{mode:resume?'INCREMENTAL_REPLAY' as const:'FULL_REPLAY' as const,replayed_commits:journal.checkpoint.sequence-(resume?.sequence??0),reused_commits:resume?.sequence??0,retained}};
   });
   tail=run.then(()=>undefined,()=>undefined);return run;
  },
 };
}
async function verifyJournalInternal(input:SecureJournalInput,recoveryProbes=new Map<number,SecureContentError>(),recoveryDepth=0,resume?:JournalReplayState,capture?:(state:JournalReplayState)=>void,ownedReplay=false):Promise<SecureVerifiedJournal>{
 const structureVerifier=createStructureBindingVerifier();
 try{return await verifyJournalInternalWithStructureVerifier(input,recoveryProbes,recoveryDepth,resume,capture,structureVerifier.verify,ownedReplay);}
 finally{structureVerifier.dispose();}
}
async function verifyJournalInternalWithStructureVerifier(input:SecureJournalInput,recoveryProbes:Map<number,SecureContentError>,recoveryDepth:number,resume:JournalReplayState|undefined,capture:((state:JournalReplayState)=>void)|undefined,verifyStructureBindingsForReplay:(policy:StructurePolicy,objects:SecureObject[],workspaceId:string)=>Promise<void>,ownedReplay:boolean):Promise<SecureVerifiedJournal>{
 requireSecure(recoveryDepth<=32,'RECOVERY_DEPTH_LIMIT');
 const byHash=await verifyPolicyChain(input.policies,input.workspaceId),genesis=input.policies[0]!.payload,latest=input.policies.at(-1)!;
 const restored=resume?{commits:input.commits.slice(resume.rawCount),source:undefined}:await restoreSealedPublicHistory(input.commits,byHash,input.workspaceId,input.keyring),commits=restored.commits;
 const recoveryMarkers=resume?[]:activeRecoveryMarkers(commits),recoveries:SecureRecoveryNotice[]=resume?.recoveries??[],installations:VerifiedProtocolInstallation[]=resume?.installations??[];
 const hashes=resume?.hashes??new Map<number,string>();if(recoveryMarkers.length){await verifyJournalHeaders({...input,commits});for(const c of commits)hashes.set(c.payload.sequence,await secureHash(c));
  for(const marker of recoveryMarkers){const policy=byHash.get(marker.payload.policy_hash);requireSecure(policy,'COMMIT_POLICY_INVALID');const r=validateRecoveryDirective(marker,policy);if(marker.payload.v===3)validateV3RecoveryRange(commits,r);requireSecure(await secureHash(recoveryRange(commits,r,hashes))===r.excluded_root,'RECOVERY_ROOT_MISMATCH');}
 }
 const trusted=input.trustedOwner??(input.pinned?{actorId:input.pinned.owner_id,key:input.pinned.owner_key}:undefined);
 if(trusted)requireSecure(trusted.actorId===genesis.owner_id&&trusted.key===genesis.signing_key,'PINNED_OWNER_MISMATCH');
 if(input.pinned)requireSecure(input.pinned.workspace_id===input.workspaceId&&integer(input.pinned.sequence)&&input.pinned.sequence<=(resume?.sequence??0)+commits.length,'ROLLBACK_DETECTED');
 if(resume&&input.pinned&&input.pinned.sequence<=resume.sequence)requireSecure(input.pinned.sequence===0?input.pinned.head===null:hashes.get(input.pinned.sequence)===input.pinned.head,'FORK_DETECTED');
 let structure:StructureState|undefined=resume?.structure,expectedSnapshot:{records:StructureRecord[];heads:StructureHead[]}|undefined=resume?.expectedSnapshot;
 let previous:string|null=resume?.previous??null,sequence=resume?.sequence??0;const objects=resume?.objects??new Map<string,SecureObject>(),operations:SecureOperation[]=resume?.operations??[],actionReceipts:VerifiedActionReceipt[]=resume?.actionReceipts?[...resume.actionReceipts]:[];const commandIds=resume?.commandIds??new Set<string>();const roleHistory=resume?.roleHistory??new Map<string,Set<string>>();let legacy=resume?.legacy??false;let migrationRoot=resume?.migrationRoot,migrationSource=resume?.migrationSource,migrationFormat=resume?.migrationFormat,migrationDone=resume?.migrationDone??false;const migrationItems=resume?.migrationItems??[],migrationObjects:SecureObject[]=resume?.migrationObjects??[];let priorMode=resume?.priorMode;
 // This token exists only inside a replay that cloned its input before awaiting.
 // Public verifyJournal and caller-provided validators keep every binding check.
 const builtInValidator=ownedReplay?(await import('./workspace-secure-engine.js')).validateSecureOperation:undefined;
 const reuseBindings=ownedReplay&&(input.validateOperation===undefined||input.validateOperation===builtInValidator);
 let boundPolicyHash:string|undefined,boundInstances:Map<string,{revision:number;protocolDigest:unknown}>|undefined;
 const instanceProjection=(candidate:SecureObject[])=>{const result=new Map<string,{revision:number;protocolDigest:unknown}>();for(const object of candidate)if(object.kind==='instances'){const prior=result.get(object.id);if(!prior||prior.revision<object.revision)result.set(object.id,{revision:object.revision,protocolDigest:(object.value as any)?.protocol_digest});}return result;};
 const completedObjects=()=>{if(!migrationRoot||migrationDone)return [...objects.values()];const pending=new Set(migrationObjects.map(object=>JSON.stringify([object.kind,object.id,object.revision])));return [...objects].filter(([key])=>!pending.has(key)).map(([,object])=>object);};
 const finishMigration=async()=>{if(!migrationRoot||migrationDone)return;const sorted=[...migrationItems].sort((a,b)=>{const x=new TextDecoder().decode(encodeCanonicalJson(a)),y=new TextDecoder().decode(encodeCanonicalJson(b));return x<y?-1:x>y?1:0;});requireSecure(new Set(sorted.map(x=>new TextDecoder().decode(encodeCanonicalJson(x)))).size===sorted.length&&await secureHash(sorted)===migrationRoot,'MIGRATION_INCOMPLETE');const inflated=await inflateSecureFragments(migrationObjects),candidate=new Map(objects),protocols=inflated.filter(object=>object.kind==='protocols');requireSecure(new Set(protocols.map(object=>object.id)).size===protocols.length,'MIGRATION_PROTOCOL_DUPLICATE');for(const object of inflated){const key=JSON.stringify([object.kind,object.id,object.revision]);if(candidate.has(key)){requireSecure(secureEqual(candidate.get(key),object),'MIGRATION_OBJECT_CONFLICT');}else candidate.set(key,object);}for(const [key,object] of candidate)if(object.kind==='secure_fragment')candidate.delete(key);requireSecure(migrationFormat===1||migrationFormat===2||migrationFormat===3,'MIGRATION_FORMAT_INVALID');if(migrationFormat===3)await assertProtocolFormatCeilingOne([...candidate.values()]);if(protocols.length)await verifyHistoricalProtocolBindings([...candidate.values()],input.workspaceId,migrationFormat===3?1:migrationFormat);boundPolicyHash=undefined;boundInstances=undefined;objects.clear();for(const [key,object] of candidate)objects.set(key,object);migrationDone=true;};
 for(const commit of commits){const p=commit.payload,context=commitContext(commit);requireSecure((p?.v===1||p?.v===2||p?.v===3)&&p.workspace_id===input.workspaceId&&p.sequence===sequence+1&&p.previous===previous&&integer(p.issued_at)&&token(p.actor_id)&&token(p.signing_key)&&token(p.command_id)&&typeof p.action_id==='string'&&p.action_id.length>0&&p.action_id.length<=120&&(p.instance_id===null||token(p.instance_id))&&encodeCanonicalJson(commit).byteLength<=L.commitBytes,'COMMIT_CONTEXT_INVALID');
  requireSecure(!commandIds.has(p.command_id),'COMMIT_REPLAY');commandIds.add(p.command_id);
  const policy=byHash.get(p.policy_hash),active=input.policies.filter(q=>q.payload.effective_sequence<=p.sequence).at(-1);requireSecure(policy&&policy===active&&policy.payload.epoch===p.epoch&&policy.payload.visibility===p.mode&&p.v===policy.payload.v,'COMMIT_POLICY_INVALID');
  if(p.v===2)validateStructuredCommitShape(commit);if(p.v===3)validateV3CommitShape(commit,policy);
  await verifySecure(commit,D.commit,p.signing_key);const author=await resolveSecureAuthor(context,policy);
  const priorPolicy=input.policies.filter(q=>q.payload.effective_sequence<=Math.max(1,sequence)).at(-1)!;
  const wireUpgrade=priorPolicy.payload.v!==3&&policy.payload.v===3&&priorPolicy.payload.visibility===p.mode;
  const disposition=recoveryMarkers.find(c=>p.sequence>c.payload.recovery!.base.sequence&&p.sequence<=c.payload.recovery!.through.sequence);
  if(disposition){const r=disposition.payload.recovery!;
   boundPolicyHash=undefined;boundInstances=undefined;
   requireSecure(!wireUpgrade,'RECOVERY_WIRE_UPGRADE_EXCLUDED');requireSecure(!raisesProtocolFormat(priorPolicy,policy),'RECOVERY_FORMAT_UPGRADE_EXCLUDED');
   if(disposition.payload.v===3)await validateV3RecoveryOperation(commit,input.keyring);
   requireSecure(author.role==='OWNER'&&p.instance_id===null||permitsSecure(author,p.action_id,p.instance_id),'AUTHOR_SCOPE_DENIED');
   if(p.sequence===r.base.sequence+1){
    requireSecure(secureEqual(r.base,{v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head:previous,policy_hash:await secureHash(input.policies.filter(q=>q.payload.effective_sequence<=sequence).at(-1)!)}),'RECOVERY_BASE_MISMATCH');
    if(!recoveryProbes.has(p.sequence)){
     const policies=input.policies.filter(q=>q.payload.effective_sequence<=p.sequence),checkpoint:SecureCheckpoint={v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence:p.sequence,head:hashes.get(p.sequence)!,policy_hash:p.policy_hash};let failure:unknown;
     try{await verifyJournal({...input,policies,commits:commits.filter(c=>c.payload.sequence<=p.sequence),checkpoint,pinned:input.pinned&&input.pinned.sequence<=p.sequence?input.pinned:undefined},recoveryProbes,recoveryDepth+1);}catch(error){failure=error;}
     if(failure===undefined||failure instanceof SecureContentError&&failure.sequence!==p.sequence)throw new SecureContentError('RECOVERY_FAILURE_NOT_REPRODUCED',disposition.payload.sequence,r.through);
     if(!(failure instanceof SecureContentError))throw failure;recoveryProbes.set(p.sequence,failure);
    }
   }
   await (await import('./workspace-secure-engine.js')).validateSecureRolePolicies(policy,[...objects.values()],roleHistory,p.issued_at,null);
   previous=hashes.get(p.sequence)!;sequence=p.sequence;continue;
  }
  // Missing/wrong-format key material is not a content failure eligible for recovery.
  const epochKey=p.mode==='PRIVATE'?await importEpoch(input.keyring,input.workspaceId,p.epoch):undefined;
  const priorCheckpointForError:SecureCheckpoint={v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head:previous,policy_hash:await secureHash(priorPolicy)};
  try{
  let operation:SecureOperation;if(p.mode==='PRIVATE'){const raw=await unsealContent(epochKey!,p.body,context);operation=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));requireSecure(new TextDecoder('utf-8',{fatal:true}).decode(raw)===new TextDecoder().decode(encodeCanonicalJson(operation)),'CONTENT_NONCANONICAL');}else operation=p.body as unknown as SecureOperation;
  const wireOperation=operation;let protocolObjectSource:ProtocolObjectSourceProof|undefined;
  if(p.recovery){validateRecoveryDirective(commit,policy);requireSecure(secureEqual(operation,{v:1,kind:'ADMIN',input:{},objects:[]}),'RECOVERY_OPERATION_INVALID');}
  else requireSecure(p.action_id!=='secure.recover','RECOVERY_REQUIRED');
  requireSecure(operation?.v===1&&['BOOTSTRAP','MIGRATE','ACTION','ADMIN'].includes(operation.kind)&&Array.isArray(operation.objects)&&operation.objects.length<=128,'OPERATION_INVALID');
  if(wireUpgrade){
   requireSecure(p.action_id==='secure.protocol-format.upgrade'&&p.instance_id===null&&p.delegation===null&&!p.recovery&&!p.migration&&author.role==='OWNER','PROTOCOL_FORMAT_UPGRADE_INVALID');
   requireSecure(policy.payload.effective_sequence===p.sequence&&policy.payload.epoch===priorPolicy.payload.epoch&&secureEqual(policy.payload.members,priorPolicy.payload.members)&&policy.payload.structure_mode===(priorPolicy.payload.v===2?'STRUCTURED':'NONE')&&structureEqual(policy.payload.structure??null,priorPolicy.payload.structure??null)&&!structure?.snapshot,'PROTOCOL_FORMAT_UPGRADE_INVALID');
   requireSecure(secureEqual(operation,{v:1,kind:'ADMIN',input:{},objects:[]}), 'PROTOCOL_FORMAT_UPGRADE_OPERATION_INVALID');
  }else requireSecure(p.action_id!=='secure.protocol-format.upgrade','PROTOCOL_FORMAT_UPGRADE_REQUIRED');
  if(raisesProtocolFormat(priorPolicy,policy)){validateProtocolFormatRaiseContext(priorPolicy,policy,context);requireSecure(!structure?.snapshot,'PROTOCOL_FORMAT_UPGRADE_INVALID');validateProtocolFormatRaiseOperation(operation);}
  else requireSecure(p.action_id!==FORMAT_RAISE_ACTION,'PROTOCOL_FORMAT_UPGRADE_REQUIRED');
  // Migration pages are accumulated in objects for historical replay, but their
  // fragments are not active until finishMigration verifies the complete batch.
  if(p.v===3)await assertProtocolFormatCeiling(completedObjects(),p.protocol_format_ceiling!);
  if(operation.kind==='ACTION')requireSecure(permitsSecure(author,p.action_id,p.instance_id),'AUTHOR_SCOPE_DENIED');else requireSecure(author.role==='OWNER'&&context.delegation===null,'OWNER_OPERATION_REQUIRED');
  if(p.action_id==='secure.fields.begin')validateFieldPolicyOperation(operation,priorPolicy,policy,context,[...objects.values()]);
  if(p.action_id==='secure.member.keys'){const changed=validateMemberKeyTransition(priorPolicy,policy,context);validateMemberKeyOperation(operation,{expected_policy_hash:await secureHash(priorPolicy),updates:await Promise.all(changed.map(async actor_id=>({actor_id,certificate_hash:await secureHash(policy.payload.members.find(m=>m.actor_id===actor_id)!.certificate)})))});}
  if(p.action_id==='secure.member.scopes'){const target=validateMemberScopeTransition(priorPolicy,policy,context);validateMemberScopeOperation(operation,target,await secureHash(priorPolicy));validateMemberScopePermissions(policy.payload.members.find(m=>m.actor_id===target)!.scopes,[...objects.values()]);}
  if(priorMode==='PUBLIC'&&p.mode==='PRIVATE')requireSecure(operation.kind==='MIGRATE','CONVERSION_PROOF_REQUIRED');
  if(operation.kind==='MIGRATE'){
   if(migrationDone&&priorMode==='PUBLIC'&&p.mode==='PRIVATE'){migrationRoot=undefined;migrationSource=undefined;migrationFormat=undefined;migrationDone=false;migrationItems.length=0;migrationObjects.length=0;}
   requireSecure(p.migration&&digest(p.migration.source_root)&&!migrationDone,'MIGRATION_CONTEXT_REQUIRED');
   if(!migrationRoot){requireSecure(sequence===0||priorMode==='PUBLIC'&&p.mode==='PRIVATE','MIGRATION_POSITION_INVALID');migrationRoot=p.migration.source_root;migrationSource=p.migration.source_checkpoint;migrationFormat=p.v;
    if(sequence===0)requireSecure(migrationSource===null,'MIGRATION_SOURCE_INVALID');else {const sourcePolicy=input.policies.filter(q=>q.payload.effective_sequence<=sequence).at(-1)!;requireSecure(secureEqual(migrationSource,{v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head:previous,policy_hash:await secureHash(sourcePolicy)}),'MIGRATION_SOURCE_INVALID');}
   }else requireSecure(p.migration.source_root===migrationRoot&&secureEqual(p.migration.source_checkpoint,migrationSource)&&p.v===migrationFormat,'MIGRATION_ROOT_CHANGED');
   migrationItems.push(...p.migration.source_items);migrationObjects.push(...operation.objects);
  }else {requireSecure(!p.migration,'UNEXPECTED_MIGRATION_CONTEXT');await finishMigration();const hydrated=hydrateProtocolInstallOperation(operation,context,[...objects.values()],operations);operation=hydrated.operation;protocolObjectSource=hydrated.objectSource;if(protocolObjectSource)requireSecure(p.mode==='PRIVATE','PROTOCOL_OBJECT_INSTALL_INVALID');if(p.v===3)await assertProtocolFormatCeiling([...objects.values(),...operation.objects],p.protocol_format_ceiling!);}
  priorMode=p.mode;
  const validate=input.validateOperation??(await import('./workspace-secure-engine.js')).validateSecureOperation;
  await validate(operation,context,policy,[...objects.values()]);
  if((p.v===1||p.v===3&&policy.payload.structure_mode==='NONE')&&operation.kind!=='MIGRATE'){
   const protocols=operation.objects.filter(object=>object.kind==='protocols');
   if(protocols.length){requireSecure(new Set(protocols.map(object=>object.id)).size===protocols.length,'HISTORICAL_PROTOCOL_BATCH_DUPLICATE');await verifyHistoricalProtocolBindings([...objects.values(),...operation.objects],input.workspaceId,p.v===3?p.protocol_format_ceiling!:1);}
  }
  if(structuredPolicy(policy)){
   requireSecure(p.structure&&policy.payload.structure,'STRUCTURE_REQUIRED');
   const seenInstanceIds=new Set<string>();
   const canReuse=reuseBindings&&p.mode==='PRIVATE'&&operation.kind!=='MIGRATE'&&!p.recovery&&boundPolicyHash===p.policy_hash&&boundInstances!==undefined&&operation.objects.every(object=>{
    if(object.kind==='protocols'||object.kind==='protocol_package_part'||object.kind==='protocol_object_part')return false;
    if(object.kind!=='instances')return true;
    const prior=boundInstances!.get(object.id);
    if(seenInstanceIds.has(object.id))return false;
    seenInstanceIds.add(object.id);
    return prior!==undefined&&object.revision>prior.revision&&prior.protocolDigest===(object.value as any)?.protocol_digest;
   });
   if(!canReuse){await verifyStructureBindingsForReplay(policy.payload.structure,[...objects.values(),...operation.objects],input.workspaceId);
    if(reuseBindings&&p.mode==='PRIVATE'&&operation.kind!=='MIGRATE'&&!p.recovery){boundPolicyHash=p.policy_hash;boundInstances=instanceProjection([...objects.values(),...operation.objects]);}
    else {boundPolicyHash=undefined;boundInstances=undefined;}
   }else for(const object of operation.objects)if(object.kind==='instances'){
    const prior=boundInstances!.get(object.id)!;
    if(prior.revision<object.revision)boundInstances!.set(object.id,{revision:object.revision,protocolDigest:prior.protocolDigest});
   }
   const oldPolicy=input.policies.filter(q=>q.payload.effective_sequence<=sequence).at(-1)??policy;
   if(!structureEqual(oldPolicy.payload.structure??null,policy.payload.structure)&&sequence>0)requireSecure(p.structure.mode==='SNAPSHOT_BEGIN'&&['secure.structure.begin','secure.fields.begin'].includes(p.action_id),'STRUCTURE_EXPLICIT_UPGRADE_REQUIRED');
   const priorCheckpoint:SecureCheckpoint={v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head:previous,policy_hash:await secureHash(oldPolicy)};
   if(p.structure.mode==='DELTA'){requireSecure(structureEqual(p.structure,structureDelta(operation,policy.payload.structure)),'STRUCTURE_CONTENT_MISMATCH');if(structure?.snapshot)requireSecure(operation.kind==='ADMIN'&&operation.objects.length===0,'STRUCTURE_UPGRADE_INCOMPLETE');}
   else {
    requireSecure(operation.kind==='ADMIN','STRUCTURE_SNAPSHOT_OPERATION_INVALID');if(operation.objects.length)await validateStructureInstall(operation,context,[...objects.values()],protocolObjectSource);
    const snapshot=p.structure.snapshot;requireSecure(snapshot,'STRUCTURE_SNAPSHOT_REQUIRED');
    if(p.structure.mode==='SNAPSHOT_BEGIN'){
     expectedSnapshot=structureSnapshotData({records:new Map(projectStructureRecords([...objects.values()],policy.payload.structure).map(r=>[r.record_id,r])),heads:new Map(projectStructureHeads([...objects.values()]).map(h=>[h.entity_id,h]))});
     requireSecure(snapshot.records===expectedSnapshot.records.length&&snapshot.heads===expectedSnapshot.heads.length&&snapshot.root===await secureHash(expectedSnapshot),'STRUCTURE_SNAPSHOT_CONTENT_MISMATCH');
    }else if(p.structure.mode==='SNAPSHOT_PAGE'){
     requireSecure(expectedSnapshot,'STRUCTURE_SNAPSHOT_SOURCE_MISSING');
     const records=snapshot.offset<snapshot.records?expectedSnapshot.records.slice(snapshot.offset,snapshot.offset+p.structure.records.length):[];
     const heads=snapshot.offset>=snapshot.records?expectedSnapshot.heads.slice(snapshot.offset-snapshot.records,snapshot.offset-snapshot.records+p.structure.heads.length):[];
     requireSecure(structureEqual(records,p.structure.records)&&structureEqual(heads,p.structure.heads),'STRUCTURE_SNAPSHOT_CONTENT_MISMATCH');
    }
   }
   if(p.recovery)requireSecure(p.structure.mode==='SNAPSHOT_BEGIN'&&secureEqual(p.structure.snapshot?.source,p.recovery.base),'RECOVERY_STRUCTURE_REQUIRED');
   structure=applyStructureCommit(context,policy,p.recovery?undefined:structure,p.recovery?.base??priorCheckpoint);
   if(p.structure.mode==='SNAPSHOT_END'){requireSecure(await secureHash(structureSnapshotData(structure))===p.structure.snapshot!.root,'STRUCTURE_SNAPSHOT_ROOT_INVALID');expectedSnapshot=undefined;}
  }else requireSecure(!p.structure&&!structure,'STRUCTURE_DOWNGRADE_DENIED');
  const batch=new Set<string>();for(const [objectIndex,object] of operation.objects.entries()){const wireObject=wireOperation.objects[objectIndex]!;requireSecure(object&&typeof object.kind==='string'&&object.kind.length>0&&object.kind.length<=80&&typeof object.id==='string'&&object.id.length>0&&object.id.length<=512&&integer(object.revision,1)&&['AUTHOR_SIGNED','LEGACY_OWNER_ATTESTED'].includes(object.provenance)&&encodeCanonicalJson(wireObject).byteLength<=L.objectBytes,'OBJECT_INVALID');
   const key=JSON.stringify([object.kind,object.id,object.revision]);requireSecure(!batch.has(key),'OBJECT_DUPLICATE');batch.add(key);requireSecure(!objects.has(key),'OBJECT_REVISION_CONFLICT');
   if(object.provenance==='LEGACY_OWNER_ATTESTED'){requireSecure(operation.kind==='MIGRATE','LEGACY_ATTESTATION_INVALID');legacy=true;}
   objects.set(key,object);
  }
  if(operation.kind!=='MIGRATE')await (await import('./workspace-secure-engine.js')).validateSecureRolePolicies(policy,[...objects.values()],roleHistory,p.issued_at,operation.kind==='ACTION'?p.instance_id:p.action_id==='secure.member.scopes'?undefined:null);
  if(p.recovery)recoveries.push({...p.recovery,marker_sequence:p.sequence,excluded_count:p.recovery.through.sequence-p.recovery.base.sequence});
  if(structuredPolicy(policy)&&operation.kind==='ADMIN'&&operation.objects.length&&p.structure?.mode==='SNAPSHOT_BEGIN'){
   // validateStructureInstall and applyStructureCommit above authenticated both the install and its source.
   const install=(operation.input as unknown as {install:Pick<VerifiedProtocolInstallation,'instance_id'|'protocol_digest'|'entrypoint'>}).install;
   installations.push({...install,source:structuredClone(p.structure.snapshot!.source),command_id:p.command_id,...(protocolObjectSource?{object_source:protocolObjectSource}:{})});
  }
  operations.push(wireOperation);previous=await secureHash(commit);sequence=p.sequence;hashes.set(sequence,previous);
  if(operation.kind==='ACTION'){
   const effects=operation.objects.filter(object=>object.kind==='records').map(object=>{
    const value=object.value as any;
    requireSecure(value?.id===object.id&&integer(value.revision,1)&&typeof value.schema_ref==='string'&&value.actor_id===p.actor_id&&value.instance_id===p.instance_id,'VERIFIED_ACTION_EFFECT_INVALID');
    return {record_id:object.id,revision:value.revision,schema_ref:value.schema_ref,entity_id:typeof value.entity_id==='string'?value.entity_id:null};
   });
   actionReceipts.push({command_id:p.command_id,commit_hash:previous,sequence,actor_id:p.actor_id,instance_id:p.instance_id!,action_id:p.action_id,effects});
  }
  if(restored.source?.sequence===sequence)requireSecure(restored.source.head===previous&&restored.source.owner_id===genesis.owner_id&&restored.source.owner_key===genesis.signing_key&&restored.source.policy_hash===p.policy_hash,'ARCHIVE_SOURCE_CHECKPOINT_MISMATCH');
  if(restored.source?.sequence===sequence){boundPolicyHash=undefined;boundInstances=undefined;}
  }catch(error){
   if(error instanceof SecureContentError)throw error;
   const code=error instanceof Error&&/^[A-Z][A-Z0-9_]+$/.test(error.message)?error.message:'ENCRYPTED_CONTENT_INVALID';
   throw new SecureContentError(code,p.sequence,priorCheckpointForError);
  }
  if(input.pinned?.sequence===sequence)requireSecure(input.pinned.head===previous,'FORK_DETECTED');
 }
 await finishMigration();
 await (await import('./workspace-secure-engine.js')).validateSecureRolePolicies(latest,[...objects.values()],roleHistory,latest.payload.issued_at,null);
 const checkpoint:SecureCheckpoint={v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence,head:previous,policy_hash:await secureHash(latest)};
 requireSecure(latest.payload.effective_sequence<=Math.max(1,sequence)&&secureEqual(checkpoint,input.checkpoint),'JOURNAL_TRUNCATED_OR_HEAD_INVALID');
 if(input.pinned){const pinnedPolicy=input.policies.filter(p=>p.payload.effective_sequence<=Math.max(1,input.pinned!.sequence)).at(-1);requireSecure(pinnedPolicy&&await secureHash(pinnedPolicy)===input.pinned.policy_hash,'POLICY_ROLLBACK');if(input.pinned.sequence===0)requireSecure(input.pinned.head===null,'CHECKPOINT_INVALID');}
 let coordination:CoordinationItem[]|undefined,coordinationState:CoordinationState|undefined;
 if(input.policies.some(p=>p.payload.structure?.coordination)){try{coordinationState=replayCoordination(commits,byHash,hashes,resume?.coordinationState);coordination=coordinationSnapshot(coordinationState);}catch(error){if(error instanceof CoordinationError){const n=error.sequence-1,policy=input.policies.filter(p=>p.payload.effective_sequence<=Math.max(1,n)).at(-1)!;throw new SecureContentError(error.message,error.sequence,{v:1,workspace_id:input.workspaceId,owner_id:genesis.owner_id,owner_key:genesis.signing_key,sequence:n,head:hashes.get(n)??null,policy_hash:await secureHash(policy)});}throw error;}}
 const result:SecureVerifiedJournal={checkpoint,policy:latest,operations,objects:[...objects.values()],trust:input.trustedOwner?'PINNED':'UNPINNED',legacy,recoveries,...(installations.length?{installations}:{}),...(coordination?{coordination}:{}),...(structure?{structure:{state:structure.snapshot?'SEEDING' as const:'ACTIVE' as const,...structureSnapshotData(structure),...(structure.snapshot?{snapshot:structure.snapshot}:{})}}:{})};
 verifiedCheckpointHistory.set(result,{base:structuredClone(checkpoint),hashes,policies:[...byHash].map(([hash,p])=>({sequence:p.payload.effective_sequence,hash}))});
 verifiedActionHistory.set(result,actionReceipts);
 capture?.({workspaceId:input.workspaceId,rawCount:input.commits.length,sequence,previous,objects,operations,actionReceipts,commandIds,roleHistory,legacy,migrationRoot,migrationSource,migrationFormat,migrationDone,migrationItems,migrationObjects,priorMode,structure,expectedSnapshot,hashes,recoveries,installations,coordinationState});return result;
}
// Capture genuine intrinsics before post-load parse and decoder hooks can alter recovery classification.
const parseV3RecoveryContent=JSON.parse,hasV3RecoveryOwn=Object.hasOwn,decodeV3RecoveryContent=TextDecoder.prototype.decode.bind(new TextDecoder('utf-8',{fatal:true}));
/** A decryptable migration/genesis body is outside ordinary V3 recovery even if its header lies. */
async function validateV3RecoveryOperation(commit:SecureCommit,keyring:SecureKeyring|undefined):Promise<void>{
 const p=commit.payload;requireSecure(p.v===3&&p.mode==='PRIVATE','RECOVERY_V3_OPERATION_CLOSED');let operation:unknown;
 try{const key=await importEpoch(keyring,p.workspace_id,p.epoch),raw=await unsealContent(key,p.body,commitContext(commit));operation=parseV3RecoveryContent(decodeV3RecoveryContent(raw));}
 catch{return;} // Full replay still reproduces the first excluded authentication or decode failure.
 if(operation&&typeof operation==='object'&&hasV3RecoveryOwn(operation,'kind'))requireSecure((operation as SecureOperation).kind==='ACTION'||(operation as SecureOperation).kind==='ADMIN','RECOVERY_V3_OPERATION_CLOSED');
}

/** Diagnose locally after authenticating the complete chain. Never returns bad plaintext. */
export async function prepareJournalRecovery(input:Parameters<typeof verifyJournal>[0]):Promise<{recovery:SecureRecovery;base:SecureVerifiedJournal;failure_code:string}>{
 const hashes=await verifyJournalHeaders(input);requireSecure(input.policies.at(-1)?.payload.visibility==='PRIVATE','RECOVERY_PRIVATE_REQUIRED');let failure:unknown;
 try{await verifyJournal(input);}catch(error){failure=error;}
 if(failure!==undefined&&!(failure instanceof SecureContentError))throw failure;
 requireSecure(failure instanceof SecureContentError,'RECOVERY_CONTENT_FAILURE_REQUIRED');
 let baseCheckpoint=failure.prior,code=failure.code;
 for(let attempt=0;attempt<32;attempt++){
  requireSecure(baseCheckpoint.sequence>=1,'RECOVERY_NO_VALID_BASE');
  const policies=input.policies.filter(p=>p.payload.effective_sequence<=baseCheckpoint.sequence),commits=input.commits.filter(c=>c.payload.sequence<=baseCheckpoint.sequence);let base:SecureVerifiedJournal;
  try{base=await verifyJournal({...input,policies,commits,checkpoint:baseCheckpoint,pinned:input.pinned&&input.pinned.sequence<=baseCheckpoint.sequence?input.pinned:undefined});}
  catch(error){if(error instanceof SecureContentError){baseCheckpoint=error.prior;code=error.code;continue;}throw error;}
  for(const commit of input.commits.filter(c=>c.payload.sequence>base.checkpoint.sequence&&c.payload.sequence<=input.checkpoint.sequence)){
   const before=input.policies.filter(p=>p.payload.effective_sequence<commit.payload.sequence).at(-1),after=input.policies.filter(p=>p.payload.effective_sequence<=commit.payload.sequence).at(-1);
   requireSecure(!(before&&after&&before.payload.v!==3&&after.payload.v===3&&before.payload.visibility===commit.payload.mode),'RECOVERY_WIRE_UPGRADE_EXCLUDED');requireSecure(!(before&&after&&raisesProtocolFormat(before,after)),'RECOVERY_FORMAT_UPGRADE_EXCLUDED');
  }
  const recovery:SecureRecovery={v:1,reason:'INVALID_ENCRYPTED_OPERATION',base:base.checkpoint,through:input.checkpoint,excluded_root:''};if(input.policies.at(-1)!.payload.v===3){validateV3RecoveryRange(input.commits,recovery);for(const commit of input.commits.filter(c=>c.payload.sequence>recovery.base.sequence&&c.payload.sequence<=recovery.through.sequence))await validateV3RecoveryOperation(commit,input.keyring);}recovery.excluded_root=await secureHash(recoveryRange(input.commits,recovery,hashes));
  return {recovery,base,failure_code:code};
 }
 throw new SecureClientError('RECOVERY_DEPTH_LIMIT');
}

type CommitContextInput={identity:Pick<SigningIdentity,'actorId'|'keyId'>;policy:SecurePolicy;checkpoint:SecureCheckpoint;actionId:string;instanceId:string|null;commandId:string;issuedAt:number;delegation?:SecureDelegation};
/** Deterministic action-preparation header; structure is completed after the operation is known. */
export async function createActionContext(input:CommitContextInput):Promise<SecureCommitContext>{
 const p=input.policy.payload;requireSecure(p.v===1||p.v===2||p.v===3,'WRITER_VERSION_UNSUPPORTED');
 if(p.v===3){validateV3PolicyShape(input.policy);if(p.structure_mode==='STRUCTURED')validateStructurePolicy(p.structure!);requireSecure(!input.actionId.startsWith('secure.convert.'),'V3_CONVERSION_OR_RECOVERY_UNSUPPORTED');}
 requireSecure(input.checkpoint.workspace_id===p.workspace_id,'WORKSPACE_MISMATCH');
 const context:SecureCommitContext={v:p.v,workspace_id:p.workspace_id,sequence:input.checkpoint.sequence+1,previous:input.checkpoint.head,policy_hash:await secureHash(input.policy),epoch:p.epoch,actor_id:input.identity.actorId,signing_key:input.identity.keyId,command_id:input.commandId,action_id:input.actionId,instance_id:input.instanceId,issued_at:input.issuedAt,delegation:input.delegation??null};
 if(p.v===3)context.protocol_format_ceiling=p.protocol_format_ceiling;
 return context;
}
/** Build the complete signed context and PRIVATE AAD from one policy and operation. */
export async function createCommitContext(input:CommitContextInput&{operation:SecureOperation;conversionExcludedMembers?:string[];migration?:SecureCommitContext['migration'];structure?:StructureEnvelope;recovery?:SecureRecovery}):Promise<SecureCommitContext>{
 const context=await createActionContext(input),p=input.policy.payload;
 if(p.v===3){
  requireSecure(input.migration===undefined&&(input.recovery===undefined||input.actionId==='secure.recover'&&p.visibility==='PRIVATE')&&input.conversionExcludedMembers===undefined&&input.operation.kind!=='MIGRATE','V3_CONVERSION_OR_RECOVERY_UNSUPPORTED');
  requireSecure(input.actionId==='secure.bootstrap'?input.operation.kind==='BOOTSTRAP':input.operation.kind==='ACTION'||input.operation.kind==='ADMIN','V3_OPERATION_INVALID');
  if(input.actionId===FORMAT_RAISE_ACTION){requireSecure(p.visibility==='PRIVATE'&&p.protocol_format_ceiling===2&&context.actor_id===p.owner_id&&context.signing_key===p.signing_key&&context.instance_id===null&&context.delegation===null,'PROTOCOL_FORMAT_UPGRADE_INVALID');validateProtocolFormatRaiseOperation(input.operation);}
  if(input.actionId==='secure.protocol-format.upgrade'){
   requireSecure(context.actor_id===p.owner_id&&context.signing_key===p.signing_key&&context.delegation===null&&context.instance_id===null,'PROTOCOL_FORMAT_UPGRADE_INVALID');
   requireSecure(secureEqual(input.operation,{v:1,kind:'ADMIN',input:{},objects:[]}), 'PROTOCOL_FORMAT_UPGRADE_OPERATION_INVALID');
  }
 }
 if(p.v===2||p.v===3&&p.structure_mode==='STRUCTURED'){
  requireSecure(p.structure,'STRUCTURE_POLICY_REQUIRED');context.structure=input.structure??structureDelta(input.operation,p.structure);validateStructureEnvelope(context.structure,p.structure);
 }else requireSecure(!input.structure,'STRUCTURE_VERSION_REQUIRED');
 if(input.recovery)context.recovery=input.recovery;
 if(p.v===3&&input.actionId==='secure.recover'){requireSecure(secureEqual(input.operation,{v:1,kind:'ADMIN',input:{},objects:[]}),'RECOVERY_OPERATION_INVALID');validateRecoveryDirective({payload:{...context,mode:p.visibility}},input.policy);}
 if(input.migration)context.migration=input.migration;
 if(input.conversionExcludedMembers)context.conversion_excluded_members=input.conversionExcludedMembers;
 return context;
}
export async function createCommit(input:{identity:SigningIdentity;policy:SecurePolicy;checkpoint:SecureCheckpoint;protocolObjectJournal?:SecureVerifiedJournal;operation:SecureOperation;actionId:string;instanceId:string|null;commandId?:string;issuedAt?:number;keyring?:SecureKeyring;delegation?:SecureDelegation;conversionExcludedMembers?:string[];migration?:SecureCommitContext['migration'];structure?:StructureEnvelope;recovery?:SecureRecovery}):Promise<SecureCommit>{
 const context=await createCommitContext({...input,commandId:input.commandId??secureToken(),issuedAt:input.issuedAt??Date.now()});
 let logicalOperation=input.operation;
 if(input.protocolObjectJournal){const journal=input.protocolObjectJournal;requireSecure(input.policy.payload.visibility==='PRIVATE'&&secureEqual(verifiedJournalCheckpoint(journal,journal.checkpoint.sequence),input.checkpoint),'PROTOCOL_OBJECT_INSTALL_INVALID');logicalOperation=hydrateProtocolInstallOperation(input.operation,context,journal.objects,journal.operations).operation;}
 if(input.policy.payload.v===3)await assertProtocolFormatCeiling(logicalOperation.objects,input.policy.payload.protocol_format_ceiling!);
 const payload:SecureCommit['payload']=input.policy.payload.visibility==='PRIVATE'?{...context,mode:'PRIVATE',body:await sealContent(await importEpoch(input.keyring,context.workspace_id,context.epoch),encodeCanonicalJson(input.operation),context)}:{...context,mode:'PUBLIC',body:input.operation as unknown as SecureJson};
 const commit=await signSecure(input.identity,D.commit,payload);if(input.policy.payload.v===3)validateV3CommitShape(commit,input.policy);requireSecure(encodeCanonicalJson(commit).byteLength<=L.commitBytes,'COMMIT_TOO_LARGE');return commit;
}
export async function createPolicy(identity:SigningIdentity,payload:SecurePolicy['payload']):Promise<SecurePolicy>{requireSecure(payload.v===1||payload.v===2||payload.v===3,'WRITER_VERSION_UNSUPPORTED');requireSecure(payload.owner_id===identity.actorId&&payload.signing_key===identity.keyId,'OWNER_KEY_MISMATCH');const policy=await signSecure(identity,D.policy,payload);if(payload.v===3){validateV3PolicyShape(policy);if(payload.structure_mode==='STRUCTURED'){requireSecure(payload.structure,'STRUCTURE_POLICY_REQUIRED');validateStructurePolicy(payload.structure);}}return policy;}
export async function verifyInvitation(offer:SecureInvitation,owner:{actorId:string;key:string},at=Date.now()):Promise<void>{const p=offer.payload;requireSecure(p.v===1&&p.actor_id===owner.actorId&&p.signing_key===owner.key&&token(p.invite_id)&&token(p.workspace_id)&&digest(p.policy_hash)&&integer(p.issued_at)&&integer(p.expires_at)&&p.expires_at>at&&p.issued_at<=at&&p.expires_at-p.issued_at<=L.invitationLifetime,'INVITATION_INVALID_OR_EXPIRED');await verifySecure(offer,D.invitation,owner.key);await verifySecureCertificate(p.recipient,at);validateScopes(p.scopes);}
export async function createInviteDecision(identity:SigningIdentity,offer:SecureInvitation,decision:'ACCEPT'|'DECLINE',owner:{actorId:string;key:string},at=Date.now()):Promise<SecureInviteDecision>{await verifyInvitation(offer,owner,at);requireSecure(offer.payload.recipient.payload.actor_id===identity.actorId&&offer.payload.recipient.payload.signing_key===identity.keyId,'INVITATION_WRONG_RECIPIENT');return signSecure(identity,D.decision,{v:1,invite_id:offer.payload.invite_id,workspace_id:offer.payload.workspace_id,actor_id:identity.actorId,signing_key:identity.keyId,offer_hash:await secureHash(offer),decision,issued_at:at});}
export async function createInvitationCancellation(identity:SigningIdentity,offer:SecureInvitation,at=Date.now()):Promise<SecureInvitationCancellation>{requireSecure(identity.actorId===offer.payload.actor_id&&identity.keyId===offer.payload.signing_key,'OWNER_REQUIRED');requireSecure(integer(at)&&at>=offer.payload.issued_at&&at<offer.payload.expires_at,'INVITATION_INVALID_OR_EXPIRED');return signSecure(identity,D.inviteCancel,{v:1,invite_id:offer.payload.invite_id,workspace_id:offer.payload.workspace_id,actor_id:identity.actorId,signing_key:identity.keyId,offer_hash:await secureHash(offer),issued_at:at});}

export async function createInvitation(input:{identity:SigningIdentity;policy:SecurePolicy;recipient:SecureKeyCertificate;scopes:SecureScope[];message:string;issuedAt?:number;expiresAt?:number}):Promise<SecureInvitation>{
 const at=input.issuedAt??Date.now(),p=input.policy.payload;requireSecure(p.owner_id===input.identity.actorId&&p.signing_key===input.identity.keyId,'OWNER_REQUIRED');await verifySecure(input.policy,D.policy,p.signing_key);await verifySecureCertificate(input.recipient,at);validateScopes(input.scopes);
 const context={v:1 as const,invite_id:secureToken(),workspace_id:p.workspace_id,actor_id:input.identity.actorId,signing_key:input.identity.keyId,recipient:input.recipient,policy_hash:await secureHash(input.policy),scopes:input.scopes,issued_at:at,expires_at:input.expiresAt??at+L.invitationLifetime};requireSecure(context.expires_at>at&&context.expires_at-at<=L.invitationLifetime,'INVITATION_EXPIRY_INVALID');requireSecure(typeof input.message==='string'&&new TextEncoder().encode(input.message).byteLength<=8192,'INVITATION_MESSAGE_TOO_LARGE');
 return signSecure(input.identity,D.invitation,{...context,message:await hpkeSeal(input.recipient.payload.encryption_key,{message:input.message},context as unknown as SecureJson)});
}
export async function openInvitation(input:{offer:SecureInvitation;recipient:SecureKeyCertificate;privateKey:CryptoKey;owner:{actorId:string;key:string};now?:number}):Promise<string>{await verifyInvitation(input.offer,input.owner,input.now);requireSecure(secureEqual(input.offer.payload.recipient,input.recipient),'INVITATION_WRONG_RECIPIENT');const {message,...context}=input.offer.payload,opened=await hpkeOpen({privateKey:input.privateKey,publicKey:await importRecipientPublicKey(input.recipient.payload.encryption_key)},message,context as unknown as SecureJson) as {message?:unknown};requireSecure(opened&&typeof opened.message==='string','INVITATION_MESSAGE_INVALID');return opened.message;}
async function verifyAcceptance(offer:SecureInvitation,decision:SecureInviteDecision,owner:{actorId:string;key:string},now:number):Promise<void>{
 await verifyInvitation(offer,owner,now);const d=decision.payload,p=offer.payload;requireSecure(d.v===1&&d.decision==='ACCEPT'&&d.invite_id===p.invite_id&&d.workspace_id===p.workspace_id&&d.actor_id===p.recipient.payload.actor_id&&d.signing_key===p.recipient.payload.signing_key&&d.offer_hash===await secureHash(offer)&&d.issued_at>=p.issued_at&&d.issued_at< p.expires_at&&d.issued_at<=now,'ACCEPTANCE_INVALID');await verifySecure(decision,D.decision,d.signing_key);
}
export async function createKeyGrant(input:{identity:SigningIdentity;recipient:SecureKeyCertificate;policy:SecurePolicy;keyring:SecureKeyring;invite?:{offer:SecureInvitation;decision:SecureInviteDecision};delegation?:SecureDelegation;issuedAt?:number}):Promise<SecureKeyGrant>{
 const at=input.issuedAt??Date.now(),p=input.policy.payload;const grantingMember=p.members.find(m=>m.actor_id===input.identity.actorId&&m.certificate.payload.signing_key===input.identity.keyId);requireSecure(grantingMember&&(grantingMember.role==='OWNER'||input.delegation?.payload.actor_id===grantingMember.actor_id),'KEY_DELIVERY_AUTHORITY_REQUIRED');await verifySecure(input.policy,D.policy,p.signing_key);await verifySecureCertificate(input.recipient,at);
 if(input.invite){requireSecure(grantingMember.role==='OWNER','OWNER_REQUIRED');await verifyAcceptance(input.invite.offer,input.invite.decision,{actorId:p.owner_id,key:p.signing_key},at);requireSecure(secureEqual(input.invite.offer.payload.recipient,input.recipient)&&input.invite.offer.payload.workspace_id===p.workspace_id,'GRANT_RECIPIENT_MISMATCH');}
 const delegate=input.delegation??null;if(delegate){requireSecure(delegate.payload.actor_id===input.identity.actorId&&delegate.payload.workspace_id===p.workspace_id&&secureEqual(delegate.payload.device,input.recipient)&&at>=delegate.payload.issued_at&&at<delegate.payload.expires_at,'DELEGATION_INVALID');const principal=p.members.find(m=>m.actor_id===delegate.payload.actor_id);requireSecure(principal&&principal.certificate.payload.signing_key===delegate.payload.signing_key&&delegate.payload.read,'DELEGATOR_NOT_MEMBER');await verifySecure(delegate,D.delegation,delegate.payload.signing_key);}else requireSecure(p.members.some(m=>secureEqual(m.certificate,input.recipient)),'GRANT_RECIPIENT_NOT_MEMBER');
 requireSecure(input.keyring.v===1&&input.keyring.workspace_id===p.workspace_id&&Array.isArray(input.keyring.keys)&&(p.visibility==='PUBLIC'?p.epoch===0&&input.keyring.keys.length===0:input.keyring.keys.some(k=>k.epoch===p.epoch)&&input.keyring.keys.every(k=>k.epoch<=p.epoch)),'KEYRING_INVALID');
 const context={v:1 as const,grant_id:secureToken(),workspace_id:p.workspace_id,actor_id:input.identity.actorId,signing_key:input.identity.keyId,recipient:input.recipient,policy_hash:await secureHash(input.policy),epoch:p.epoch,invite_id:input.invite?.offer.payload.invite_id??null,acceptance_hash:input.invite?await secureHash(input.invite.decision):null,delegation:delegate,issued_at:at};
 return signSecure(input.identity,D.grant,{...context,box:await hpkeSeal(input.recipient.payload.encryption_key,input.keyring as unknown as SecureJson,context as unknown as SecureJson)});
}
export async function openKeyGrant(input:{grant:SecureKeyGrant;recipient:SecureKeyCertificate;privateKey:CryptoKey;policy:SecurePolicy;policies?:SecurePolicy[];owner:{actorId:string;key:string};expectedInvite?:{offer:SecureInvitation;decision:SecureInviteDecision};expectedDelegation?:SecureDelegation;now?:number}):Promise<SecureKeyring>{
 const at=input.now??Date.now(),p=input.grant.payload,policy=input.policy.payload;
 let current=policy;if(input.policies){const chain=await verifyPolicyChain(input.policies,policy.workspace_id);requireSecure(chain.has(await secureHash(input.policy)),'KEY_GRANT_POLICY_NOT_IN_CHAIN');current=input.policies.at(-1)!.payload;requireSecure(current.owner_id===input.owner.actorId&&current.signing_key===input.owner.key&&current.epoch===policy.epoch,'KEY_GRANT_CURRENT_EPOCH_REQUIRED');}
 requireSecure(p.v===1&&token(p.grant_id)&&p.workspace_id===policy.workspace_id&&policy.owner_id===input.owner.actorId&&policy.signing_key===input.owner.key&&p.policy_hash===await secureHash(input.policy)&&p.epoch===policy.epoch&&integer(p.issued_at)&&p.issued_at<=at&&secureEqual(p.recipient,input.recipient),'KEY_GRANT_CONTEXT_INVALID');
 await verifySecure(input.policy,D.policy,input.owner.key);const grantingMember=policy.members.find(m=>m.actor_id===p.actor_id&&m.certificate.payload.signing_key===p.signing_key);requireSecure(grantingMember&&(grantingMember.role==='OWNER'||input.expectedDelegation?.payload.actor_id===p.actor_id),'KEY_DELIVERY_AUTHORITY_REQUIRED');await verifySecure(input.grant,D.grant,p.signing_key);await verifySecureCertificate(input.recipient,p.issued_at);
 if(input.expectedInvite){requireSecure(grantingMember.role==='OWNER','OWNER_REQUIRED');await verifyAcceptance(input.expectedInvite.offer,input.expectedInvite.decision,input.owner,p.issued_at);requireSecure(p.invite_id===input.expectedInvite.offer.payload.invite_id&&p.acceptance_hash===await secureHash(input.expectedInvite.decision)&&secureEqual(input.expectedInvite.offer.payload.recipient,input.recipient),'KEY_GRANT_ACCEPTANCE_MISMATCH');}
 else requireSecure(p.invite_id===null&&p.acceptance_hash===null,'ACCEPTANCE_PROOF_REQUIRED');
 if(input.expectedDelegation){requireSecure(p.delegation&&secureEqual(p.delegation,input.expectedDelegation),'DEVICE_DELEGATION_MISMATCH');const d=p.delegation.payload,principal=current.members.find(m=>m.actor_id===d.actor_id);requireSecure(principal&&principal.certificate.payload.signing_key===d.signing_key&&d.actor_id===p.actor_id&&d.workspace_id===p.workspace_id&&secureEqual(d.device,input.recipient)&&d.read&&at>=d.issued_at&&at<d.expires_at,'DEVICE_DELEGATION_EXPIRED_OR_INVALID');await verifySecure(p.delegation,D.delegation,d.signing_key);}
 else requireSecure(p.delegation===null&&current.members.some(m=>secureEqual(m.certificate,input.recipient)),'KEY_GRANT_RECIPIENT_NOT_MEMBER');
 const {box,...context}=p,keyring=await hpkeOpen({privateKey:input.privateKey,publicKey:await importRecipientPublicKey(input.recipient.payload.encryption_key)},box,context as unknown as SecureJson) as unknown as SecureKeyring;
 requireSecure(keyring.v===1&&keyring.workspace_id===p.workspace_id&&Array.isArray(keyring.keys)&&(policy.visibility==='PUBLIC'?p.epoch===0&&keyring.keys.length===0:keyring.keys.length>0&&keyring.keys.length<=1024&&new Set(keyring.keys.map(k=>k.epoch)).size===keyring.keys.length&&keyring.keys.every(k=>integer(k.epoch,1)&&k.epoch<=p.epoch&&decodeBase64Url(k.key).length===32)&&keyring.keys.some(k=>k.epoch===p.epoch)),'KEYRING_INVALID');return keyring;
}
