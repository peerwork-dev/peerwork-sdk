/** Recovery is an explicit signed disposition, never deletion or a rewrite of history. */
import type {SecureCheckpoint,SecureCommit,SecureCommitContext,SecurePolicy} from './workspace-secure-contract.js';
export type SecureRecovery={v:1;reason:'INVALID_ENCRYPTED_OPERATION';base:SecureCheckpoint;through:SecureCheckpoint;excluded_root:string};
export type SecureRecoveryNotice=SecureRecovery&{marker_sequence:number;excluded_count:number};
const token=(v:unknown)=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v);
const hash=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function check(ok:unknown,code:string):asserts ok{if(!ok)throw new Error(code);}
function keys(v:unknown,fields:string[]){check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===fields.length&&fields.every(k=>Object.hasOwn(v,k)),'RECOVERY_SHAPE_INVALID');}
export function validateRecoveryCheckpoint(p:SecureCheckpoint):void{
 keys(p,['v','workspace_id','owner_id','owner_key','sequence','head','policy_hash']);check(p.v===1&&token(p.workspace_id)&&token(p.owner_id)&&token(p.owner_key)&&Number.isSafeInteger(p.sequence)&&p.sequence>=1&&hash(p.head)&&hash(p.policy_hash),'RECOVERY_CHECKPOINT_INVALID');
}
export function validateRecoveryDirective(commit:{payload:SecureCommitContext&{mode:'PUBLIC'|'PRIVATE'}},policy:SecurePolicy):SecureRecovery{
 const p=commit.payload,r=p.recovery;check(r,'RECOVERY_REQUIRED');keys(r,['v','reason','base','through','excluded_root']);validateRecoveryCheckpoint(r.base);validateRecoveryCheckpoint(r.through);
 check(r.v===1&&r.reason==='INVALID_ENCRYPTED_OPERATION'&&hash(r.excluded_root)&&r.base.sequence<r.through.sequence&&r.through.sequence===p.sequence-1&&r.through.head===p.previous,'RECOVERY_RANGE_INVALID');
 check(p.action_id==='secure.recover'&&p.mode==='PRIVATE'&&policy.payload.visibility==='PRIVATE'&&p.instance_id===null&&p.delegation===null&&p.actor_id===policy.payload.owner_id&&p.signing_key===policy.payload.signing_key&&!p.migration&&!p.conversion_excluded_members,'RECOVERY_OWNER_REQUIRED');
 for(const anchor of [r.base,r.through])check(anchor.workspace_id===p.workspace_id&&anchor.owner_id===policy.payload.owner_id&&anchor.owner_key===policy.payload.signing_key,'RECOVERY_WORKSPACE_MISMATCH');
 if(p.v===3){check(policy.payload.v===3&&p.epoch===policy.payload.epoch,'RECOVERY_V3_EPOCH_MISMATCH');if(policy.payload.structure_mode==='STRUCTURED'){check(p.structure?.mode==='SNAPSHOT_BEGIN'&&p.structure.snapshot,'RECOVERY_STRUCTURE_REQUIRED');validateRecoveryCheckpoint(p.structure.snapshot.source);check(sameCheckpoint(p.structure.snapshot.source,r.base),'RECOVERY_STRUCTURE_REQUIRED');}}
 return r;
}

function sameCheckpoint(a:SecureCheckpoint|undefined,b:SecureCheckpoint):boolean{return Boolean(a&&a.v===b.v&&a.workspace_id===b.workspace_id&&a.owner_id===b.owner_id&&a.owner_key===b.owner_key&&a.sequence===b.sequence&&a.head===b.head&&a.policy_hash===b.policy_hash);}
/** V3 recovery covers ordinary encrypted content only; terminal migrations remain closed. */
export function validateV3RecoveryRange(commits:SecureCommit[],r:SecureRecovery):void{
 const excluded=commits.filter(c=>c.payload.sequence>r.base.sequence&&c.payload.sequence<=r.through.sequence);
 // Preserve the authenticated wire-upgrade exclusion before the narrower origin check.
 for(const commit of excluded){const previous=commits.find(c=>c.payload.sequence===commit.payload.sequence-1);check(!(previous&&previous.payload.v!==3&&commit.payload.v===3&&previous.payload.mode===commit.payload.mode),'RECOVERY_WIRE_UPGRADE_EXCLUDED');check(commit.payload.action_id!=='secure.protocol-format.raise','RECOVERY_FORMAT_UPGRADE_EXCLUDED');}
 const first=commits[0]?.payload,base=commits.find(c=>c.payload.sequence===r.base.sequence)?.payload;
 const prefix=commits.filter(c=>c.payload.sequence<=r.base.sequence);
 if(first?.v===3){
  check(first.mode==='PRIVATE'&&first.sequence===1&&first.action_id==='secure.bootstrap'&&!Object.hasOwn(first,'migration')&&!Object.hasOwn(first,'recovery')&&!Object.hasOwn(first,'conversion_excluded_members'),'RECOVERY_V3_ORIGIN_CLOSED');
  check(prefix.every(c=>!Object.hasOwn(c.payload,'migration')&&!Object.hasOwn(c.payload,'conversion_excluded_members')&&!c.payload.action_id.startsWith('secure.convert.')&&c.payload.action_id!=='secure.protocol-format.upgrade'),'RECOVERY_V3_ORIGIN_CLOSED');
 }else{
  // Historical policy, signatures and any sealed PUBLIC archive are replayed by the reader.
  check(first&&(first.v===1||first.v===2),'RECOVERY_V3_ORIGIN_CLOSED');
  const upgrades=prefix.filter(c=>{const previous=prefix.find(q=>q.payload.sequence===c.payload.sequence-1);return previous&&(previous.payload.v===1||previous.payload.v===2)&&previous.payload.mode==='PRIVATE'&&c.payload.v===3&&c.payload.mode==='PRIVATE';});
  check(upgrades.length===1,'RECOVERY_V3_ORIGIN_CLOSED');const upgrade=upgrades[0]!.payload,previous=prefix.find(c=>c.payload.sequence===upgrade.sequence-1)!.payload;
  check(upgrade.action_id==='secure.protocol-format.upgrade'&&upgrade.instance_id===null&&upgrade.delegation===null&&upgrade.actor_id===r.base.owner_id&&upgrade.signing_key===r.base.owner_key&&upgrade.epoch===previous.epoch&&!Object.hasOwn(upgrade,'migration')&&!Object.hasOwn(upgrade,'recovery')&&!Object.hasOwn(upgrade,'conversion_excluded_members'),'RECOVERY_V3_ORIGIN_CLOSED');
  check(prefix.every(c=>c.payload.sequence<upgrade.sequence?(c.payload.v===1||c.payload.v===2):c.payload.v===3&&c.payload.mode==='PRIVATE'&&!Object.hasOwn(c.payload,'migration')&&!Object.hasOwn(c.payload,'conversion_excluded_members')&&!c.payload.action_id.startsWith('secure.convert.')&&(c.payload.action_id!=='secure.protocol-format.upgrade'||c.payload.sequence===upgrade.sequence)),'RECOVERY_V3_ORIGIN_CLOSED');
 }
 check(base?.v===3&&base.mode==='PRIVATE','RECOVERY_V3_ORIGIN_CLOSED');
 check(excluded.length===r.through.sequence-r.base.sequence&&excluded.every(c=>{const p=c.payload;return p.v===3&&p.mode==='PRIVATE'&&!Object.hasOwn(p,'migration')&&!Object.hasOwn(p,'conversion_excluded_members')&&(!Object.hasOwn(p,'recovery')||p.action_id==='secure.recover')&&p.action_id!=='secure.bootstrap'&&p.action_id!=='secure.protocol-format.upgrade'&&!p.action_id.startsWith('secure.convert.');}),'RECOVERY_V3_RANGE_CLOSED');
}
/** Uses authenticated full-chain artifacts. The caller verifies every signature separately. */
export function recoveryRange(commits:SecureCommit[],r:SecureRecovery,hashes:Map<number,string>):{sequence:number;hash:string}[]{
 const base=commits.find(c=>c.payload.sequence===r.base.sequence),through=commits.find(c=>c.payload.sequence===r.through.sequence);
 check(base&&through&&hashes.get(r.base.sequence)===r.base.head&&base.payload.policy_hash===r.base.policy_hash&&hashes.get(r.through.sequence)===r.through.head&&through.payload.policy_hash===r.through.policy_hash,'RECOVERY_ANCHOR_MISMATCH');
 const excluded=commits.filter(c=>c.payload.sequence>r.base.sequence&&c.payload.sequence<=r.through.sequence);check(excluded.length===r.through.sequence-r.base.sequence&&excluded.every(c=>c.payload.mode==='PRIVATE'),'RECOVERY_RANGE_INVALID');
 return excluded.map(c=>({sequence:c.payload.sequence,hash:hashes.get(c.payload.sequence)!}));
}
/** A later disposition may supersede an earlier broken recovery, but cannot overlap a live one. */
export function activeRecoveryMarkers(commits:SecureCommit[]):SecureCommit[]{
 const selected:SecureCommit[]=[];for(const commit of [...commits].reverse()){
  if(selected.some(c=>commit.payload.sequence>c.payload.recovery!.base.sequence&&commit.payload.sequence<=c.payload.recovery!.through.sequence))continue;
  if(commit.payload.recovery)selected.push(commit);
 }
 return selected.reverse();
}
