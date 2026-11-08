/** A certificate update preserves membership and permissions; changed encryption keys rotate the epoch. */
import type {SecureCommitContext,SecureOperation,SecurePolicy} from './workspace-secure-contract.js';
import {encodeCanonicalJson} from './workspace-secure-crypto.js';
const equal=(a:unknown,b:unknown)=>new TextDecoder().decode(encodeCanonicalJson(a))===new TextDecoder().decode(encodeCanonicalJson(b));
const check=(ok:unknown)=>{if(!ok)throw new Error('SECURE_MEMBER_KEYS_TRANSITION_INVALID');};
export type MemberKeyRequest={expected_policy_hash:string;updates:{actor_id:string;certificate_hash:string}[]};
export function validateMemberKeyRequest(input:MemberKeyRequest){
 check(input&&Object.keys(input).sort().join(',')==='expected_policy_hash,updates'&&/^[a-f0-9]{64}$/.test(input.expected_policy_hash)&&Array.isArray(input.updates)&&input.updates.length>0&&input.updates.length<=128);
 const seen=new Set<string>();for(const row of input.updates){check(row&&Object.keys(row).sort().join(',')==='actor_id,certificate_hash'&&/^[A-Za-z0-9_-]{43}$/.test(row.actor_id)&&/^[a-f0-9]{64}$/.test(row.certificate_hash)&&!seen.has(row.actor_id));seen.add(row.actor_id);}
}
export function validateMemberKeyTransition(previous:SecurePolicy,next:SecurePolicy,context:SecureCommitContext):string[]{
 const before=previous.payload,after=next.payload,changed:string[]=[];let rotate=false;
 check(context.action_id==='secure.member.keys'&&context.actor_id===before.owner_id&&context.signing_key===before.signing_key&&context.delegation===null&&context.instance_id===null&&after.version===before.version+1&&after.effective_sequence===context.sequence&&after.issued_at===context.issued_at&&after.members.length===before.members.length);
 for(let i=0;i<before.members.length;i++){
  const old=before.members[i]!,member=after.members[i]!;check(member&&equal({...old,certificate:member.certificate},member));
  if(!equal(old.certificate,member.certificate)){check(member.certificate.payload.actor_id===old.actor_id&&member.certificate.payload.signing_key===old.certificate.payload.signing_key&&member.certificate.payload.issued_at>=old.certificate.payload.issued_at);changed.push(old.actor_id);if(!equal(old.certificate.payload.encryption_key,member.certificate.payload.encryption_key))rotate=true;}
 }
 check(changed.length>0&&after.epoch===before.epoch+(before.visibility==='PRIVATE'&&rotate?1:0));
 check(equal({...before,members:after.members,epoch:after.epoch,version:after.version,previous_policy:after.previous_policy,effective_sequence:after.effective_sequence,issued_at:after.issued_at},after));
 if(context.structure)check(context.structure.mode==='DELTA'&&context.structure.records.length===0&&context.structure.heads.length===0);
 return changed.sort();
}
export function validateMemberKeyOperation(operation:SecureOperation,request:MemberKeyRequest){check(equal(operation,{v:1,kind:'ADMIN',input:request,objects:[]}));}
