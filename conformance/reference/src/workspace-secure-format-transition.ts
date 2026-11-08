/** Shared policy and context checks for an explicit PRIVATE format-two opt-in. */
import type {SecurePolicy,SecureCommitContext,SecureOperation} from './workspace-secure-contract.js';
import {canonicalJsonText} from './workspace-secure-crypto.js';
export const FORMAT_TWO_FEATURE='signed-protocol-format2-v1';
export const FORMAT_RAISE_ACTION='secure.protocol-format.raise';
const same=(a:unknown,b:unknown)=>canonicalJsonText(a)===canonicalJsonText(b);
const check=(ok:unknown)=>{if(!ok)throw new Error('PROTOCOL_FORMAT_UPGRADE_INVALID');};
export const raisesProtocolFormat=(before:SecurePolicy,after:SecurePolicy)=>before.payload.v===3&&after.payload.v===3&&before.payload.protocol_format_ceiling===1&&after.payload.protocol_format_ceiling===2;
export function validateProtocolFormatPolicy(before:SecurePolicy|undefined,after:SecurePolicy):void{
 const next=after.payload,old=before?.payload;
 if(next.v!==3)return;
 if(old?.v!==3){check(next.protocol_format_ceiling===1);return;}
 if(next.protocol_format_ceiling===old.protocol_format_ceiling)return;
 check(raisesProtocolFormat(before!,after)&&old.visibility==='PRIVATE'&&next.visibility==='PRIVATE');
 check(same({...old,protocol_format_ceiling:2,version:next.version,previous_policy:next.previous_policy,effective_sequence:next.effective_sequence,issued_at:next.issued_at},next));
}
export function validateProtocolFormatRaiseContext(before:SecurePolicy,after:SecurePolicy,context:SecureCommitContext):void{
 check(raisesProtocolFormat(before,after));validateProtocolFormatPolicy(before,after);
 check(context.v===3&&context.protocol_format_ceiling===2&&context.action_id===FORMAT_RAISE_ACTION&&context.instance_id===null&&context.delegation===null&&context.actor_id===before.payload.owner_id&&context.signing_key===before.payload.signing_key&&!context.migration&&!context.recovery&&!context.conversion_excluded_members&&after.payload.effective_sequence===context.sequence&&after.payload.issued_at===context.issued_at);
 if(context.structure)check(context.structure.mode==='DELTA'&&context.structure.records.length===0&&context.structure.heads.length===0);
}
export function validateProtocolFormatRaiseOperation(operation:SecureOperation):void{
 check(same(operation,{v:1,kind:'ADMIN',input:{from:1,to:2},objects:[]}));
}
export function permitsFormatTwo(policy:SecurePolicy):boolean{return policy.payload.v===3&&policy.payload.visibility==='PRIVATE'&&policy.payload.protocol_format_ceiling===2;}
