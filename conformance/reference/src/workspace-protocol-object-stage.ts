/** Consecutive Owner-signed storage operations, prior to a separately verified installation. */
import type {SecureCheckpoint,SecureCommitContext,SecureObject,SecureOperation,SecurePolicy} from './workspace-secure-contract.js';
import {secureEqual,secureHash,verifiedJournalCheckpoint,type SecureVerifiedJournal} from './workspace-secure-client.js';
import {normalizeProtocolObjectSourceProof,protocolObjectPartId,validateProtocolObjectPart,type ProtocolObjectSourceProof} from './workspace-protocol-object-source.js';
export const PROTOCOL_OBJECT_STAGE_ACTION='secure.protocol-object.stage';
const check=(ok:unknown):void=>{if(!ok)throw new Error('PROTOCOL_OBJECT_STAGE_INVALID');};
const keys=(value:unknown,expected:string[]):boolean=>Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(','));
/** This validates content/context after the caller has authenticated the signed policy and commit. */
export async function validateProtocolObjectStageOperation(operation:SecureOperation,context:SecureCommitContext,policy:SecurePolicy,objects:SecureObject[]):Promise<void>{
 check(keys(operation,['v','kind','input','objects'])&&operation.v===1&&operation.kind==='ADMIN'&&Array.isArray(operation.objects)&&operation.objects.length===1);
 check(context.action_id===PROTOCOL_OBJECT_STAGE_ACTION&&context.v===3&&policy.payload.v===3&&policy.payload.visibility==='PRIVATE'&&context.workspace_id===policy.payload.workspace_id&&context.actor_id===policy.payload.owner_id&&context.signing_key===policy.payload.signing_key&&context.delegation===null&&context.instance_id===null&&!context.recovery&&!context.migration&&!context.conversion_excluded_members&&context.epoch===policy.payload.epoch&&context.protocol_format_ceiling===policy.payload.protocol_format_ceiling&&context.policy_hash===await secureHash(policy));
 if(policy.payload.structure_mode==='STRUCTURED')check(Boolean(policy.payload.structure)&&keys(context.structure,['v','mode','records','heads'])&&context.structure!.v===1&&context.structure!.mode==='DELTA'&&Array.isArray(context.structure!.records)&&context.structure!.records.length===0&&Array.isArray(context.structure!.heads)&&context.structure!.heads.length===0);
 else check(policy.payload.structure_mode==='NONE'&&context.structure===undefined&&policy.payload.structure===undefined);
 const input=operation.input as any,stage=input?.protocol_object_stage;
 check(keys(input,['protocol_object_stage'])&&keys(stage,['proof','part_index']));
 const proof=normalizeProtocolObjectSourceProof(stage.proof),source=proof.source,index=stage.part_index;
 check(Number.isSafeInteger(index)&&index>=0&&index<proof.parts.length);
 const part=validateProtocolObjectPart(operation.objects[0]),value=part.value as any,descriptor=proof.parts[index]!;
 check(source.workspace_id===context.workspace_id&&source.owner_id===context.actor_id&&source.owner_key===context.signing_key&&source.policy_hash===context.policy_hash&&policy.payload.effective_sequence<=source.sequence&&context.sequence===source.sequence+index+1&&part.id===descriptor.id&&value.source_id===proof.source_id&&value.workspace_id===source.workspace_id&&value.index===index&&value.bytes===descriptor.bytes&&value.sha256===descriptor.sha256&&!objects.some(object=>object.kind===part.kind&&object.id===part.id));
 if(index===0)check(context.previous===source.head);
 else {const prior=objects.filter(object=>object.kind==='protocol_object_part'&&object.id===protocolObjectPartId(source,proof.source_id,index-1));check(prior.length===1);const previous=validateProtocolObjectPart(prior[0]),data=previous.value as any,expected=proof.parts[index-1]!;check(data.source_id===proof.source_id&&data.workspace_id===source.workspace_id&&data.index===index-1&&data.bytes===expected.bytes&&data.sha256===expected.sha256);}
}
/** A review checkpoint advances only over this exact verified staging prefix. */
export function verifyStagedProtocolObjectCheckpoint(journal:SecureVerifiedJournal,value:unknown,targetCP:SecureCheckpoint=journal.checkpoint):SecureCheckpoint{
 const proof:ProtocolObjectSourceProof=normalizeProtocolObjectSourceProof(value),base=proof.source,target=targetCP;
 check(secureEqual(verifiedJournalCheckpoint(journal,base.sequence),base)&&secureEqual(verifiedJournalCheckpoint(journal,target.sequence),target));
 const count=target.sequence-base.sequence,after=journal.checkpoint.sequence-target.sequence;
 check(count>=0&&count<=proof.parts.length&&after>=0&&target.workspace_id===base.workspace_id&&target.owner_id===base.owner_id&&target.owner_key===base.owner_key&&target.policy_hash===base.policy_hash);
 const end=journal.operations.length-after,start=end-count;check(start>=0&&end<=journal.operations.length);
 for(let index=0;index<count;index++){
  const operation=journal.operations[start+index],input=operation?.input as any,stage=input?.protocol_object_stage,descriptor=proof.parts[index]!;
  check(keys(operation,['v','kind','input','objects'])&&operation!.v===1&&operation!.kind==='ADMIN'&&keys(input,['protocol_object_stage'])&&keys(stage,['proof','part_index'])&&secureEqual(stage.proof,proof)&&stage.part_index===index&&Array.isArray(operation!.objects)&&operation!.objects.length===1);
  const part=validateProtocolObjectPart(operation!.objects[0]),data=part.value as any;
  check(part.id===descriptor.id&&data.workspace_id===base.workspace_id&&data.source_id===proof.source_id&&data.index===index&&data.bytes===descriptor.bytes&&data.sha256===descriptor.sha256&&verifiedJournalCheckpoint(journal,base.sequence+index+1).policy_hash===base.policy_hash);
 }
 return structuredClone(target);
}
