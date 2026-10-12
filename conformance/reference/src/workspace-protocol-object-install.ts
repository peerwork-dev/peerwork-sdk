/** Reconstruct signed protocol storage only at a complete, consecutive installation boundary. */
import type {SecureCommitContext,SecureObject,SecureOperation} from './workspace-secure-contract.js';
import {SECURE_LIMITS} from './workspace-secure-contract.js';
import {encodeCanonicalJson} from './workspace-secure-crypto.js';
import {normalizeProtocolObjectSourceProof,readProtocolObjectSource,validateProtocolObjectPart,type ProtocolObjectSourceProof} from './workspace-protocol-object-source.js';
export const PROTOCOL_OBJECT_SOURCE_FEATURE='signed-protocol-object-source-v1';
const check=(ok:unknown):void=>{if(!ok)throw new Error('PROTOCOL_OBJECT_INSTALL_INVALID');};
const keys=(value:unknown,expected:string[]):boolean=>Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(','));
const same=(a:unknown,b:unknown)=>encodeCanonicalJson(a).toString()===encodeCanonicalJson(b).toString();
/** The caller must already have authenticated priorOperations and the current signed context. */
export function hydrateProtocolInstallOperation(operation:SecureOperation,context:SecureCommitContext,objects:SecureObject[],priorOperations:SecureOperation[]):{operation:SecureOperation;objectSource?:ProtocolObjectSourceProof}{
 const references=operation.objects.filter(object=>object.kind==='protocols'&&object.value&&typeof object.value==='object'&&!Array.isArray(object.value)&&Object.hasOwn(object.value,'object_source'));
 if(!references.length)return {operation};
 check(references.length===1&&context.v===3&&context.action_id==='secure.structure.begin'&&context.instance_id===null&&context.delegation===null&&!context.recovery&&!context.migration&&context.structure?.mode==='SNAPSHOT_BEGIN'&&operation.kind==='ADMIN'&&operation.objects.length===2);
 const reference=references[0]!,value=reference.value as any;
 check(reference.revision===1&&reference.provenance==='AUTHOR_SIGNED'&&keys(value,['workspace_id','digest','object_source'])&&encodeCanonicalJson(reference).byteLength<=SECURE_LIMITS.objectBytes);
 const proof=normalizeProtocolObjectSourceProof(value.object_source),source=proof.source,snapshot=context.structure!.snapshot?.source,install=(operation.input as any)?.install;
 check(value.workspace_id===context.workspace_id&&value.digest===reference.id&&reference.id===proof.protocol_digest&&proof.workspace_id===context.workspace_id&&source.owner_id===context.actor_id&&source.owner_key===context.signing_key&&install?.protocol_digest===reference.id&&!objects.some(object=>object.kind==='protocols'&&object.id===reference.id));
 check(snapshot&&snapshot.workspace_id===source.workspace_id&&snapshot.owner_id===source.owner_id&&snapshot.owner_key===source.owner_key&&snapshot.policy_hash===source.policy_hash&&snapshot.sequence===source.sequence+proof.parts.length&&snapshot.sequence===context.sequence-1&&snapshot.head===context.previous);
 check(priorOperations.length>=proof.parts.length);
 const tail=priorOperations.slice(-proof.parts.length);
 for(let index=0;index<proof.parts.length;index++){
  const prior=tail[index]!,input=prior.input as any,stage=input?.protocol_object_stage,descriptor=proof.parts[index]!;
  check(keys(prior,['v','kind','input','objects'])&&prior.v===1&&prior.kind==='ADMIN'&&keys(input,['protocol_object_stage'])&&keys(stage,['proof','part_index'])&&same(stage.proof,proof)&&stage.part_index===index&&Array.isArray(prior.objects)&&prior.objects.length===1);
  const part=validateProtocolObjectPart(prior.objects[0]),data=part.value as any;
  check(part.id===descriptor.id&&data.source_id===proof.source_id&&data.workspace_id===proof.workspace_id&&data.index===index&&data.bytes===descriptor.bytes&&data.sha256===descriptor.sha256);
 }
 const logical={...reference,value:readProtocolObjectSource(proof,objects)};
 return {operation:{...operation,objects:operation.objects.map(object=>object===reference?logical:object)},objectSource:proof};
}
