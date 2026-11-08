/** Owner field changes cannot alter membership, keys, protocols or record history. */
import type {SecureCheckpoint,SecureCommitContext,SecureObject,SecureOperation,SecurePolicy} from './workspace-secure-contract.js';
import type {StructurePolicy} from './workspace-structure-contract.js';
import {structureEqual,structurePolicyFromObjects,validateStructurePolicy,taskStructureTransitions} from './workspace-structure.js';
export type FieldDisclosure={protocol_digest:string;schema:string;fields:string[]}[];
export type FieldPolicyRequest={expected_checkpoint:SecureCheckpoint;disclosure:FieldDisclosure;history:'REPROJECT_VERIFIED_HISTORY'};
const check=(ok:unknown,code='FIELD_POLICY_INVALID')=>{if(!ok)throw new Error(code);};
export function normalizeDisclosure(value:unknown):FieldDisclosure{
 check(Array.isArray(value)&&value.length<=256);const seen=new Set<string>();
 return (value as any[]).map(row=>{check(row&&typeof row==='object'&&Object.keys(row).sort().join(',')==='fields,protocol_digest,schema'&&/^[a-f0-9]{64}$/.test(row.protocol_digest)&&typeof row.schema==='string'&&Array.isArray(row.fields)&&row.fields.length<=64&&row.fields.every((f:any)=>typeof f==='string'&&f.length>0)&&new Set(row.fields).size===row.fields.length);const key=JSON.stringify([row.protocol_digest,row.schema]);check(!seen.has(key));seen.add(key);return {protocol_digest:row.protocol_digest,schema:row.schema,fields:[...row.fields].sort()};}).sort((a,b)=>JSON.stringify([a.protocol_digest,a.schema])<JSON.stringify([b.protocol_digest,b.schema])?-1:1);
}
export function planFieldDisclosure(objects:SecureObject[],current:StructurePolicy,desired:unknown):StructurePolicy{
 const disclosure=normalizeDisclosure(desired),maximum=structurePolicyFromObjects(objects);
 for(const row of disclosure){const schema=maximum.protocols.find(p=>p.protocol_digest===row.protocol_digest)?.schemas[row.schema];check(schema,'FIELD_POLICY_SCHEMA_UNKNOWN');for(const field of row.fields)check(schema!.fields[field]?.protection==='server_readable','FIELD_POLICY_FIELD_PRIVATE');}
 const keep_encrypted=maximum.protocols.flatMap(p=>Object.entries(p.schemas).flatMap(([schema,definition])=>{const allowed=disclosure.find(r=>r.protocol_digest===p.protocol_digest&&r.schema===schema)?.fields??[],fields=Object.keys(definition.fields).filter(field=>!allowed.includes(field));return fields.length?[{protocol_digest:p.protocol_digest,schema,fields}]:[];}));
 const next=structurePolicyFromObjects(objects,{keep_encrypted});if(current.coordination)next.coordination=structuredClone(current.coordination);validateStructurePolicy(next);return next;
}
export function validateFieldPolicyTransition(before:SecurePolicy,after:SecurePolicy,context:SecureCommitContext):void{
 const old=before.payload,next=after.payload;
 const structuredWire=old.v===2&&next.v===2||old.v===3&&next.v===3&&old.structure_mode==='STRUCTURED'&&next.structure_mode==='STRUCTURED'&&old.protocol_format_ceiling===next.protocol_format_ceiling;
 check(context.action_id==='secure.fields.begin'&&context.actor_id===old.owner_id&&context.signing_key===old.signing_key&&context.instance_id===null&&context.delegation===null&&context.structure?.mode==='SNAPSHOT_BEGIN'&&structuredWire&&old.structure&&next.structure,'FIELD_POLICY_TRANSITION_INVALID');
 check(next.version===old.version+1&&next.effective_sequence===context.sequence&&next.issued_at===context.issued_at&&structureEqual({...old,structure:next.structure,version:next.version,previous_policy:next.previous_policy,effective_sequence:next.effective_sequence,issued_at:next.issued_at},next),'FIELD_POLICY_TRANSITION_INVALID');
 const a=old.structure!,b=next.structure!;check(structureEqual(a.instances,b.instances)&&structureEqual(a.coordination??null,b.coordination??null)&&a.protocols.length===b.protocols.length,'FIELD_POLICY_TRANSITION_INVALID');
 for(let i=0;i<a.protocols.length;i++){const p=a.protocols[i]!,q=b.protocols[i]!;check(q&&p.protocol_digest===q.protocol_digest&&p.v===q.v&&p.field_declarations===q.field_declarations&&structureEqual(Object.keys(p.schemas).sort(),Object.keys(q.schemas).sort()),'FIELD_POLICY_TRANSITION_INVALID');
  for(const [schema,definition] of Object.entries(p.schemas)){const target=q.schemas[schema]!;check(structureEqual(definition.required,target.required)&&structureEqual(definition.workflow??null,target.workflow??null)&&structureEqual(Object.keys(definition.fields).sort(),Object.keys(target.fields).sort()),'FIELD_POLICY_TRANSITION_INVALID');for(const [field,rule] of Object.entries(definition.fields)){const updated=target.fields[field]!;if(rule.protection===updated.protection)check(structureEqual(rule,updated),'FIELD_POLICY_TRANSITION_INVALID');}}
  const actions=(v:typeof p)=>Object.fromEntries(Object.entries(v.actions).map(([id,{task_transition:_transition,...rule}])=>[id,rule]));check(structureEqual(actions(p),actions(q)),'FIELD_POLICY_TRANSITION_INVALID');for(const [id,rule] of Object.entries(q.actions))check(structureEqual(rule.task_transition??null,taskStructureTransitions(q.schemas,id)??null),'FIELD_POLICY_TRANSITION_INVALID');
 }
}
export function validateFieldPolicyOperation(operation:SecureOperation,before:SecurePolicy,after:SecurePolicy,context:SecureCommitContext,objects:SecureObject[]):void{
 validateFieldPolicyTransition(before,after,context);const input=operation.input as any,request=input?.field_policy;
 check(operation.kind==='ADMIN'&&operation.objects.length===0&&input&&Object.keys(input).join(',')==='field_policy'&&request&&Object.keys(request).sort().join(',')==='disclosure,expected_checkpoint,history'&&request.history==='REPROJECT_VERIFIED_HISTORY'&&structureEqual(request.expected_checkpoint,context.structure!.snapshot!.source),'FIELD_POLICY_OPERATION_INVALID');
 check(structureEqual(request.disclosure,normalizeDisclosure(request.disclosure))&&structureEqual(planFieldDisclosure(objects,before.payload.structure!,request.disclosure),after.payload.structure),'FIELD_POLICY_OPERATION_INVALID');
}
