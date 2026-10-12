import {workflowSchema,validateWorkflowFields} from './workspace-workflow.js';
import {fieldDeclarationSchema,compatibleFieldType} from './workspace-field-protection.js';
import {z} from 'zod';
import {ApiError} from './errors.js';
import {guardSchema,interpreterManifestSchema,validateResolvedManifest} from './workspace-interpreter.js';
export const SEMANTICS='peerwork.kernel.v1';
export const limits=Object.freeze({
 outerBytes:262144,jwsBytes:250000,payloadBytes:180000,headerBytes:256,
 manifestBytes:65536,actionBytes:16384,recordBytes:16384,stateBytes:65536,
 dependencies:16,actions:64,nodes:2048,depth:12,guards:32,refs:32,effects:16,
 producedRecords:8,stringBytes:8192,listItems:128,protocols:128,
 instancesPerWorkspace:10000,instancesGlobal:100000,grantsPerInstance:128,
 objectsPerWorkspace:50000,objectsGlobal:1000000,bytesPerWorkspace:10*1024*1024,
 bytesGlobal:1024*1024*1024,workspacesPerActor:64,workspacesGlobal:10000,
 commandsPerMinute:120,
 catalogPackageBytes:1024*1024,catalogChunkBytes:64*1024,catalogActorStagedBytes:2*1024*1024,catalogGlobalStagedBytes:16*1024*1024,catalogActorActiveUploads:2,catalogUploadTtlMs:600000,
 protocolRoles:32,capabilities:64,roleConflicts:32,
 admissionRows:20000,admissionBytes:20000*(256+71+16),
 browserRequestsGlobal:256,browserRequestPerSourcePerMinute:32,browserAdmissionRows:4096,
 readNonceRows:20000,readNonceBytes:20000*(256+43+64+43+8),
 filesystemHeadroomBytes:16*1024*1024,
});
export const token=z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const digest=z.string().regex(/^[a-f0-9]{64}$/);
export const jsonValue:z.ZodType<unknown>=z.lazy(()=>z.union([
 z.null(),z.boolean(),z.number().int(),z.string().refine(v=>new TextEncoder().encode(v).byteLength<=limits.stringBytes),
 z.array(jsonValue).max(limits.listItems),z.record(z.string(),jsonValue),
]));
const bindingName=z.string().min(1).max(80).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/);
const executionRequirementsSchema=z.object({format:z.literal('peerwork.protocol-execution-requirements.v1'),closure_complete:z.boolean(),ports:z.array(z.object({import_path:z.array(bindingName).max(limits.dependencies),action_id:z.string().min(1).max(120),variant:z.number().int().nonnegative().max(31),input_name:bindingName,type:z.enum(['exact_ref','actor_id']),required:z.boolean(),bound:z.boolean()}).strict()).max(512)}).strict();
const stateExportSegment=z.string().min(1).max(80).refine(v=>!['__proto__','prototype','constructor'].includes(v));
const stateExportSchema=z.object({path:z.array(stateExportSegment).min(1).max(limits.depth),read:z.boolean(),write:z.boolean()}).strict().refine(v=>v.read||v.write);
const stateArrayTypeSchema=z.object({path:z.array(stateExportSegment).min(1).max(limits.depth),kind:z.enum(['json','exact_ref_list'])}).strict();
const exactStateRef=(value:unknown)=>Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')==='record_id,revision'&&token.safeParse((value as any).record_id).success&&Number.isSafeInteger((value as any).revision)&&(value as any).revision>0);
function nestedRefOrProduced(value:unknown):boolean{
 if(!value||typeof value!=='object')return false;
 if(exactStateRef(value))return true;
 return Array.isArray(value)?value.some(nestedRefOrProduced):Object.entries(value).some(([key,child])=>key==='$produced'||nestedRefOrProduced(child));
}
export const manifestSchema=z.object({
 name:z.string().min(1).max(120),display_version:z.string().min(1).max(40),semantics:z.literal(SEMANTICS),
 format_version:z.literal(2).optional(),
 dependencies:z.array(digest).max(limits.dependencies).refine(v=>new Set(v).size===v.length),
 protocol_roles:z.array(bindingName).max(limits.protocolRoles).refine(v=>new Set(v).size===v.length).default([]),
 capabilities:z.array(bindingName).max(limits.capabilities).refine(v=>new Set(v).size===v.length).default([]),
 role_conflicts:z.array(z.tuple([bindingName,bindingName])).max(limits.roleConflicts).default([]),
 historical_role_conflicts:z.array(z.tuple([bindingName,bindingName])).max(limits.roleConflicts).default([]),
 constraints:z.record(z.string().min(1).max(120),z.array(guardSchema).min(1).max(limits.guards)).default({}),
 record_schemas:z.record(z.string().min(1).max(80),z.object({type:z.literal('object'),fields:z.record(z.string().min(1).max(80),z.enum(['string','integer','boolean','null','json'])),required:z.array(z.string().min(1).max(80)).max(64),max_bytes:z.number().int().positive().max(limits.recordBytes),protection:fieldDeclarationSchema.optional(),workflow:workflowSchema.optional()}).strict().superRefine((v,ctx)=>{if(v.workflow){try{validateWorkflowFields(v.workflow,v.protection?.fields,v.required);}catch{ctx.addIssue({code:'custom',message:'invalid workflow field contract'});}}for(const name of v.required)if(!Object.hasOwn(v.fields,name))ctx.addIssue({code:'custom',message:'unknown required field'});if(v.protection){if(Object.keys(v.fields).sort().join(',')!==Object.keys(v.protection.fields).sort().join(','))ctx.addIssue({code:'custom',message:'protection must declare every field'});for(const [field,rule] of Object.entries(v.protection.fields))if(!compatibleFieldType(v.fields[field]??'',rule))ctx.addIssue({code:'custom',message:'incompatible field protection'});}})),
 initial_state:jsonValue,
 state_array_types:z.array(stateArrayTypeSchema).min(1).max(64).optional(),
 state_exports:z.array(stateExportSchema).max(64).optional(),
 actions:interpreterManifestSchema.shape.actions,
 execution_requirements:executionRequirementsSchema.optional(),
}).strict().superRefine((v,ctx)=>{
 if(Boolean(v.format_version)!==Boolean(v.state_array_types))ctx.addIssue({code:'custom',message:'state array types require format version 2'});
 if(v.state_array_types){
  if(!v.initial_state||typeof v.initial_state!=='object'||Array.isArray(v.initial_state))ctx.addIssue({code:'custom',message:'state array types require object state'});
  let previous='';const kinds=new Map<string,string>();
  for(const entry of v.state_array_types){
   const encoded=JSON.stringify(entry.path);
   if(previous&&encoded<=previous)ctx.addIssue({code:'custom',message:'state array types must be unique and sorted'});
   previous=encoded;kinds.set(encoded,entry.kind);
   let at:unknown=v.initial_state;
   for(const part of entry.path){if(!at||typeof at!=='object'||Array.isArray(at)||!Object.hasOwn(at,part)){at=undefined;break;}at=(at as Record<string,unknown>)[part];}
   if(!Array.isArray(at)){ctx.addIssue({code:'custom',message:'state array type path must resolve to an array'});continue;}
   if(entry.kind==='exact_ref_list'&&!at.every(exactStateRef))ctx.addIssue({code:'custom',message:'invalid exact reference list default'});
   if(entry.kind==='json'&&nestedRefOrProduced(at))ctx.addIssue({code:'custom',message:'JSON array cannot contain exact references or produced markers'});
  }
  const guard=(node:any)=>{if(node.op==='exact_ref_list'&&node.source==='state'&&kinds.get(JSON.stringify(node.path))==='json')ctx.addIssue({code:'custom',message:'JSON state array cannot have exact reference list guard'});if(node.op==='and'||node.op==='or')node.rules.forEach(guard);if(node.op==='not')guard(node.rule);};
  for(const action of v.actions)for(const variant of action.variants)variant.when.forEach(guard);
  for(const rules of Object.values(v.constraints))rules.forEach(guard);
 }
 const ids=v.actions.map(a=>a.id);if(new Set(ids).size!==ids.length)ctx.addIssue({code:'custom',message:'duplicate action'});
 const roles=new Set(v.protocol_roles);for(const conflicts of [v.role_conflicts,v.historical_role_conflicts]){const pairs=new Set<string>();for(const [a,b] of conflicts){if(a===b||!roles.has(a)||!roles.has(b))ctx.addIssue({code:'custom',message:'invalid role conflict'});const key=[a,b].sort().join('\0');if(pairs.has(key))ctx.addIssue({code:'custom',message:'duplicate role conflict'});pairs.add(key);}}
 for(const a of v.actions)for(const variant of a.variants)for(const e of variant.effects)if(e.op==='append'&&!Object.hasOwn(v.record_schemas,e.schema))ctx.addIssue({code:'custom',message:'unknown append schema'});
 const exported=new Set<string>();for(const entry of v.state_exports??[]){const name=JSON.stringify(entry.path);if(exported.has(name))ctx.addIssue({code:'custom',message:'duplicate state export'});exported.add(name);let at:unknown=v.initial_state;for(const part of entry.path){if(!at||typeof at!=='object'||Array.isArray(at)||!Object.hasOwn(at,part)){ctx.addIssue({code:'custom',message:'state export path missing'});break;}at=(at as Record<string,unknown>)[part];}}
});
export type Manifest=z.infer<typeof manifestSchema>;

/** Apply the signed array declarations to runtime state, including resolved outputs. */
export function validateStateArrayTypes(manifest:Pick<Manifest,'state_array_types'>,state:unknown):void{
 if(!manifest.state_array_types)return;
 // Bound the value before recursively inspecting nested JSON elements.
 canonical(state);
 if(!state||typeof state!=='object'||Array.isArray(state))throw new ApiError('STATE_ARRAY_TYPE_INVALID',409);
 for(const entry of manifest.state_array_types){
  let at:unknown=state;
  for(const part of entry.path){
   if(!at||typeof at!=='object'||Array.isArray(at)||!Object.hasOwn(at,part))throw new ApiError('STATE_ARRAY_TYPE_INVALID',409);
   at=(at as Record<string,unknown>)[part];
  }
  if(!Array.isArray(at)||(entry.kind==='exact_ref_list'?!at.every(exactStateRef):nestedRefOrProduced(at)))throw new ApiError('STATE_ARRAY_TYPE_INVALID',409);
 }
}


export function normalized(value:unknown,depth=0,nodes={n:0},maxDepth:number=limits.depth):unknown{
 if(++nodes.n>limits.nodes||depth>maxDepth)throw new ApiError('INVALID_PAYLOAD',400);
 if(value===null||typeof value==='boolean'||typeof value==='string')return value;
 if(typeof value==='number'){if(!Number.isSafeInteger(value))throw new ApiError('INVALID_PAYLOAD',400);return value;}
 if(Array.isArray(value)){if(value.length>limits.listItems)throw new ApiError('INVALID_PAYLOAD',400);return value.map(v=>normalized(v,depth+1,nodes,maxDepth));}
 if(typeof value==='object'){
  const result:Record<string,unknown>={};
  for(const key of Object.keys(value as object).sort()){
   if(!key||['__proto__','prototype','constructor'].includes(key))throw new ApiError('INVALID_PAYLOAD',400);
   result[key]=normalized((value as Record<string,unknown>)[key],depth+1,nodes,maxDepth);
  }
  return result;
 }
 throw new ApiError('INVALID_PAYLOAD',400);
}
export function canonical(value:unknown){return JSON.stringify(normalized(value));}
// Persisted receipt envelopes add one level to an ordinarily bounded result.
export function canonicalResponse(value:unknown){return JSON.stringify(normalized(value,0,{n:0},limits.depth+1));}
export function canonicalCommand(value:unknown){return JSON.stringify(normalized(value,0,{n:0},40));}
export function canonicalStructured(value:unknown){return JSON.stringify(normalized(value,0,{n:0},32));}

export function manifestCanonical(value:unknown){
 // Reject unsafe raw keys before schema parsing can discard them.
 normalized(value,0,{n:0},32);
 const manifest=manifestSchema.parse(value);canonical(manifest.initial_state);validateResolvedManifest({actions:manifest.actions});const encoded=JSON.stringify(normalized({semantics:SEMANTICS,manifest},0,{n:0},32));
 if(new TextEncoder().encode(encoded).byteLength>limits.manifestBytes)throw new ApiError('RESOURCE_EXHAUSTED',429);
 return {manifest,canonical:encoded};
}
