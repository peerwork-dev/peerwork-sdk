import {coordinationItemKey} from './workspace-coordination-contract.js';
import {validateWorkflowFields,workflowForStructure,validateWorkflowChange,validateWorkflowGraph} from './workspace-workflow.js';
import {protectedFieldSchema,fieldDeclarationSchema,compatibleFieldType} from './workspace-field-protection.js';
import {verifyProtocolComposition} from './workspace-secure-composition.js';
import {verifyProtocolPackageSource} from './workspace-protocol-package-source.js';
import {composeProtocol} from './workspace-protocol-composition.js';
import {canonicalStructured,manifestCanonical} from './workspace-manifest.js';
import {validateCoordinationPolicy} from './workspace-coordination-contract.js';
/** Shared deterministic checks. This module does not decrypt content or authenticate signatures. */
import type {Manifest} from './workspace-contract.js';
import type {SecureCommitContext,SecureJson,SecureObject,SecureOperation,SecurePolicy} from './workspace-secure-contract.js';
import type {ProtectedField,StructureAdoptionOptions,StructureAction,StructureEnvelope,StructureHead,StructurePolicy,StructureProtocol,StructureRecord,StructureState} from './workspace-structure-contract.js';
import {canonicalJsonText,encodeCanonicalJson,sha256} from './workspace-secure-crypto.js';

const token=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value);
const digest=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const name=(value:unknown):value is string=>typeof value==='string'&&/^[a-zA-Z][a-zA-Z0-9_.-]{0,79}$/.test(value);
function check(value:unknown,code:string):asserts value{if(!value)throw new Error(code);}
function object(value:unknown):value is Record<string,any>{return Boolean(value&&typeof value==='object'&&!Array.isArray(value));}
function keys(value:unknown,required:string[],optional:string[]=[]){check(object(value)&&required.every(k=>Object.hasOwn(value,k))&&Object.keys(value).every(k=>required.includes(k)||optional.includes(k)),'STRUCTURE_UNKNOWN_OR_MISSING_FIELD');}
function unique(values:unknown,validate:(value:unknown)=>boolean,max=128):asserts values is any[]{check(Array.isArray(values)&&values.length<=max&&new Set(values).size===values.length&&values.every(validate),'STRUCTURE_LIST_INVALID');}
const taskStates=['OPEN','IN_PROGRESS','DONE','CANCELED'];
export const structureEqual=(a:unknown,b:unknown)=>canonicalJsonText(a)===canonicalJsonText(b);
export function validateStructuredPolicyShape(policy:SecurePolicy):void{
 keys(policy,['payload','signature']);keys(policy.payload,['v','workspace_id','owner_id','signing_key','version','previous_policy','effective_sequence','visibility','epoch','members','issued_at','structure']);
 check(Array.isArray(policy.payload.members),'STRUCTURE_MEMBERS_INVALID');
 for(const member of policy.payload.members){keys(member,['actor_id','certificate','role','scopes']);keys(member.certificate,['payload','signature']);keys(member.certificate.payload,['v','actor_id','signing_key','encryption_key','encryption_key_id','issued_at','expires_at']);keys(member.certificate.payload.encryption_key,['kty','crv','x','y']);}
}
export function validateStructuredCommitShape(commit:import('./workspace-secure-contract.js').SecureCommit):void{
 keys(commit,['payload','signature']);const p=commit.payload;
 keys(p,['v','workspace_id','sequence','previous','policy_hash','epoch','actor_id','signing_key','command_id','action_id','instance_id','issued_at','delegation','mode','body','structure'],['migration','conversion_excluded_members','recovery']);
 if(p.mode==='PRIVATE')keys(p.body,['v','alg','nonce','chunks']);
}
/** V3 separates wire revision from the presence of a structured projection. */
export function validateV3PolicyShape(policy:SecurePolicy):void{
 keys(policy,['payload','signature']);const p=policy.payload;
 keys(p,['v','workspace_id','owner_id','signing_key','version','previous_policy','effective_sequence','visibility','epoch','members','issued_at','protocol_format_ceiling','structure_mode'],p.structure_mode==='STRUCTURED'?['structure']:[]);
 check(p.v===3&&(p.protocol_format_ceiling===1||p.protocol_format_ceiling===2&&p.visibility==='PRIVATE')&&['NONE','STRUCTURED'].includes(p.structure_mode as string),'PROTOCOL_FORMAT_DECLARATION_INVALID');
 check(p.structure_mode==='STRUCTURED'?p.structure!==undefined:p.structure===undefined,'STRUCTURE_MODE_INVALID');
 check(Array.isArray(p.members),'STRUCTURE_MEMBERS_INVALID');
 for(const member of p.members){keys(member,['actor_id','certificate','role','scopes']);keys(member.certificate,['payload','signature']);keys(member.certificate.payload,['v','actor_id','signing_key','encryption_key','encryption_key_id','issued_at','expires_at']);keys(member.certificate.payload.encryption_key,['kty','crv','x','y']);}
}
export function validateV3CommitShape(commit:import('./workspace-secure-contract.js').SecureCommit,policy:SecurePolicy):void{
 keys(commit,['payload','signature']);const p=commit.payload;
 keys(p,['v','workspace_id','sequence','previous','policy_hash','epoch','actor_id','signing_key','command_id','action_id','instance_id','issued_at','delegation','mode','body','protocol_format_ceiling',...(policy.payload.structure_mode==='STRUCTURED'?['structure']:[])],['migration','conversion_excluded_members','recovery']);
 check(p.v===3&&(p.protocol_format_ceiling===1||p.protocol_format_ceiling===2&&p.mode==='PRIVATE')&&p.protocol_format_ceiling===policy.payload.protocol_format_ceiling,'PROTOCOL_FORMAT_DECLARATION_INVALID');
 if(p.mode==='PRIVATE')keys(p.body,['v','alg','nonce','chunks']);
}
export function validateStructurePolicy(policy:StructurePolicy):void{
 keys(policy,['v','protocols','disclosure','instances'],['coordination']);if(policy.coordination)validateCoordinationPolicy(policy.coordination);check(policy.v===1&&Array.isArray(policy.protocols)&&policy.protocols.length<=64&&Array.isArray(policy.disclosure)&&policy.disclosure.length<=256&&Array.isArray(policy.instances)&&policy.instances.length<=128,'STRUCTURE_POLICY_INVALID');
 const protocols=new Map<string,StructureProtocol>();
 for(const protocol of policy.protocols){keys(protocol,['v','protocol_digest','schemas','actions'],['field_declarations']);check((protocol.field_declarations===undefined||protocol.field_declarations===1)&&protocol.v===1&&digest(protocol.protocol_digest)&&!protocols.has(protocol.protocol_digest)&&object(protocol.schemas)&&Object.keys(protocol.schemas).length<=64&&object(protocol.actions)&&Object.keys(protocol.actions).length<=64,'STRUCTURE_PROTOCOL_INVALID');protocols.set(protocol.protocol_digest,protocol);
  for(const [schema,definition] of Object.entries(protocol.schemas)){check(name(schema),'STRUCTURE_SCHEMA_INVALID');keys(definition,['fields','required'],['workflow']);if(definition.workflow)validateWorkflowFields(definition.workflow,definition.fields,definition.required);check(object(definition.fields)&&Object.keys(definition.fields).length<=64,'STRUCTURE_SCHEMA_INVALID');unique(definition.required,k=>typeof k==='string'&&Object.hasOwn(definition.fields,k),64);
   for(const [field,rule] of Object.entries(definition.fields)){check(name(field),'STRUCTURE_FIELD_INVALID');check(protectedFieldSchema.safeParse(rule).success,'STRUCTURE_FIELD_PROTECTION_INVALID');}
  }
  for(const [action,rule] of Object.entries(protocol.actions)){check(name(action),'STRUCTURE_ACTION_INVALID');keys(rule,['schemas','roles','capabilities','heads'],['task_transition']);check(['NONE','APPEND','SELECT'].includes(rule.heads),'STRUCTURE_HEAD_RULE_INVALID');unique(rule.schemas,s=>typeof s==='string'&&Object.hasOwn(protocol.schemas,s),64);unique(rule.roles,name,64);unique(rule.capabilities,name,64);
   if(rule.task_transition){const task=protocol.schemas['task.revision'];check(task?.fields.status?.protection==='server_readable'&&task.fields.status.type==='task_status'&&task.fields.parent?.protection==='server_readable'&&task.fields.parent.type==='optional_reference','STRUCTURE_TRANSITION_FIELDS_PRIVATE');check(Array.isArray(rule.task_transition)&&rule.task_transition.length>0&&rule.task_transition.length<=16&&rule.schemas.includes('task.revision'),'STRUCTURE_TRANSITION_INVALID');for(const pair of rule.task_transition){keys(pair,['from','to']);check((pair.from===null||taskStates.includes(pair.from))&&taskStates.includes(pair.to),'STRUCTURE_TRANSITION_INVALID');}}
  }
 }
 const grants=new Set<string>();for(const grant of policy.disclosure){keys(grant,['protocol_digest','schema','fields']);const schema=protocols.get(grant.protocol_digest)?.schemas[grant.schema];check(schema&&!grants.has(`${grant.protocol_digest}:${grant.schema}`),'STRUCTURE_DISCLOSURE_INVALID');grants.add(`${grant.protocol_digest}:${grant.schema}`);unique(grant.fields,f=>typeof f==='string'&&schema.fields[f]?.protection==='server_readable',64);}
 // No silent fallback: every readable declaration needs explicit Owner approval.
 for(const protocol of policy.protocols)for(const [schema,definition] of Object.entries(protocol.schemas)){const approved=policy.disclosure.find(g=>g.protocol_digest===protocol.protocol_digest&&g.schema===schema)?.fields??[];for(const [field,rule] of Object.entries(definition.fields))check(rule.protection!=='server_readable'||approved.includes(field),'STRUCTURE_DISCLOSURE_REQUIRED');}
 if(policy.coordination){const c=policy.coordination;check(policy.instances.some(i=>i.instance_id===c.instance_id&&i.protocol_digest===c.protocol_digest),'COORDINATION_INSTANCE_INVALID');const p=protocols.get(c.protocol_digest);for(const schema of ['coordination.request','coordination.ack','coordination.disposition','coordination.cancel','coordination.remind']){check(p?.schemas[schema],'COORDINATION_PROTOCOL_REQUIRED');for(const [field,type] of Object.entries(readableFields[schema]!).filter(([field])=>field!=='result_ref'||c.v===2))check(p.schemas[schema]!.fields[field]?.protection==='server_readable'&&p.schemas[schema]!.fields[field]?.type===type,'COORDINATION_ROUTING_REQUIRED');}}
 const instances=new Set<string>();for(const instance of policy.instances){keys(instance,['instance_id','protocol_digest']);check(token(instance.instance_id)&&protocols.has(instance.protocol_digest)&&!instances.has(instance.instance_id),'STRUCTURE_INSTANCE_INVALID');instances.add(instance.instance_id);}
}

/** Initial readable fields are deliberately narrow; other JSON remains encrypted. */
const readableFields:Record<string,Record<string,ProtectedField['type']>>={
 'coordination.request':{request_id:'opaque',recipients:'tokens',source_ref:'optional_workspace_reference',author:'actor'},
 'coordination.ack':{item_id:'item_key',source_ref:'workspace_reference',source_hash:'digest',author:'actor'},
 'coordination.disposition':{item_id:'item_key',source_ref:'workspace_reference',source_hash:'digest',author:'actor',expected_version:'counter',state:'work_status',defer_until:'timestamp',result_ref:'optional_workspace_reference'},
 'coordination.cancel':{item_id:'item_key',source_ref:'workspace_reference',source_hash:'digest',author:'actor'},
 'coordination.remind':{item_id:'item_key',source_ref:'workspace_reference',source_hash:'digest',author:'actor'},
 'discussion.message':{author:'actor',reply_to:'optional_reference'},
 'wiki.revision':{author:'actor',parent:'optional_reference'},
 'task.revision':{status:'task_status',assignee:'optional_actor',author:'actor',parent:'optional_reference'},
 'task.report':{task_ref:'reference',author:'actor'},
};
/** Fixed service rules follow the availability of their exact typed fields. */
export function taskStructureTransitions(schemas:StructureProtocol['schemas'],action:string):StructureAction['task_transition']{
 const status=schemas['task.revision']?.fields.status,parent=schemas['task.revision']?.fields.parent;
 if(status?.protection!=='server_readable'||status.type!=='task_status'||parent?.protection!=='server_readable'||parent.type!=='optional_reference')return undefined;
 return action==='task.create'?[{from:null,to:'OPEN'}]:action==='task.update'?[{from:'OPEN',to:'IN_PROGRESS'},{from:'IN_PROGRESS',to:'DONE'},{from:'OPEN',to:'CANCELED'},{from:'IN_PROGRESS',to:'CANCELED'}]:undefined;
}
export function structureProtocolFromManifest(protocolDigest:string,manifest:Manifest,keepEncrypted:Map<string,Set<string>>=new Map()):StructureProtocol{
 check(digest(protocolDigest),'STRUCTURE_PROTOCOL_INVALID');const schemas:StructureProtocol['schemas']={},actions:StructureProtocol['actions']={};
 for(const [schema,definition] of Object.entries(manifest.record_schemas)){if(definition.protection){check(fieldDeclarationSchema.safeParse(definition.protection).success&&Object.keys(definition.fields).length===Object.keys(definition.protection.fields).length&&Object.entries(definition.protection.fields).every(([field,rule])=>Object.hasOwn(definition.fields,field)&&compatibleFieldType(definition.fields[field]!,rule)),'STRUCTURE_FIELD_DECLARATION_INVALID');}const fields:Record<string,ProtectedField>={};for(const [field,type] of Object.entries(definition.fields)){const declared=definition.protection?.fields[field],readable=readableFields[schema]?.[field];fields[field]=keepEncrypted.get(schema)?.has(field)?{protection:'e2ee',type}:declared?structuredClone(declared):readable?{protection:'server_readable',type:readable} as ProtectedField:{protection:'e2ee',type};}schemas[schema]={fields,required:[...definition.required],...(definition.workflow?{workflow:structuredClone(definition.workflow)}:{})};}
 for(const action of manifest.actions){
  // Structural checks supplement the complete encrypted interpreter. Only constraints
  // shared by all variants can be required here without misrepresenting private semantics.
  const variants=action.variants as any[],common=(kind:string,key:string)=>variants.length?variants[0]!.when.filter((p:any)=>p.op===kind&&variants.every(v=>v.when.some((q:any)=>q.op===kind&&q[key]===p[key]))).map((p:any)=>p[key]):[];
  const produced=[...new Set<string>(variants.flatMap(v=>v.effects.filter((e:any)=>e.op==='append').map((e:any)=>e.schema)))];
  const effects=variants.flatMap(v=>v.effects),headMode=effects.some(e=>e.op==='select_head')?'SELECT':effects.some(e=>e.op==='append'&&e.selectHead)?'APPEND':'NONE';
  const rule:StructureAction={schemas:produced,roles:common('has_protocol_role','role'),capabilities:[...new Set<string>(common('has_capability','capability'))],heads:headMode};
  const transition=taskStructureTransitions(schemas,action.id);if(transition)rule.task_transition=transition;
  actions[action.id]=rule;
 }
 return {v:1,protocol_digest:protocolDigest,schemas,actions,...(Object.values(manifest.record_schemas).some(s=>s.protection)?{field_declarations:1 as const}:{})};
}
function decode(value:unknown):any{return typeof value==='string'?JSON.parse(value):value;}
function latest(objects:SecureObject[],kind:string){const result=new Map<string,SecureObject>();for(const value of objects)if(value.kind===kind&&(!result.has(value.id)||result.get(value.id)!.revision<value.revision))result.set(value.id,value);return [...result.values()];}
function adoptionChoices(options:StructureAdoptionOptions,protocolsFor:()=>SecureObject[],manifestFor:(object:SecureObject)=>Manifest):Map<string,Map<string,Set<string>>>{
 keys(options,[],['keep_encrypted']);const choices=options.keep_encrypted??[];check(Array.isArray(choices)&&choices.length<=256,'STRUCTURE_ADOPTION_INVALID');
 const protocols=protocolsFor(),result=new Map<string,Map<string,Set<string>>>();
 for(const choice of choices){keys(choice,['schema','fields'],['protocol_digest']);check(name(choice.schema)&&(choice.protocol_digest===undefined||digest(choice.protocol_digest)),'STRUCTURE_ADOPTION_INVALID');unique(choice.fields,name,64);check(choice.fields.length>0,'STRUCTURE_ADOPTION_INVALID');
  const matching=protocols.filter(o=>{const v=o.value as any;return (!choice.protocol_digest||v.digest===choice.protocol_digest)&&Object.hasOwn(manifestFor(o).record_schemas,choice.schema);});check(matching.length>0,'STRUCTURE_ADOPTION_SCHEMA_NOT_FOUND');
  for(const object of matching){const v=object.value as any,manifest=manifestFor(object);let schemas=result.get(v.digest);if(!schemas)result.set(v.digest,schemas=new Map());let fields=schemas.get(choice.schema);if(!fields)schemas.set(choice.schema,fields=new Set());
   for(const field of choice.fields){check(Object.hasOwn(manifest.record_schemas[choice.schema]!.fields,field),'STRUCTURE_ADOPTION_FIELD_NOT_FOUND');check(!fields.has(field),'STRUCTURE_ADOPTION_DUPLICATE');fields.add(field);}
  }
 }
 return result;
}
export function structurePolicyFromObjects(objects:SecureObject[],options:StructureAdoptionOptions={}):StructurePolicy{
 // Reuse only within this synchronous call. Later calls must see changed objects.
 let latestProtocols:SecureObject[]|undefined;const protocolsFor=()=>latestProtocols??=latest(objects,'protocols'),manifests=new Map<SecureObject,Manifest>();
 const manifestFor=(object:SecureObject):Manifest=>{if(manifests.has(object))return manifests.get(object)!;const value=object.value as any,manifest=decode(value.resolved_manifest??value.manifest) as Manifest;manifests.set(object,manifest);return manifest;};
 const choices=adoptionChoices(options,protocolsFor,manifestFor);
 const protocols=protocolsFor().map(o=>{const value=o.value as any;return structureProtocolFromManifest(value.digest,manifestFor(o),choices.get(value.digest));});
 const policy:StructurePolicy={v:1,protocols,disclosure:protocols.flatMap(p=>Object.entries(p.schemas).map(([schema,s])=>({protocol_digest:p.protocol_digest,schema,fields:Object.entries(s.fields).filter(([,f])=>f.protection==='server_readable').map(([field])=>field)}))),instances:latest(objects,'instances').map(o=>({instance_id:o.id,protocol_digest:(o.value as any).protocol_digest}))};validateStructurePolicy(policy);return policy;
}
type CheckedManifest=ReturnType<typeof manifestCanonical>;
type StructureManifestCheck=(value:unknown)=>CheckedManifest&{rawCanonical?:string;normalizedCanonical?:string};
// Build an injective cache key while checking ordinary JSON eligibility. The
// descriptor walk excludes accessors, symbols, sparse arrays and class instances;
// other values use the uncached manifest parser. Object keys are sorted so order
// of insertion cannot change the key (including for numeric-looking keys).
function plainManifestCacheKey(value:unknown,depth=0,nodes={n:0}):string|undefined{
 if(depth>32||++nodes.n>2048)return undefined;
 if(value===null)return 'null';
 if(typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number')return Number.isSafeInteger(value)&&!Object.is(value,-0)?JSON.stringify(value):undefined;
 if(typeof value!=='object')return undefined;
 const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
 if(array?prototype!==Array.prototype||value.length>128:prototype!==Object.prototype&&prototype!==null)return undefined;
 const ownKeys=Reflect.ownKeys(value);
 if(ownKeys.some(key=>typeof key!=='string'))return undefined;
 if(array){
  if(ownKeys.length!==value.length+1)return undefined;
  const parts:string[]=[];
  for(let index=0;index<value.length;index++){
   const descriptor=Object.getOwnPropertyDescriptor(value,String(index));
   if(!descriptor?.enumerable||!Object.hasOwn(descriptor,'value')||!Object.is(Reflect.get(value,String(index)),descriptor.value))return undefined;
   const part=plainManifestCacheKey(descriptor.value,depth+1,nodes);
   if(part===undefined)return undefined;
   parts.push(part);
  }
  return `[${parts.join(',')}]`;
 }
 const parts:string[]=[];
 for(const key of (ownKeys as string[]).sort()){
  if(!key||key==='__proto__'||key==='prototype'||key==='constructor')return undefined;
  const descriptor=Object.getOwnPropertyDescriptor(value,key);
  if(!descriptor?.enumerable||!Object.hasOwn(descriptor,'value')||!Object.is(Reflect.get(value,key),descriptor.value))return undefined;
  const part=plainManifestCacheKey(descriptor.value,depth+1,nodes);
  if(part===undefined)return undefined;
  parts.push(`${JSON.stringify(key)}:${part}`);
 }
 return `{${parts.join(',')}}`;
}
// Conservative logical retention accounting, not a JavaScript heap/RSS promise.
function freezeManifestJson(value:unknown):number{
 let weight=96+(typeof value==='string'?value.length*2:0);
 if(value&&typeof value==='object'){
  for(const [key,child] of Object.entries(value))weight+=64+key.length*2+freezeManifestJson(child);
  Object.freeze(value);
 }
 return weight;
}
type StructureBindingDigest = (bytes:Uint8Array)=>Promise<string>;
const hexDigest=(bytes:Uint8Array)=>[...bytes].map(byte=>byte.toString(16).padStart(2,'0')).join('');
const uncachedStructureDigest:StructureBindingDigest=async bytes=>hexDigest(await sha256(bytes));

/** Public one-shot validation never shares state with any other invocation. */
export async function verifyStructureBindings(policy:StructurePolicy,objects:SecureObject[],workspaceId?:string):Promise<void>{
 await verifyStructureBindingsInternal(policy,objects,uncachedStructureDigest,workspaceId);
}

/**
 * Internal replay-scoped digest verifier. The returned capability owns its cache;
 * callers cannot provide or inspect cached results. Dispose it when replay ends.
 */
export function createStructureBindingVerifier(){
 const maxEntries=32,maxBytes=8*1024*1024;
 const cache=new Map<string,{digest?:string;manifest?:CheckedManifest;rawCanonical?:string;normalizedCanonical?:string;weight:number}>();let bytesHeld=0,active=true;
 const retain=(key:string,entry:{digest?:string;manifest?:CheckedManifest;rawCanonical?:string;normalizedCanonical?:string;weight:number})=>{
  if(!active||cache.has(key)||entry.weight>maxBytes)return;
  while(cache.size>=maxEntries||bytesHeld+entry.weight>maxBytes){const oldest=cache.entries().next();if(oldest.done)break;cache.delete(oldest.value[0]);bytesHeld-=oldest.value[1].weight;}
  cache.set(key,entry);bytesHeld+=entry.weight;
 };
 const manifestFor:StructureManifestCheck=value=>{
  const rawKey=plainManifestCacheKey(value);
  if(rawKey===undefined)return manifestCanonical(value);
  // This validates raw keys, numbers and bounds before lookup; omitted defaults
  // remain distinct from explicit defaults. No object identity is trusted.
  const key='manifest:'+rawKey,cached=cache.get(key);
  if(cached){cache.delete(key);cache.set(key,cached);return {...cached.manifest!,rawCanonical:cached.rawCanonical,normalizedCanonical:cached.normalizedCanonical};}
  const checked=manifestCanonical(value),rawCanonical=canonicalJsonText(value);
  // Format 2 requires the raw form to match the normalized form. The parsed
  // result is frozen below, so this string remains valid on later cache hits.
  const normalizedCanonical=checked.manifest.format_version===2?canonicalJsonText(checked.manifest):undefined;
  const treeWeight=freezeManifestJson(checked);
  retain(key,{manifest:checked,rawCanonical,normalizedCanonical,weight:key.length*2+rawCanonical.length*2+(normalizedCanonical?.length??0)*2+treeWeight+256});
  return {...checked,rawCanonical,normalizedCanonical};
 };
 const verify=async(policy:StructurePolicy,objects:SecureObject[],workspaceId?:string):Promise<void>=>{
  check(active,'STRUCTURE_VERIFIER_SESSION_DISPOSED');
  await verifyStructureBindingsInternal(policy,objects,async encoded=>{
   // Canonical bytes are recomputed from the current object on every call. The exact
   // decoded canonical string is the key; object identity is never consulted.
   const key='digest:'+new TextDecoder('utf-8',{fatal:true}).decode(encoded),cached=cache.get(key);
   if(cached){cache.delete(key);cache.set(key,cached);await Promise.resolve();return cached.digest!;}
   const digest=hexDigest(await sha256(encoded));
   retain(key,{digest,weight:key.length*2+128});
   return digest;
  },workspaceId,manifestFor);
 };
 const dispose=()=>{active=false;cache.clear();bytesHeld=0;};
 return Object.freeze({verify,dispose});
}

/** Strict historical protocol gate without requiring a v2 structure policy. */
export async function verifyHistoricalProtocolBindings(objects:SecureObject[],workspaceId:string,format:1|2):Promise<void>{
 await verifyProtocolAndStructureBindingsInternal(undefined,objects,uncachedStructureDigest,workspaceId,format===2);
}

async function verifyStructureBindingsInternal(policy:StructurePolicy,objects:SecureObject[],digestFor:StructureBindingDigest,workspaceId?:string,manifestFor:StructureManifestCheck=manifestCanonical):Promise<void>{
 await verifyProtocolAndStructureBindingsInternal(policy,objects,digestFor,workspaceId,true,manifestFor);
}
async function verifyProtocolAndStructureBindingsInternal(policy:StructurePolicy|undefined,objects:SecureObject[],digestFor:StructureBindingDigest,workspaceId:string|undefined,allowFormat2:boolean,manifestFor:StructureManifestCheck=manifestCanonical):Promise<void>{
 if(policy)validateStructurePolicy(policy);
 const protocols=latest(objects,'protocols');
 const legacy=new Map<string,{workspace:string;source:Manifest;resolved:Manifest;sourceDigest:string;closure:string[]}>();
 for(const object of protocols){
  if(object.provenance==='LEGACY_OWNER_ATTESTED'){
   // Control rows were migrated as database rows, not private protocol objects.
   // Their source is a canonical envelope string; their digest names the resolved program.
   const value=object.value as any;
   keys(value,['digest','workspace_id','source_digest','resolved_manifest','manifest','dependency_closure','created_by','created']);
   check(workspaceId!==undefined&&value.workspace_id===workspaceId,'STRUCTURE_LEGACY_WORKSPACE_MISMATCH');
   check(object.revision===1&&digest(object.id)&&object.id===value.digest&&token(value.workspace_id)&&digest(value.source_digest)&&token(value.created_by)&&Number.isSafeInteger(value.created)&&value.created>=0&&typeof value.manifest==='string'&&typeof value.resolved_manifest==='string'&&typeof value.dependency_closure==='string','STRUCTURE_LEGACY_ROW_INVALID');
   let envelope:any,source:Manifest,resolved:Manifest,resolvedRaw:unknown,closure:unknown;
   try{
    envelope=JSON.parse(value.manifest);keys(envelope,['semantics','manifest']);check(envelope.semantics==='peerwork.kernel.v1'&&value.manifest===canonicalStructured(envelope),'STRUCTURE_LEGACY_ENVELOPE_INVALID');
    source=manifestCanonical(envelope.manifest).manifest;
    resolvedRaw=JSON.parse(value.resolved_manifest);check(value.resolved_manifest===canonicalStructured(resolvedRaw),'STRUCTURE_LEGACY_RESOLVED_INVALID');resolved=manifestCanonical(resolvedRaw).manifest;
    closure=JSON.parse(value.dependency_closure);check(value.dependency_closure===canonicalStructured(closure),'STRUCTURE_LEGACY_CLOSURE_INVALID');
   }catch{throw new Error('STRUCTURE_LEGACY_ROW_INVALID');}
   check(!source.format_version&&!resolved.format_version&&Array.isArray(closure)&&closure.length<=16&&closure.every(digest)&&new Set(closure).size===closure.length,'STRUCTURE_LEGACY_ROW_INVALID');
   check(await digestFor(new TextEncoder().encode(value.manifest))===value.source_digest,'STRUCTURE_LEGACY_SOURCE_DIGEST_MISMATCH');
   check(await digestFor(encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest:resolvedRaw}))===value.digest,'STRUCTURE_LEGACY_RESOLVED_DIGEST_MISMATCH');
   legacy.set(object.id,{workspace:value.workspace_id,source,resolved,sourceDigest:value.source_digest,closure});
   continue;
  }
  check(object.provenance==='AUTHOR_SIGNED','STRUCTURE_PROTOCOL_PROVENANCE_INVALID');
  const value=object.value as any;
  let manifest:unknown,resolved:unknown;
  try{manifest=decode(value.manifest);resolved=decode(value.resolved_manifest===undefined?value.manifest:value.resolved_manifest);}catch{throw new Error('STRUCTURE_MANIFEST_INVALID');}
  const identityCode=policy?'STRUCTURE_PROTOCOL_ID_INVALID':'STRUCTURE_HISTORICAL_PROTOCOL_ID_INVALID';
  // Replay supplies its authenticated workspace ID. Context-free calls are used
  // only to inspect manifest/structure declarations and retain that contract.
  if(workspaceId!==undefined)check(value.workspace_id===workspaceId&&digest(object.id)&&object.id===value.digest&&object.revision===1,identityCode);
  if(!policy)check(workspaceId!==undefined&&value.manifest!==undefined&&value.resolved_manifest!==undefined,identityCode);
  // Validate both signed values before using their schema or action declarations.
  // Hash the original source value: normalizing an older manifest here would change
  // its already signed digest when a later parser supplies optional defaults.
  let checkedSource:ReturnType<StructureManifestCheck>,checkedResolved:ReturnType<StructureManifestCheck>;
  try{checkedSource=manifestFor(manifest);checkedResolved=manifestFor(resolved);}catch{throw new Error('STRUCTURE_MANIFEST_INVALID');}
  if(!allowFormat2)check(!checkedSource.manifest.format_version&&!checkedResolved.manifest.format_version,'STRUCTURE_HISTORICAL_FORMAT_UNSUPPORTED');
  // Format 2 has no historical default-omission allowance. Its signed values
  // must already be the exact schema-normalized form, and both must be present.
  if(checkedSource.manifest.format_version===2||checkedResolved.manifest.format_version===2)
   check(value.resolved_manifest!==undefined&&
    (checkedSource.rawCanonical===undefined?structureEqual(manifest,checkedSource.manifest):checkedSource.rawCanonical===(checkedSource.normalizedCanonical??canonicalJsonText(checkedSource.manifest)))&&
    (checkedResolved.rawCanonical===undefined?structureEqual(resolved,checkedResolved.manifest):checkedResolved.rawCanonical===(checkedResolved.normalizedCanonical??canonicalJsonText(checkedResolved.manifest))),'STRUCTURE_MANIFEST_INVALID');
  // The replay cache has already serialized the exact raw source bytes. This
  // envelope has the same sorted keys as encodeCanonicalJson; never use the
  // schema-normalized manifest here because omitted defaults are signed data.
  const encoded=checkedSource.rawCanonical===undefined?encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest}):
   new TextEncoder().encode(`{"manifest":${checkedSource.rawCanonical},"semantics":"peerwork.kernel.v1"}`);
  const computed=await digestFor(encoded);
  check(computed===value.digest,'STRUCTURE_MANIFEST_DIGEST_MISMATCH');
  if(value.package_source!==undefined){
   const compiled=verifyProtocolPackageSource(value.package_source,objects);
   check(value.composition===undefined&&compiled.protocolDigest===value.digest&&structureEqual(compiled.manifest,manifest)&&structureEqual(manifest,resolved),'STRUCTURE_PACKAGE_SOURCE_MISMATCH');
  }else if(value.composition!==undefined)await verifyProtocolComposition(value);
  else{
   check(structureEqual(manifest,resolved),'STRUCTURE_RESOLVED_MANIFEST_MISMATCH');
   if(!allowFormat2)check(checkedSource.manifest.dependencies.length===0&&Object.keys(checkedSource.manifest.constraints).length===0,'STRUCTURE_COMPOSITION_REQUIRED');
   if(checkedSource.manifest.format_version===2)
    check(checkedSource.manifest.dependencies.length===0&&Object.keys(checkedSource.manifest.constraints).length===0,'STRUCTURE_COMPOSITION_REQUIRED');
  }
 }
 for(const row of legacy.values()){
  let composed:ReturnType<typeof composeProtocol>;
  try{composed=composeProtocol(row.source,d=>{const dependency=legacy.get(d);return dependency?.workspace===row.workspace&&dependency.sourceDigest===d?dependency.source:undefined;},(a,b)=>a.localeCompare(b));}
  catch{throw new Error('STRUCTURE_LEGACY_COMPOSITION_INVALID');}
  check(structureEqual(composed.dependencyClosure,row.closure)&&structureEqual(composed.manifest,row.resolved),'STRUCTURE_LEGACY_COMPOSITION_MISMATCH');
 }
 if(!policy)return;
 // Derive conservative choices from the signed declarations; reconstruct all types
 // and actions from verified manifests. Private text can never become a new wire field.
 const keep_encrypted=policy.protocols.flatMap(p=>Object.entries(p.schemas).flatMap(([schema,s])=>{const fields=Object.entries(s.fields).filter(([,f])=>f.protection==='e2ee').map(([field])=>field);return fields.length?[{protocol_digest:p.protocol_digest,schema,fields}]:[];}));
 const actual=structurePolicyFromObjects(objects,{keep_encrypted});
 check(structureEqual(policy.instances,actual.instances)&&policy.protocols.length===actual.protocols.length,'STRUCTURE_BINDINGS_MISMATCH');
 for(const declared of policy.protocols){const expected=actual.protocols.find(p=>p.protocol_digest===declared.protocol_digest);check(expected&&declared.field_declarations===expected.field_declarations&&structureEqual(Object.keys(declared.schemas).sort(),Object.keys(expected.schemas).sort())&&structureEqual(declared.actions,expected.actions),'STRUCTURE_PROTOCOL_MISMATCH');
  check(structureEqual(declared.schemas,expected.schemas),'STRUCTURE_FIELD_DECLARATION_MISMATCH');
 }
}

function reference(value:unknown,optional=false):SecureJson{
 if(optional&&value===null)return null;check(object(value),'STRUCTURE_REFERENCE_INVALID');const field=Object.hasOwn(value,'recordId')?'recordId':'record_id';keys(value,[field,'revision']);check(token(value[field])&&Number.isSafeInteger(value.revision)&&value.revision>=1,'STRUCTURE_REFERENCE_INVALID');return {record_id:value[field],revision:value.revision};
}
export function fieldValue(rule:ProtectedField,value:unknown):SecureJson{
 check(rule.protection==='server_readable','STRUCTURE_PRIVATE_FIELD_DISCLOSED');
 switch(rule.type){
  case 'opaque':case 'actor':check(token(value),'STRUCTURE_ACTOR_INVALID');return value;
  case 'optional_actor':check(value===null||token(value),'STRUCTURE_ACTOR_INVALID');return value;
  case 'workspace_reference':case 'reference':return reference(value);
  case 'optional_workspace_reference':case 'optional_reference':return reference(value,true);
  case 'item_key':check(typeof value==='string'&&coordinationItemKey.test(value),'STRUCTURE_ITEM_KEY_INVALID');return value;
  case 'digest':check(digest(value),'STRUCTURE_DIGEST_INVALID');return value;
  case 'enum':check(typeof value==='string'&&rule.values.includes(value),'STRUCTURE_ENUM_INVALID');return value;
  case 'counter':check(Number.isSafeInteger(value)&&Number(value)>=0,'STRUCTURE_COUNTER_INVALID');return value as number;
  case 'work_status':check(typeof value==='string'&&['IN_PROGRESS','WAITING_FOR_INPUT','DEFERRED','HANDLED','DECLINED'].includes(value),'STRUCTURE_WORK_STATUS_INVALID');return value;
  case 'references':check(Array.isArray(value)&&value.length<=32,'STRUCTURE_REFERENCE_INVALID');return value.map(v=>reference(v));
  case 'task_status':check(typeof value==='string'&&taskStates.includes(value),'STRUCTURE_TASK_STATUS_INVALID');return value;
  case 'timestamp':check(value===null||Number.isSafeInteger(value)&&Number(value)>=0,'STRUCTURE_TIMESTAMP_INVALID');return value as SecureJson;
  case 'tokens':unique(value,token,32);return value;
 }
}
export function projectStructureRecords(objects:SecureObject[],policy:StructurePolicy):StructureRecord[]{
 return objects.filter(o=>o.kind==='records').map(o=>{
  const r=o.value as any,protocol=policy.protocols.find(p=>p.protocol_digest===r.protocol_digest),schema=protocol?.schemas[r.schema_ref];check(schema,'STRUCTURE_SCHEMA_UNDECLARED');const payload=decode(r.payload);check(object(payload)&&schema.required.every(f=>Object.hasOwn(payload,f))&&Object.keys(payload).every(f=>Object.hasOwn(schema.fields,f)),'STRUCTURE_CONTENT_SCHEMA_INVALID');
  const fields:Record<string,SecureJson>={};for(const [field,rule] of Object.entries(schema.fields))if(Object.hasOwn(payload,field)&&rule.protection==='server_readable')fields[field]=fieldValue(rule,payload[field]);
  return {record_id:r.id,entity_id:r.entity_id,revision:r.revision,instance_id:r.instance_id,protocol_digest:r.protocol_digest,schema_ref:r.schema_ref,actor_id:r.actor_id,created:r.created,fields};
 });
}
export function projectStructureHeads(objects:SecureObject[]):StructureHead[]{return latest(objects,'entity_heads').map(o=>{const h=o.value as any;return {entity_id:h.entity_id,record_id:h.record_id,revision:h.revision,instance_id:h.instance_id};});}
export function structureDelta(operation:SecureOperation,policy:StructurePolicy):StructureEnvelope{return {v:1,mode:'DELTA',records:projectStructureRecords(operation.objects,policy),heads:projectStructureHeads(operation.objects)};}

export function validateStructureEnvelope(envelope:StructureEnvelope,policy:StructurePolicy):void{
 keys(envelope,['v','mode','records','heads'],['snapshot']);check(envelope.v===1&&['DELTA','SNAPSHOT_BEGIN','SNAPSHOT_PAGE','SNAPSHOT_END'].includes(envelope.mode)&&Array.isArray(envelope.records)&&envelope.records.length<=128&&Array.isArray(envelope.heads)&&envelope.heads.length<=128,'STRUCTURE_ENVELOPE_INVALID');
 if(envelope.mode==='DELTA')check(!envelope.snapshot,'STRUCTURE_UNEXPECTED_SNAPSHOT');else {const s=envelope.snapshot;keys(s,['source','root','records','heads','offset']);check(s&&digest(s.root)&&[s.records,s.heads,s.offset].every(n=>Number.isSafeInteger(n)&&n>=0)&&s.records+s.heads<=100000&&s.offset<=s.records+s.heads,'STRUCTURE_SNAPSHOT_INVALID');}
 const records=new Set<string>();for(const r of envelope.records){keys(r,['record_id','entity_id','revision','instance_id','protocol_digest','schema_ref','actor_id','created','fields']);check([r.record_id,r.entity_id,r.instance_id,r.actor_id].every(token)&&digest(r.protocol_digest)&&Number.isSafeInteger(r.revision)&&r.revision>=1&&Number.isSafeInteger(r.created)&&r.created>=0&&!records.has(r.record_id)&&object(r.fields),'STRUCTURE_RECORD_INVALID');records.add(r.record_id);
  check(policy.instances.some(i=>i.instance_id===r.instance_id&&i.protocol_digest===r.protocol_digest),'STRUCTURE_INSTANCE_MISMATCH');const schema=policy.protocols.find(p=>p.protocol_digest===r.protocol_digest)?.schemas[r.schema_ref];check(schema,'STRUCTURE_SCHEMA_UNDECLARED');
  for(const [field,value] of Object.entries(r.fields)){const rule=schema.fields[field];check(rule?.protection==='server_readable','STRUCTURE_PRIVATE_OR_UNKNOWN_FIELD');const normalized=fieldValue(rule,value);check(structureEqual(normalized,value),'STRUCTURE_NONCANONICAL_FIELD');}
  for(const required of schema.required)check(schema.fields[required]?.protection!=='server_readable'||Object.hasOwn(r.fields,required),'STRUCTURE_REQUIRED_FIELD_MISSING');
 }
 const heads=new Set<string>();for(const h of envelope.heads){keys(h,['entity_id','record_id','revision','instance_id']);check([h.entity_id,h.record_id,h.instance_id].every(token)&&Number.isSafeInteger(h.revision)&&h.revision>=1&&!heads.has(h.entity_id),'STRUCTURE_HEAD_INVALID');heads.add(h.entity_id);}
}
/** Apply only after authenticating the full commit and the exact active Owner policy. */
export function applyStructureDelta(envelope:StructureEnvelope,contract:StructurePolicy,state:StructureState,context:SecureCommitContext,policy:SecurePolicy):StructureState{
 validateStructureEnvelope(envelope,contract);check(envelope.mode==='DELTA','STRUCTURE_DELTA_REQUIRED');
 const records=new Map(state.records),heads=new Map(state.heads),principal=context.delegation?.payload.actor_id??context.actor_id,member=policy.payload.members.find(m=>m.actor_id===principal);check(member,'STRUCTURE_MEMBER_REQUIRED');
 const scopes=member.scopes.filter(s=>(s.expires_at==null||s.expires_at>context.issued_at)&&(s.instance_id===null||s.instance_id===context.instance_id));
 const has=(field:'protocol_roles'|'capabilities',value:string)=>scopes.some(s=>s[field].includes(value))&&(!context.delegation||context.delegation.payload.scope.some(s=>(s.expires_at==null||s.expires_at>context.issued_at)&&(s.instance_id===null||s.instance_id===context.instance_id)&&s[field].includes(value)));
 for(const r of envelope.records){check(!records.has(r.record_id)&&r.instance_id===context.instance_id&&r.actor_id===principal&&r.created===context.issued_at,'STRUCTURE_RECORD_CONTEXT_INVALID');const protocol=contract.protocols.find(p=>p.protocol_digest===r.protocol_digest)!,action=protocol.actions[context.action_id];check(action&&action.schemas.includes(r.schema_ref)&&action.roles.every(role=>has('protocol_roles',role))&&action.capabilities.every(cap=>has('capabilities',cap)),'STRUCTURE_ACTION_DENIED');
  if(Object.hasOwn(r.fields,'author'))check(r.fields.author===principal,'STRUCTURE_AUTHOR_MISMATCH');if(Object.hasOwn(r.fields,'assignee'))check(r.fields.assignee===null||policy.payload.members.some(m=>m.actor_id===r.fields.assignee),'STRUCTURE_ASSIGNEE_NOT_MEMBER');
  const schema=protocol.schemas[r.schema_ref]!;const assignee=schema.workflow?.assignee_field;if(assignee&&Object.hasOwn(r.fields,assignee))check(r.fields[assignee]===null||policy.payload.members.some(m=>m.actor_id===r.fields[assignee]),'WORKFLOW_ASSIGNEE_NOT_MEMBER');for(const [field,value] of Object.entries(r.fields)){const rule=schema.fields[field]!;if(rule.type==='reference'||rule.type==='optional_reference'||rule.type==='references'||rule.type==='workspace_reference'||rule.type==='optional_workspace_reference'){for(const ref of value===null?[]:Array.isArray(value)?value:[value]){const p=ref as {record_id:string;revision:number},target=records.get(p.record_id);check(target&&target.revision===p.revision&&(rule.type==='workspace_reference'||rule.type==='optional_workspace_reference'||target.instance_id===r.instance_id),'STRUCTURE_REFERENCE_NOT_FOUND');}}}
  if(action.task_transition&&r.schema_ref==='task.revision'){const parent=r.fields.parent as {record_id:string;revision:number}|null,prior=parent?records.get(parent.record_id):undefined;
   check(parent?prior&&prior.entity_id===r.entity_id&&prior.schema_ref===r.schema_ref&&prior.revision+1===r.revision&&heads.get(r.entity_id)?.record_id===parent.record_id:r.revision===1&&!heads.has(r.entity_id),'STRUCTURE_TASK_PARENT_INVALID');
   check(action.task_transition.some(t=>t.from===(prior?.fields.status??null)&&t.to===r.fields.status),'STRUCTURE_TASK_TRANSITION_INVALID');
  }
  records.set(r.record_id,r);
 }
 for(const h of envelope.heads){const r=records.get(h.record_id);check(r&&r.entity_id===h.entity_id&&r.revision===h.revision&&r.instance_id===h.instance_id&&h.instance_id===context.instance_id,'STRUCTURE_HEAD_TARGET_INVALID');const action=contract.protocols.find(p=>p.protocol_digest===r.protocol_digest)?.actions[context.action_id];check(action&&action.roles.every(role=>has('protocol_roles',role))&&action.capabilities.every(cap=>has('capabilities',cap))&&(action.heads==='SELECT'||action.heads==='APPEND'&&envelope.records.some(record=>record.record_id===h.record_id)),'STRUCTURE_HEAD_ACTION_DENIED');heads.set(h.entity_id,h);}
 for(const protocol of contract.protocols)for(const [schema,definition] of Object.entries(protocol.schemas)){const rule=definition.workflow&&workflowForStructure(definition.workflow,definition.fields);if(rule&&context.instance_id&&contract.instances.some(i=>i.instance_id===context.instance_id&&i.protocol_digest===protocol.protocol_digest))validateWorkflowChange(rule,schema,context.instance_id,protocol.protocol_digest,context.action_id,state.records,state.heads,records,heads,envelope.records,new Set(policy.payload.members.map(member=>member.actor_id)));}
 return {records,heads};
}

export function structureSnapshotData(state:StructureState){return {records:[...state.records.values()].sort((a,b)=>a.record_id<b.record_id?-1:a.record_id>b.record_id?1:0),heads:[...state.heads.values()].sort((a,b)=>a.entity_id<b.entity_id?-1:a.entity_id>b.entity_id?1:0)};}
/** Snapshot root hashing is performed by the caller using its canonical SHA-256 implementation. */
export function applyStructureCommit(context:SecureCommitContext,policy:SecurePolicy,state:StructureState|undefined,prior:import('./workspace-secure-contract.js').SecureCheckpoint):StructureState{
 const envelope=context.structure,contract=policy.payload.structure;check((context.v===2&&policy.payload.v===2||context.v===3&&policy.payload.v===3&&policy.payload.structure_mode==='STRUCTURED')&&envelope&&contract,'STRUCTURE_VERSION_REQUIRED');validateStructurePolicy(contract);validateStructureEnvelope(envelope,contract);
 if(envelope.mode==='DELTA'){
  if(state?.snapshot){check(context.action_id==='secure.rotate'&&context.actor_id===policy.payload.owner_id&&context.signing_key===policy.payload.signing_key&&context.delegation===null&&context.instance_id===null&&policy.payload.effective_sequence===context.sequence&&envelope.records.length===0&&envelope.heads.length===0,'STRUCTURE_UPGRADE_INCOMPLETE');return {...state};}
  check(state||context.sequence===1,'STRUCTURE_UPGRADE_INCOMPLETE');return applyStructureDelta(envelope,contract,state??{records:new Map(),heads:new Map()},context,policy);
 }
 check(context.actor_id===policy.payload.owner_id&&context.signing_key===policy.payload.signing_key&&context.delegation===null&&context.instance_id===null,'STRUCTURE_SNAPSHOT_OWNER_REQUIRED');
 const snapshot=envelope.snapshot!,action=envelope.mode==='SNAPSHOT_BEGIN'?'secure.structure.begin':envelope.mode==='SNAPSHOT_PAGE'?'secure.structure.page':'secure.structure.end';check(context.action_id===action||envelope.mode==='SNAPSHOT_BEGIN'&&(context.action_id==='secure.fields.begin'||context.action_id==='secure.recover'&&context.recovery),'STRUCTURE_SNAPSHOT_ACTION_INVALID');
 if(envelope.mode==='SNAPSHOT_BEGIN'){check(!state?.snapshot&&structureEqual(snapshot.source,prior)&&snapshot.offset===0&&envelope.records.length===0&&envelope.heads.length===0,'STRUCTURE_SNAPSHOT_SOURCE_INVALID');return {records:new Map(),heads:new Map(),snapshot};}
 check(state?.snapshot&&structureEqual(snapshot,state.snapshot),'STRUCTURE_SNAPSHOT_CONFLICT');const records=new Map(state.records),heads=new Map(state.heads);
 if(envelope.mode==='SNAPSHOT_END'){check(envelope.records.length===0&&envelope.heads.length===0&&snapshot.offset===snapshot.records+snapshot.heads&&records.size===snapshot.records&&heads.size===snapshot.heads,'STRUCTURE_SNAPSHOT_INCOMPLETE');for(const h of heads.values()){const r=records.get(h.record_id);check(r&&r.revision===h.revision&&r.instance_id===h.instance_id&&r.entity_id===h.entity_id,'STRUCTURE_HEAD_TARGET_INVALID');}for(const protocol of contract.protocols)for(const [schema,definition] of Object.entries(protocol.schemas)){const rule=definition.workflow&&workflowForStructure(definition.workflow,definition.fields);if(rule)for(const instance of contract.instances.filter(i=>i.protocol_digest===protocol.protocol_digest))validateWorkflowGraph(rule,schema,instance.instance_id,protocol.protocol_digest,records,heads);}return {records,heads};}
 check(envelope.records.length+envelope.heads.length>0,'STRUCTURE_SNAPSHOT_EMPTY_PAGE');
 // Deterministic order: all immutable records, then selected heads. Never silently skip.
 check(snapshot.offset<snapshot.records?envelope.heads.length===0&&snapshot.offset+envelope.records.length<=snapshot.records:envelope.records.length===0,'STRUCTURE_SNAPSHOT_PAGE_ORDER');
 for(const record of envelope.records){check(!records.has(record.record_id),'STRUCTURE_RECORD_DUPLICATE');records.set(record.record_id,record);}
 for(const head of envelope.heads){check(!heads.has(head.entity_id),'STRUCTURE_HEAD_DUPLICATE');heads.set(head.entity_id,head);}
 const offset=snapshot.offset+envelope.records.length+envelope.heads.length;check(offset<=snapshot.records+snapshot.heads,'STRUCTURE_SNAPSHOT_OVERRUN');return {records,heads,snapshot:{...snapshot,offset}};
}

/** A private field is not an empty index. Reject filters the chosen disclosure cannot answer. */
export function validateStructureQueryPolicy(policy:StructurePolicy,filter:{instance_id?:string;schema?:string;status?:string;assignee?:string}):void{
 const protocols=filter.instance_id?policy.protocols.filter(p=>policy.instances.some(i=>i.instance_id===filter.instance_id&&i.protocol_digest===p.protocol_digest)):policy.protocols;
 for(const field of ['status','assignee'] as const){if(filter[field]===undefined)continue;
  const rules=protocols.flatMap(p=>Object.entries(p.schemas).filter(([schema,s])=>(!filter.schema||schema===filter.schema)&&Object.hasOwn(s.fields,field)).map(([,s])=>s.fields[field]!));
  check(rules.length>0,'STRUCTURE_FILTER_UNAVAILABLE');check(rules.every(r=>r.protection==='server_readable'),'STRUCTURE_FILTER_PRIVATE');
 }
}
