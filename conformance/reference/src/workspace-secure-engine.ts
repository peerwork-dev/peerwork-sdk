import {PROTOCOL_OBJECT_STAGE_ACTION,validateProtocolObjectStageOperation} from './workspace-protocol-object-stage.js';
import {validateWorkflowRows} from './workspace-workflow.js';
import {fieldValue} from './workspace-structure.js';
/** Deterministic protocol execution on verified client data. Private values never reach Control. */
import {evaluateAction, validateResolvedManifest, type ResolvedInput} from './workspace-interpreter.js';
import type {Manifest} from './workspace-contract.js';
import {validateStateArrayTypes} from './workspace-manifest.js';
import type {SecureCommitContext, SecureJson, SecureObject, SecureOperation, SecurePolicy} from './workspace-secure-contract.js';
import {encodeBase64Url, encodeCanonicalJson, sha256} from './workspace-secure-crypto.js';
import {normalizeProtocolPackageSourceCheckpoint,protocolPackagePartId,validateProtocolPackagePart} from './workspace-protocol-package-source.js';
import {resolveSecureAuthor, permitsSecure, secureEqual, secureHash, secureToken, SecureClientError} from './workspace-secure-client.js';

type Row=Record<string,SecureJson>;
const fail=(code:string):never=>{throw new SecureClientError(code);};
function check(ok:unknown,code='INVALID_PROTOCOL_TRANSITION'):asserts ok{if(!ok)fail(code);}
function row(object:SecureObject):Row{check(object.value&&typeof object.value==='object'&&!Array.isArray(object.value));return object.value as Row;}
function decoded(value:SecureJson|undefined):unknown{return typeof value==='string'?JSON.parse(value):value;}
function latest(objects:SecureObject[],kind:string,id:string):SecureObject|undefined{return objects.filter(o=>o.kind===kind&&o.id===id).sort((a,b)=>b.revision-a.revision)[0];}
export function secureLatestObjects(objects:SecureObject[]):SecureObject[]{
 const result:SecureObject[]=[],positions=new Map<string,Map<string,number>>();
 for(const object of objects){
  let byId=positions.get(object.kind);
  if(!byId){byId=new Map();positions.set(object.kind,byId);}
  const index=byId.get(object.id);
  // Preserve first-occurrence order across kinds, and keep the first equal revision.
  if(index===undefined){byId.set(object.id,result.length);result.push(object);}
  else if(result[index]!.revision<object.revision)result[index]=object;
 }
 return result;
}
function put(objects:SecureObject[],kind:string,id:string,value:Row):SecureObject{return {kind,id,revision:(latest(objects,kind,id)?.revision??0)+1,value,provenance:'AUTHOR_SIGNED'};}
type AllocationInput={record_id:string;entity_id:string};
export type SecureActionInput={instance_id:string;expected_instance_revision:number;action_id:string;body:SecureJson;exact_input_refs:{record_id:string;revision:number}[];allocations:AllocationInput[]};
export async function prepareSecureAction(input:{objects:SecureObject[];context:SecureCommitContext;policy:SecurePolicy;body:SecureJson;exactRefs?:{record_id:string;revision:number}[];allocations?:AllocationInput[]}):Promise<SecureOperation>{
 const {objects,context,policy}=input,instanceObject=latest(objects,'instances',context.instance_id??'');check(instanceObject,'INSTANCE_NOT_FOUND');const instance=row(instanceObject);
 check(instance.workspace_id===context.workspace_id&&instance.id===context.instance_id,'INSTANCE_SCOPE_MISMATCH');
 const latestObjects=secureLatestObjects(objects);
 const status=latestObjects.find(o=>o.kind==='protocol_status'&&row(o).digest===instance.protocol_digest);check(!status||row(status).state==='ACTIVE','PROTOCOL_SUSPENDED');
 const protocolObject=latestObjects.find(o=>o.kind==='protocols'&&row(o).digest===instance.protocol_digest);check(protocolObject,'PROTOCOL_NOT_FOUND');const protocol=row(protocolObject),manifest=decoded(protocol.resolved_manifest??protocol.manifest) as Manifest;
 const member=await resolveSecureAuthor(context,policy),scopes=member.scopes.filter(s=>s.instance_id===null||s.instance_id===context.instance_id);
 check(permitsSecure(member,context.action_id,context.instance_id),'AUTHOR_SCOPE_DENIED');
 validateSecureRolePolicies(policy,objects,new Map(),context.issued_at,context.instance_id);
 const exactRefs=input.exactRefs??[];check(exactRefs.length<=32&&new Set(exactRefs.map(r=>r.record_id+':'+r.revision)).size===exactRefs.length,'REFERENCE_INVALID');
 const exactInputs:ResolvedInput[]=exactRefs.map(ref=>{const found=objects.find(o=>o.kind==='records'&&o.id===ref.record_id&&row(o).revision===ref.revision);check(found,'REFERENCE_NOT_FOUND');const r=row(found);check(r.workspace_id===context.workspace_id&&r.schema_ref!=='participation.request','REFERENCE_SCOPE_MISMATCH');return {recordId:ref.record_id,revision:ref.revision,schema:String(r.schema_ref),payload:decoded(r.payload),entityId:String(r.entity_id),scope:r.instance_id===context.instance_id&&r.protocol_digest===instance.protocol_digest?'INSTANCE':'WORKSPACE'};});
 // Structured v2 and format-one v3 validate the real private source state even
 // when the Owner keeps status or parent encrypted. Less disclosure cannot
 // weaken client semantics or full decrypted replay.
 if((context.v===2||context.v===3)&&context.action_id==='task.update'&&manifest.record_schemas['task.revision']){
  const body=input.body as Row,ref=body.task_ref as Row|undefined,prior=exactInputs.find(r=>r.recordId===ref?.record_id&&r.revision===ref?.revision&&r.schema==='task.revision'&&r.scope==='INSTANCE');
  check(prior&&body.from_status===(prior.payload as Row).status,'TASK_SOURCE_STATUS_MISMATCH');
 }
 const sourceState=decoded(instance.state);validateStateArrayTypes(manifest,sourceState);
 const interpreted=evaluateAction({manifest:validateResolvedManifest({actions:manifest.actions}),actionId:context.action_id,state:sourceState,body:input.body,auth:{actorId:member.actor_id,workspaceRoles:[member.role],protocolRoles:[...new Set(scopes.flatMap(s=>s.protocol_roles))],capabilities:[...new Set(scopes.flatMap(s=>s.capabilities))]},exactInputs});
 const allocations=input.allocations??interpreted.records.map(()=>({record_id:secureToken(),entity_id:secureToken()}));check(allocations.length===interpreted.records.length,'ALLOCATION_INVALID');
 check(allocations.every(a=>/^[A-Za-z0-9_-]{43}$/.test(a.record_id)&&/^[A-Za-z0-9_-]{43}$/.test(a.entity_id))&&new Set(allocations.map(a=>a.record_id)).size===allocations.length,'ALLOCATION_INVALID');
 check(allocations.every(a=>!objects.some(o=>o.kind==='records'&&o.id===a.record_id)),'RECORD_ALREADY_EXISTS');
 const allRecords=objects.filter(o=>o.kind==='records').map(row),recordSlots=new Map<string,{record_id:string;revision:number}>(),entitySlots=new Map<string,string>(),entityMax=new Map<string,number>();
 const assigned:{id:string;entityId:string;revision:number;parent?:{recordId:string;revision:number};record:typeof interpreted.records[number]}[]=[];
 for(let i=0;i<interpreted.records.length;i++){const record=interpreted.records[i]!,a=allocations[i]!;let entityId=a.entity_id,revision=1,parent:{recordId:string;revision:number}|undefined;
  if(record.entitySlot){entityId=encodeBase64Url(await sha256(new TextEncoder().encode(`${context.instance_id}\0${record.entitySlot}`)));const prior=allRecords.filter(r=>r.entity_id===entityId).sort((a,b)=>Number(b.revision)-Number(a.revision))[0];if(prior){check(exactRefs.some(r=>r.record_id===prior.id&&r.revision===prior.revision),'STALE_REVISION');revision=(entityMax.get(entityId)??Number(prior.revision))+1;}entitySlots.set(record.entitySlot,entityId);}
  else if(record.entity?.mode==='new'){check(!allRecords.some(r=>r.entity_id===entityId)&&!assigned.some(r=>r.entityId===entityId),'ENTITY_ALREADY_EXISTS');entitySlots.set(record.entity.slot,entityId);}
  else if(record.entity){parent=record.entity.parent;const prior=allRecords.find(r=>r.id===parent!.recordId&&r.revision===parent!.revision);check(prior&&prior.workspace_id===context.workspace_id&&prior.instance_id===context.instance_id&&prior.protocol_digest===instance.protocol_digest,'ENTITY_PARENT_INVALID');entityId=String(prior.entity_id);revision=(entityMax.get(entityId)??Math.max(...allRecords.filter(r=>r.entity_id===entityId).map(r=>Number(r.revision))))+1;entitySlots.set(record.entity.slot,entityId);if(record.selectHead){const head=latest(objects,'entity_heads',entityId);check(head&&row(head).record_id===parent.recordId&&row(head).revision===parent.revision,'STALE_REVISION');}}
  else check(!allRecords.some(r=>r.entity_id===entityId)&&!assigned.some(r=>r.entityId===entityId),'ENTITY_ALREADY_EXISTS');
  entityMax.set(entityId,revision);if(record.recordSlot){check(!recordSlots.has(record.recordSlot));recordSlots.set(record.recordSlot,{record_id:a.record_id,revision});}assigned.push({id:a.record_id,entityId,revision,...parent?{parent}:{},record});
 }
 const substitute=(value:unknown,depth=0):SecureJson=>{check(depth<=12);if(Array.isArray(value))return value.map(v=>substitute(v,depth+1));if(value&&typeof value==='object'){const source=value as Row;if(source.$produced==='record'){const found=recordSlots.get(String(source.slot));check(found);return found;}if(source.$produced==='entity'){const found=entitySlots.get(String(source.slot));check(found);return found;}const out:Row={};for(const [key,item] of Object.entries(source))out[key]=substitute(item,depth+1);return out;}return value as SecureJson;};
 const produced:SecureObject[]=[],headChanges=new Map<string,Row>();
 for(const a of assigned){const payload=substitute(a.record.payload),schema=manifest.record_schemas[a.record.schema];check(schema&&payload&&typeof payload==='object'&&!Array.isArray(payload),'RECORD_SCHEMA_INVALID');const p=payload as Row;check(schema.required.every(k=>Object.hasOwn(p,k))&&Object.keys(p).every(k=>Object.hasOwn(schema.fields,k)),'RECORD_SCHEMA_INVALID');for(const [key,value] of Object.entries(p)){const type=schema.fields[key];check(type==='json'||type==='null'&&value===null||type==='integer'&&Number.isSafeInteger(value)||type==='string'&&typeof value==='string'||type==='boolean'&&typeof value==='boolean','RECORD_SCHEMA_INVALID');const declaration=schema.protection?.fields[key];if(declaration?.protection==='server_readable')fieldValue(declaration,value);}check(encodeCanonicalJson(p).byteLength<=schema.max_bytes,'RECORD_TOO_LARGE');
  const value:Row={id:a.id,workspace_id:context.workspace_id,instance_id:context.instance_id,protocol_digest:instance.protocol_digest!,entity_id:a.entityId,schema_ref:a.record.schema,payload:p,actor_id:member.actor_id,revision:a.revision,created:context.issued_at};produced.push({kind:'records',id:a.id,revision:1,value,provenance:'AUTHOR_SIGNED'});
  for(const relation of a.record.relations){const target=substitute(relation.target) as Row,recordId=String(target.recordId??target.record_id),targetRevision=Number(target.revision);check(allRecords.some(r=>r.id===recordId&&r.revision===targetRevision)||assigned.some(r=>r.id===recordId&&r.revision===targetRevision),'RELATION_TARGET_INVALID');const id=JSON.stringify([a.id,relation.kind,recordId,targetRevision]);produced.push(put(objects,'record_relations',id,{record_id:a.id,kind:relation.kind,target_record:recordId,target_revision:targetRevision}));}
  if(a.record.entity&&a.record.selectHead){check(!headChanges.has(a.entityId),'HEAD_CONFLICT');headChanges.set(a.entityId,{entity_id:a.entityId,workspace_id:context.workspace_id,instance_id:context.instance_id,record_id:a.id,revision:a.revision,updated:context.issued_at});}
 }
 for(const selection of interpreted.headSelections){const expected=allRecords.find(r=>r.id===selection.expected.recordId&&r.revision===selection.expected.revision),target=allRecords.find(r=>r.id===selection.target.recordId&&r.revision===selection.target.revision);check(expected&&target&&expected.entity_id===target.entity_id,'HEAD_SELECTION_INVALID');const entity=String(expected.entity_id),head=latest(objects,'entity_heads',entity);check(head&&row(head).record_id===expected.id&&row(head).revision===expected.revision&&!headChanges.has(entity),'STALE_REVISION');headChanges.set(entity,{...row(head),record_id:target.id!,revision:target.revision!,updated:context.issued_at});}
 for(const [id,value] of headChanges)produced.push(put(objects,'entity_heads',id,value));
 if(Object.values(manifest.record_schemas).some(schema=>schema.workflow)){const beforeHeads=secureLatestObjects(objects).filter(o=>o.kind==='entity_heads').map(o=>row(o)) as any[],afterHeads=new Map(beforeHeads.map(head=>[String(head.entity_id),head]));for(const [id,head] of headChanges)afterHeads.set(id,head);const changed=produced.filter(o=>o.kind==='records').map(o=>row(o));validateWorkflowRows(manifest.record_schemas,context.instance_id!,String(instance.protocol_digest),context.action_id,allRecords,[...allRecords,...changed],beforeHeads,[...afterHeads.values()] as any[],changed.map(row=>String(row.id)),new Set(policy.payload.members.map(member=>member.actor_id)));}
 const state=substitute(interpreted.nextState);validateStateArrayTypes(manifest,state);check(encodeCanonicalJson(state).byteLength<=65536,'STATE_TOO_LARGE');produced.push(put(objects,'instances',context.instance_id!,{...instance,state,revision:Number(instance.revision)+(interpreted.revisionEffects.control?1:0),event_revision:Number(instance.event_revision??0)+1}));
 const action:SecureActionInput={instance_id:context.instance_id!,expected_instance_revision:Number(instance.revision),action_id:context.action_id,body:input.body,exact_input_refs:exactRefs,allocations};
 return {v:1,kind:'ACTION',input:action as unknown as SecureJson,objects:produced};
}
export async function validateSecureOperation(operation:SecureOperation,context:SecureCommitContext,policy:SecurePolicy,objects:SecureObject[]):Promise<void>{
 if(context.action_id===PROTOCOL_OBJECT_STAGE_ACTION){await resolveSecureAuthor(context,policy);await validateProtocolObjectStageOperation(operation,context,policy,objects);return;}
 if(['ACTION','BOOTSTRAP','ADMIN'].includes(operation.kind))check(!operation.objects.some(object=>object.kind==='protocol_object_part'),'ADMIN_CONTENT_KIND_DENIED');
 if(context.action_id==='secure.protocol-package.stage'){
  check(operation.v===1&&operation.kind==='ADMIN'&&Object.keys(operation).sort().join(',')==='input,kind,objects,v'&&operation.objects.length===1,'PROTOCOL_PACKAGE_STAGE_INVALID');
  check(policy.payload.visibility==='PRIVATE'&&(policy.payload.v===2||policy.payload.v===3&&policy.payload.structure_mode==='STRUCTURED')&&policy.payload.structure&&context.v===policy.payload.v&&context.actor_id===policy.payload.owner_id&&context.signing_key===policy.payload.signing_key&&context.delegation===null&&context.instance_id===null&&context.structure?.mode==='DELTA'&&context.structure.v===1&&Object.keys(context.structure).sort().join(',')==='heads,mode,records,v'&&Array.isArray(context.structure.records)&&context.structure.records.length===0&&Array.isArray(context.structure.heads)&&context.structure.heads.length===0&&!context.recovery&&!context.migration&&!context.conversion_excluded_members&&context.epoch===policy.payload.epoch&&context.policy_hash===await secureHash(policy),'PROTOCOL_PACKAGE_STAGE_INVALID');
  const author=await resolveSecureAuthor(context,policy);check(author.role==='OWNER','OWNER_OPERATION_REQUIRED');
  const input=operation.input as any,stage=input?.package_stage;
  check(input&&Object.keys(input).sort().join(',')==='package_stage'&&stage&&Object.keys(stage).sort().join(',')==='part_index,source,source_id','PROTOCOL_PACKAGE_STAGE_INVALID');
  const source=normalizeProtocolPackageSourceCheckpoint(stage.source),part=validateProtocolPackagePart(operation.objects[0]),value=part.value as any;
  check(source.workspace_id===context.workspace_id&&source.owner_id===context.actor_id&&source.owner_key===context.signing_key&&source.policy_hash===context.policy_hash&&policy.payload.effective_sequence<=source.sequence&&stage.source_id===value.source_id&&stage.part_index===value.index&&part.id===protocolPackagePartId(source,stage.source_id,stage.part_index)&&value.workspace_id===context.workspace_id&&context.sequence===source.sequence+stage.part_index+1&&!objects.some(object=>object.kind===part.kind&&object.id===part.id),'PROTOCOL_PACKAGE_STAGE_INVALID');
  if(stage.part_index===0)check(context.previous===source.head,'PROTOCOL_PACKAGE_STAGE_INVALID');
  else{const prior=objects.filter(object=>object.kind==='protocol_package_part'&&object.id===protocolPackagePartId(source,stage.source_id,stage.part_index-1));check(prior.length===1,'PROTOCOL_PACKAGE_STAGE_INVALID');const previous=validateProtocolPackagePart(prior[0]),data=previous.value as any;check(data.source_id===stage.source_id&&data.workspace_id===source.workspace_id&&data.index===stage.part_index-1,'PROTOCOL_PACKAGE_STAGE_INVALID');}
  return;
 }
 if(['ACTION','BOOTSTRAP','ADMIN'].includes(operation.kind))check(!operation.objects.some(object=>object.kind==='protocol_package_part'),'ADMIN_CONTENT_KIND_DENIED');
 if(operation.kind==='ACTION'){const input=operation.input as unknown as SecureActionInput;check(input?.action_id===context.action_id&&input.instance_id===context.instance_id&&Array.isArray(input.exact_input_refs)&&Array.isArray(input.allocations),'ACTION_CONTEXT_MISMATCH');const instance=latest(objects,'instances',context.instance_id!);check(instance&&row(instance).revision===input.expected_instance_revision,'STALE_REVISION');const expected=await prepareSecureAction({objects,context,policy,body:input.body,exactRefs:input.exact_input_refs,allocations:input.allocations});check(secureEqual(expected,operation),'PROTOCOL_OUTPUT_MISMATCH');return;}
 if(operation.kind==='BOOTSTRAP'){check(context.sequence===1&&objects.length===0,'BOOTSTRAP_INVALID');}
 if(operation.kind==='MIGRATE'){check(context.migration,'MIGRATION_CONTEXT_REQUIRED');const descriptors=operation.objects.map(o=>({kind:o.kind,id:o.id,revision:o.revision}));check(secureEqual(descriptors,context.migration.source_items),'MIGRATION_COVERAGE_MISMATCH');return;}
 // An owner's configuration authority must not fabricate another author's record.
 check(operation.objects.every(o=>['workspaces','protocols','instances','workspace_config','entrypoints','protocol_status','protocol_drafts','protocol_draft_revisions','protocol_validations','instance_links'].includes(o.kind)),'ADMIN_CONTENT_KIND_DENIED');
 for(const o of operation.objects){const value=row(o);if(value.workspace_id!==undefined)check(value.workspace_id===context.workspace_id,'OBJECT_WORKSPACE_MISMATCH');if(o.kind==='workspaces')check(o.id===context.workspace_id&&value.id===context.workspace_id,'OBJECT_WORKSPACE_MISMATCH');const prior=latest(objects,o.kind,o.id);check(o.revision===(prior?.revision??0)+1,'OBJECT_REVISION_INVALID');if(o.kind==='protocols'){const manifest=decoded(value.resolved_manifest??value.manifest) as Manifest;validateResolvedManifest({actions:manifest.actions});}}
}

/** Apply the original protocol's separation-of-duty rules to signed policies.
 * The accumulator includes revoked roles: revocation cannot erase history. */
export function validateSecureRolePolicies(policy:SecurePolicy,objects:SecureObject[],history:Map<string,Set<string>>,at=policy.payload.issued_at,validateInstanceId?:string|null):void{
 const latest=secureLatestObjects(objects),protocols=latest.filter(o=>o.kind==='protocols');
 for(const object of latest.filter(o=>o.kind==='instances')){
  const instance=row(object),protocol=protocols.find(o=>row(o).digest===instance.protocol_digest);if(!protocol)continue;
  const manifest=decoded(row(protocol).resolved_manifest??row(protocol).manifest) as Manifest;
  check(Array.isArray(manifest.role_conflicts)&&Array.isArray(manifest.historical_role_conflicts),'PROTOCOL_ROLE_POLICY_INVALID');
  for(const legacyGrant of latest.filter(o=>o.kind==='grants')){const grant=row(legacyGrant);if(grant.instance_id!==object.id||grant.protocol_digest!==instance.protocol_digest)continue;const roles=decoded(grant.protocol_roles);check(Array.isArray(roles)&&roles.every(r=>typeof r==='string'),'LEGACY_GRANT_INVALID');const key=JSON.stringify([object.id,instance.protocol_digest,grant.actor_id]);history.set(key,new Set([...(history.get(key)??[]),...roles as string[]]));}
  for(const member of policy.payload.members){
   const roles=new Set(member.scopes.filter(s=>(s.expires_at==null||s.expires_at>at)&&(s.instance_id===null||s.instance_id===object.id)).flatMap(s=>s.protocol_roles)),key=JSON.stringify([object.id,instance.protocol_digest,member.actor_id]),past=new Set([...(history.get(key)??[]),...roles]);
   if(validateInstanceId===undefined||validateInstanceId===object.id){for(const [left,right] of manifest.role_conflicts)check(!(roles.has(left)&&roles.has(right)),'ACTIVE_ROLE_CONFLICT');
   for(const [left,right] of manifest.historical_role_conflicts)check(!(past.has(left)&&past.has(right)),'HISTORICAL_ROLE_CONFLICT');}
   history.set(key,past);
  }
 }
}
