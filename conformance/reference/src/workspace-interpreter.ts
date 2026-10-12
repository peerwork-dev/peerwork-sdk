import {z} from 'zod';
import {ApiError} from './errors.js';
const byteLength=(value:string)=>new TextEncoder().encode(value).byteLength;

const L={nodes:2048,depth:12,effects:16,records:8,relations:32,valueBytes:16_384,list:128,string:8_192,auth:64};
const segment=z.string().min(1).max(80).refine(v=>!['__proto__','prototype','constructor'].includes(v));
const path=z.array(segment).max(L.depth);
const refShape=z.object({record_id:z.string().regex(/^[A-Za-z0-9_-]{43}$/),revision:z.number().int().positive()}).strict();
const json:z.ZodType<unknown>=z.lazy(()=>z.union([z.null(),z.boolean(),z.number().int().safe(),z.string().refine(v=>byteLength(v)<=L.string),z.array(json).max(L.list),z.record(z.string(),json)]));
const refSelector=z.object({from:z.literal('ref'),source:z.enum(['body','state']),path,schema:segment.optional(),scope:z.enum(['INSTANCE','WORKSPACE'])}).strict();
const actionInputField=z.discriminatedUnion('type',[
 z.object({type:z.literal('string'),maxBytes:z.number().int().positive().max(L.string).optional(),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('integer'),minimum:z.number().int().safe().optional(),maximum:z.number().int().safe().optional(),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('boolean'),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('enum'),values:z.array(z.string().min(1).max(L.string)).min(1).max(64),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('actor_id')}).strict(),
 z.object({type:z.literal('exact_ref'),schema:segment,scope:z.enum(['INSTANCE','WORKSPACE'])}).strict(),
]);
const actionInputs=z.object({fields:z.record(segment,actionInputField),required:z.array(segment).max(32),additionalProperties:z.boolean()}).strict().superRefine((value,ctx)=>{
 if(Object.keys(value.fields).length>32)ctx.addIssue({code:'custom',message:'too many action input fields'});
 if(value.required.some(name=>!Object.hasOwn(value.fields,name))||new Set(value.required).size!==value.required.length)ctx.addIssue({code:'custom',message:'invalid required action input'});
 for(const field of Object.values(value.fields) as any[])if(field.type==='integer'&&field.minimum!==undefined&&field.maximum!==undefined&&field.minimum>field.maximum)ctx.addIssue({code:'custom',message:'invalid integer input bounds'});
});
const producedRef=z.object({from:z.literal('produced_ref'),slot:segment}).strict();
const selector:z.ZodType<any>=z.lazy(()=>z.discriminatedUnion('from',[
 z.object({from:z.literal('literal'),value:json}).strict(),z.object({from:z.enum(['body','state']),path}).strict(),
 z.object({from:z.literal('time')}).strict(),z.object({from:z.literal('time_add'),timestamp:selector,milliseconds:selector}).strict(),
 z.object({from:z.literal('auth'),field:z.enum(['actorId','workspaceRoles','protocolRoles','capabilities'])}).strict(),refSelector,
 z.object({from:z.literal('resolved_entity'),ref:refSelector}).strict(),z.object({from:z.literal('resolved_payload'),ref:refSelector,path}).strict(),producedRef,z.object({from:z.literal('produced_entity'),slot:segment}).strict(),
 z.object({from:z.literal('object'),fields:z.record(segment,selector)}).strict(),z.object({from:z.literal('array'),items:z.array(selector).max(L.list)}).strict(),
]));
export const guardSchema:z.ZodType<any>=z.lazy(()=>z.discriminatedUnion('op',[
 z.object({op:z.literal('eq'),left:selector,right:selector}).strict(),z.object({op:z.literal('in'),value:selector,set:z.array(selector).max(L.list)}).strict(),
 z.object({op:z.enum(['lt','lte','gt','gte']),left:selector,right:selector}).strict(),
 z.object({op:z.literal('has_role'),role:segment}).strict(),z.object({op:z.literal('has_protocol_role'),role:segment}).strict(),z.object({op:z.literal('has_capability'),capability:z.string().min(1).max(120)}).strict(),
 z.object({op:z.literal('exact_ref'),ref:refSelector}).strict(),z.object({op:z.literal('exact_ref_list'),source:z.enum(['body','state']),path,scope:z.enum(['INSTANCE','WORKSPACE','INSTANCE_OR_WORKSPACE']),schema:segment.optional(),max:z.number().int().positive().max(32)}).strict(),z.object({op:z.enum(['and','or']),rules:z.array(guardSchema).min(1).max(32)}).strict(),z.object({op:z.literal('not'),rule:guardSchema}).strict(),
]));
const relation=z.object({kind:segment,target:z.discriminatedUnion('from',[refSelector,producedRef])}).strict();
const entity=z.discriminatedUnion('mode',[z.object({mode:z.literal('new'),slot:segment}).strict(),z.object({mode:z.literal('revise'),slot:segment,parent:refSelector}).strict()]);
const effect=z.discriminatedUnion('op',[
 z.object({op:z.literal('set'),path:path.min(1),value:selector}).strict(),
 z.object({op:z.literal('append'),schema:segment,recordSlot:segment.optional(),entitySlot:segment.optional(),entity:entity.optional(),selectHead:z.boolean().default(false),value:selector,relations:z.array(relation).max(L.relations).default([])}).strict().refine(v=>!(v.entitySlot&&v.entity)),
 z.object({op:z.literal('select_head'),expected:refSelector,target:refSelector}).strict(),
]);
const variant=z.object({when:z.array(guardSchema).max(32),effects:z.array(effect).max(L.effects)}).strict();
const action=z.object({id:z.string().min(1).max(120),reads:z.array(path).max(64),writes:z.array(path.min(1)).max(64),revisionEffects:z.object({control:z.boolean(),contentEntities:z.array(segment).max(L.records)}).strict(),variants:z.array(variant).min(1).max(32),inputs:actionInputs.optional()}).strict();
export const interpreterManifestSchema=z.object({actions:z.array(action).max(64)}).strict();
export type ResolvedManifest=z.infer<typeof interpreterManifestSchema>;
export type ResolvedInput={recordId:string;revision:number;schema:string;payload:unknown;scope:'INSTANCE'|'WORKSPACE';entityId?:string};
export type InterpreterAuth={actorId:string;roles?:readonly string[];workspaceRoles?:readonly string[];protocolRoles?:readonly string[];capabilities:readonly string[]};
export type ActionInputs=z.infer<typeof actionInputs>;
export type ProducedReference={$produced:'record';slot:string};
export type InterpreterRecord={schema:string;recordSlot?:string;entitySlot?:string;entity?:{mode:'new';slot:string}|{mode:'revise';slot:string;parent:{recordId:string;revision:number}};selectHead?:boolean;payload:unknown;relations:{kind:string;target:{recordId:string;revision:number}|ProducedReference}[]};
export type HeadSelection={expected:{recordId:string;revision:number};target:{recordId:string;revision:number}};

function reject(code='INVALID_PAYLOAD'):never{throw new ApiError(code,code==='CONSTRAINT_FAILED'||code==='STALE_REVISION'?409:code==='FORBIDDEN'?403:code==='RESOURCE_EXHAUSTED'?429:400);}
function safeValue(value:unknown,depth=0,n={v:0}):unknown{if(++n.v>L.nodes||depth>L.depth)reject();if(value===null||typeof value==='boolean')return value;if(typeof value==='string'){if(byteLength(value)>L.string)reject();return value;}if(typeof value==='number'){if(!Number.isSafeInteger(value))reject();return value;}if(Array.isArray(value)){if(value.length>L.list)reject();return value.map(v=>safeValue(v,depth+1,n));}if(value&&typeof value==='object'){const out:Record<string,unknown>={};for(const key of Object.keys(value as object).sort()){if(!segment.safeParse(key).success)reject();out[key]=safeValue((value as Record<string,unknown>)[key],depth+1,n);}return out;}reject();}
function canonical(v:unknown){return JSON.stringify(safeValue(v));}
function at(root:unknown,p:readonly string[]){let v=root;for(const key of p){if(!v||typeof v!=='object'||Array.isArray(v)||!Object.hasOwn(v,key))reject();v=(v as Record<string,unknown>)[key];}return v;}
function owns(all:readonly (readonly string[])[],p:readonly string[]){return all.some(d=>d.length<=p.length&&d.every((x,i)=>x===p[i]));}
function validateActionInputs(contract:ActionInputs|undefined,body:unknown,exactInputs:Map<string,ResolvedInput>){
 if(!contract)return;if(!body||typeof body!=='object'||Array.isArray(body))reject();const value=body as Record<string,unknown>,keys=Object.keys(value);
 if(!contract.additionalProperties&&keys.some(key=>!Object.hasOwn(contract.fields,key))||contract.required.some(key=>!Object.hasOwn(value,key)))reject();
 for(const key of keys){const field=contract.fields[key];if(!field){if(contract.additionalProperties)continue;reject();}const current=value[key];if(current===null&&'nullable'in field&&field.nullable)continue;
  if(field.type==='string'){if(typeof current!=='string'||byteLength(current)>(field.maxBytes??L.string))reject();}
  else if(field.type==='integer'){if(typeof current!=='number'||!Number.isSafeInteger(current)||(field.minimum!==undefined&&current<field.minimum)||(field.maximum!==undefined&&current>field.maximum))reject();}
  else if(field.type==='boolean'){if(typeof current!=='boolean')reject();}
  else if(field.type==='enum'){if(typeof current!=='string'||!field.values.includes(current))reject();}
  else if(field.type==='actor_id'){if(typeof current!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(current))reject();}
  else{const ref=refShape.safeParse(current);if(!ref.success)reject();const resolved=exactInputs.get(`${ref.data.record_id}:${ref.data.revision}`);if(!resolved||resolved.scope!==field.scope||(field.schema!=='*'&&resolved.schema!==field.schema))reject();}
 }
}
function walk(v:unknown,fn:(v:Record<string,unknown>)=>void,depth=0,n={v:0}){if(++n.v>L.nodes||depth>32)reject();if(Array.isArray(v))for(const x of v)walk(x,fn,depth+1,n);else if(v&&typeof v==='object'){const r=v as Record<string,unknown>;if(typeof r.from==='string')fn(r);for(const [k,x] of Object.entries(r)){if(['__proto__','prototype','constructor'].includes(k))reject();walk(x,fn,depth+1,n);}}}

export function validateResolvedManifest(value:unknown):ResolvedManifest{
 walk(value,s=>{if(s.from==='literal')safeValue(s.value);});const parsed=interpreterManifestSchema.safeParse(value);if(!parsed.success||parsed.data.actions.length>=64)reject();const ids=parsed.data.actions.map(a=>a.id);if(new Set(ids).size!==ids.length)reject();
 for(const a of parsed.data.actions){const content=new Set(a.revisionEffects.contentEntities);if(content.size!==a.revisionEffects.contentEntities.length)reject();for(const v of a.variants){const rs=v.effects.flatMap(e=>e.op==='append'&&e.recordSlot?[e.recordSlot]:[]),es=v.effects.flatMap(e=>e.op==='append'?(e.entity?[e.entity.slot]:e.entitySlot?[e.entitySlot]:[]):[]);if(new Set(rs).size!==rs.length||new Set(es).size!==es.length||es.some(s=>!content.has(s)))reject();for(const g of v.when)walk(g,s=>{if(s.from==='produced_ref'||s.from==='produced_entity')reject();});for(const e of v.effects){if(e.op==='set'&&!owns(a.writes,e.path))reject();walk(e,s=>{if(s.from==='produced_ref'&&!rs.includes(String(s.slot))||s.from==='produced_entity'&&!es.includes(String(s.slot)))reject();});}}if(!a.revisionEffects.control&&content.size===0&&a.variants.some(v=>v.effects.some(e=>e.op==='set'||e.op==='select_head'||e.op==='append'&&e.entity!==undefined)))reject();}
 return parsed.data;
}

export function evaluateAction(input:{manifest:ResolvedManifest;actionId:string;state:unknown;body:unknown;auth:InterpreterAuth;exactInputs:ResolvedInput[];executionTimeMs?:number}):{nextState:unknown;records:InterpreterRecord[];headSelections:HeadSelection[];revisionEffects:{control:boolean;contentEntities:string[]};evaluatedAt?:number}{
 const manifest=validateResolvedManifest(input.manifest),action=manifest.actions.find(a=>a.id===input.actionId);if(!action)reject('FORBIDDEN');const workspaceRoles=input.auth.workspaceRoles??input.auth.roles??[],protocolRoles=input.auth.protocolRoles??[],lists=[workspaceRoles,protocolRoles,input.auth.capabilities];if(!/^[A-Za-z0-9_-]{43}$/.test(input.auth.actorId)||lists.some(xs=>xs.length>L.auth||new Set(xs).size!==xs.length||xs.some(x=>!x||byteLength(x)>120)))reject();
 const exact=new Map<string,ResolvedInput>();for(const x of input.exactInputs){const key=`${x.recordId}:${x.revision}`;if(exact.has(key)||!refShape.safeParse({record_id:x.recordId,revision:x.revision}).success||!segment.safeParse(x.schema).success||(x.entityId!==undefined&&!z.string().regex(/^[A-Za-z0-9_-]{43}$/).safeParse(x.entityId).success))reject();safeValue(x.payload);exact.set(key,x);}validateActionInputs(action.inputs,input.body,exact);
 let usedTime=false;const readTime=()=>{usedTime=true;if(!Number.isSafeInteger(input.executionTimeMs)||input.executionTimeMs!<0)reject();return input.executionTimeMs!;};
 const select=(s:any,produced=false):any=>{if(s.from==='literal')return safeValue(s.value);if(s.from==='time')return readTime();if(s.from==='time_add'){const timestamp=select(s.timestamp),milliseconds=select(s.milliseconds);if(!Number.isSafeInteger(timestamp)||timestamp<0||!Number.isSafeInteger(milliseconds)||milliseconds<0||timestamp>Number.MAX_SAFE_INTEGER-milliseconds)reject();return timestamp+milliseconds;}if(s.from==='auth')return s.field==='actorId'?input.auth.actorId:s.field==='workspaceRoles'?[...workspaceRoles]:s.field==='protocolRoles'?[...protocolRoles]:[...input.auth.capabilities];if(s.from==='body')return safeValue(at(input.body,s.path));if(s.from==='state'){if(!owns(action.reads,s.path))reject();return safeValue(at(input.state,s.path));}if(s.from==='object'){const o:Record<string,unknown>={};for(const k of Object.keys(s.fields).sort())o[k]=select(s.fields[k],produced);return safeValue(o);}if(s.from==='array')return safeValue(s.items.map((x:any)=>select(x,produced)));if(s.from==='produced_ref'||s.from==='produced_entity'){if(!produced)reject();return {$produced:s.from==='produced_ref'?'record':'entity',slot:s.slot};}const r=s.from==='resolved_entity'||s.from==='resolved_payload'?s.ref:s;if(r.from==='ref'){if(r.source==='state'&&!owns(action.reads,r.path))reject();const parsed=refShape.safeParse(at(r.source==='body'?input.body:input.state,r.path));if(!parsed.success)reject();const found=exact.get(`${parsed.data.record_id}:${parsed.data.revision}`);if(!found||found.scope!==r.scope||(r.schema&&found.schema!==r.schema))reject();if(s.from==='resolved_entity'&&!found.entityId)reject();return s.from==='resolved_entity'?found.entityId:s.from==='resolved_payload'?safeValue(at(found.payload,s.path)):parsed.data;}reject();};
 const test=(g:any):boolean=>g.op==='eq'?canonical(select(g.left))===canonical(select(g.right)):['lt','lte','gt','gte'].includes(g.op)?(()=>{const left=select(g.left),right=select(g.right);if(!Number.isSafeInteger(left)||!Number.isSafeInteger(right))reject();return g.op==='lt'?left<right:g.op==='lte'?left<=right:g.op==='gt'?left>right:left>=right;})():g.op==='in'?g.set.some((x:any)=>canonical(select(g.value))===canonical(select(x))):g.op==='has_role'?workspaceRoles.includes(g.role):g.op==='has_protocol_role'?protocolRoles.includes(g.role):g.op==='has_capability'?input.auth.capabilities.includes(g.capability):g.op==='exact_ref'?(select(g.ref),true):g.op==='exact_ref_list'?(()=>{if(g.source==='state'&&!owns(action.reads,g.path))reject();const value=at(g.source==='body'?input.body:input.state,g.path);if(!Array.isArray(value)||value.length>g.max)reject();for(const item of value){const parsed=refShape.safeParse(item);if(!parsed.success)reject();const found=exact.get(`${parsed.data.record_id}:${parsed.data.revision}`),scopeOk=g.scope==='INSTANCE_OR_WORKSPACE'?(found?.scope==='INSTANCE'||found?.scope==='WORKSPACE'):found?.scope===g.scope;if(!found||!scopeOk||(g.schema&&found.schema!==g.schema))reject();}return true;})():g.op==='and'?g.rules.every(test):g.op==='or'?g.rules.some(test):g.op==='not'?!test(g.rule):false;
 const matches=action.variants.filter(v=>v.when.every(test));if(matches.length!==1)reject('CONSTRAINT_FAILED');const chosen=matches[0]!;let state=safeValue(input.state);const records:InterpreterRecord[]=[],headSelections:HeadSelection[]=[];const put=(p:string[],value:unknown)=>{const copy=structuredClone(state) as Record<string,unknown>;let node=copy;for(const k of p.slice(0,-1)){if(!node[k]||typeof node[k]!=='object'||Array.isArray(node[k]))reject();node=node[k] as Record<string,unknown>;}node[p.at(-1)!]=value;state=safeValue(copy);};
 for(const e of chosen.effects){if(e.op==='set')put(e.path,select(e.value,true));else if(e.op==='select_head'){const a=select(e.expected),b=select(e.target);headSelections.push({expected:{recordId:a.record_id,revision:a.revision},target:{recordId:b.record_id,revision:b.revision}});}else{let entityValue:InterpreterRecord['entity'];if(e.entity?.mode==='new')entityValue={mode:'new',slot:e.entity.slot};else if(e.entity){const p=select(e.entity.parent);entityValue={mode:'revise',slot:e.entity.slot,parent:{recordId:p.record_id,revision:p.revision}};}const relations=e.relations.map(r=>{const t=select(r.target,true);return {kind:r.kind,target:t.$produced?t:{recordId:t.record_id,revision:t.revision}};});records.push({schema:e.schema,...e.recordSlot?{recordSlot:e.recordSlot}:{},...e.entitySlot?{entitySlot:e.entitySlot}:{},...entityValue?{entity:entityValue}:{},...(e.entity||e.selectHead?{selectHead:e.selectHead}:{}),payload:safeValue(select(e.value,true)),relations});}if(records.length>L.records||records.some(r=>byteLength(canonical(r.payload))>L.valueBytes))reject('RESOURCE_EXHAUSTED');}
 const selectedEntities=chosen.effects.flatMap(e=>e.op==='append'?(e.entity?[e.entity.slot]:e.entitySlot?[e.entitySlot]:[]):[]);return {nextState:state,records,headSelections,revisionEffects:{control:action.revisionEffects.control,contentEntities:selectedEntities},...(usedTime?{evaluatedAt:input.executionTimeMs}:{})};
}
