/** Pure deterministic composition; callers verify dependency digests before loading. */
import {ApiError} from './errors.js';
import {manifestSchema,manifestCanonical,canonicalStructured,type Manifest} from './workspace-manifest.js';
import {validateResolvedManifest} from './workspace-interpreter.js';
const MAX_DEPENDENCIES=16;
const ordinal=(a:string,b:string)=>a<b?-1:a>b?1:0;
function fail(code='INVALID_PAYLOAD',status=400):never{throw new ApiError(code,status);}
function objectState(value:unknown){if(!value||typeof value!=='object'||Array.isArray(value))fail('COMPOSITION_CONFLICT',409);return value as Record<string,unknown>;}
const isObjectState=(value:unknown)=>Boolean(value&&typeof value==='object'&&!Array.isArray(value));
const emptyObjectState=(value:unknown)=>isObjectState(value)&&Object.keys(value as object).length===0;
function usesState(node:unknown):boolean{
 if(!node||typeof node!=='object')return false;
 if(Array.isArray(node))return node.some(usesState);
 const value=node as Record<string,unknown>;
 if(value.from==='state'||value.source==='state'||value.op==='set')return true;
 return Object.entries(value).some(([key,child])=>!(value.from==='literal'&&key==='value')&&usesState(child));
}
function stateless(manifest:Manifest):boolean{
 return manifest.actions.every(action=>!action.reads.length&&!action.writes.length&&!usesState(action))&&
  Object.values(manifest.constraints).every(rules=>!usesState(rules));
}
function same(a:unknown,b:unknown){return canonicalStructured(a)===canonicalStructured(b);}

export function composeProtocol(rootValue:unknown,load:(digest:string)=>unknown|undefined,compare:(a:string,b:string)=>number=ordinal){
 const root=manifestSchema.parse(rootValue),ordered:Manifest[]=[],closure:string[]=[],active=new Set<string>(),done=new Set<string>();
 const visit=(digest:string,depth:number)=>{if(active.has(digest))fail('DEPENDENCY_CYCLE',409);if(done.has(digest))return;if(depth>MAX_DEPENDENCIES||active.size+done.size>=MAX_DEPENDENCIES)fail('RESOURCE_EXHAUSTED',429);const value=load(digest);if(value===undefined)fail('DEPENDENCY_MISSING',409);const manifest=manifestSchema.parse(value);active.add(digest);for(const child of [...manifest.dependencies].sort())visit(child,depth+1);active.delete(digest);done.add(digest);closure.push(digest);ordered.push(manifest);};
 for(const digest of [...root.dependencies].sort())visit(digest,1);ordered.push(root);
 const standalone=closure.length===0,nonObjectRoot=!isObjectState(root.initial_state);
 if(nonObjectRoot&&!standalone&&(!ordered.slice(0,-1).every(module=>emptyObjectState(module.initial_state))||!ordered.every(stateless)))fail('COMPOSITION_CONFLICT',409);
 const schemas:Manifest['record_schemas']={},actions=new Map<string,Manifest['actions'][number]>(),roles=new Set<string>(),capabilities=new Set<string>(),conflicts=new Map<string,[string,string]>(),historicalConflicts=new Map<string,[string,string]>(),state:unknown=standalone||nonObjectRoot?root.initial_state:{},constraints=new Map<string,unknown[]>();
 const stateOwners=new Map<string,Manifest['state_array_types']>(),arrayTypes=new Map<string,NonNullable<Manifest['state_array_types']>[number]>();
 for(const manifest of ordered){for(const [name,schema] of Object.entries(manifest.record_schemas)){if(schemas[name]&&!same(schemas[name],schema))fail('COMPOSITION_CONFLICT',409);schemas[name]=schema;}for(const action of manifest.actions){if(actions.has(action.id))fail('REDUCER_CONFLICT',409);actions.set(action.id,action);}for(const role of manifest.protocol_roles)roles.add(role);for(const capability of manifest.capabilities)capabilities.add(capability);for(const pair of manifest.role_conflicts){const sorted=[...pair].sort() as [string,string];conflicts.set(sorted.join('\0'),sorted);}for(const pair of manifest.historical_role_conflicts){const sorted=[...pair].sort() as [string,string];historicalConflicts.set(sorted.join('\0'),sorted);}if(!standalone&&!nonObjectRoot)for(const [key,value] of Object.entries(objectState(manifest.initial_state))){const declarations=manifest.state_array_types?.filter(entry=>entry.path[0]===key)??[];if(Object.hasOwn(state as object,key)&&(!same((state as Record<string,unknown>)[key],value)||!same(stateOwners.get(key)??[],declarations)))fail('COMPOSITION_CONFLICT',409);(state as Record<string,unknown>)[key]=value;stateOwners.set(key,declarations);}for(const entry of manifest.state_array_types??[]){const path=JSON.stringify(entry.path),previous=arrayTypes.get(path);if(previous&&!same(previous,entry))fail('COMPOSITION_CONFLICT',409);arrayTypes.set(path,entry);}for(const [id,rules] of Object.entries(manifest.constraints)){const list=constraints.get(id)??[];list.push(...rules);constraints.set(id,list);}}
 const unresolved=[...constraints.keys()].filter(id=>!actions.has(id));if(unresolved.length&&actions.size>0)fail('COMPOSITION_CONFLICT',409);
 const resolvedActions=[...actions.values()].sort((a,b)=>compare(a.id,b.id)).map(action=>{const extra=constraints.get(action.id)??[];return extra.length?{...action,variants:action.variants.map(variant=>({...variant,when:[...extra,...variant.when]}))}:action;});
 const retainedConstraints=actions.size?{}:Object.fromEntries([...constraints.entries()].sort(([a],[b])=>compare(a,b)));const mergedArrayTypes=[...arrayTypes.values()].sort((a,b)=>ordinal(JSON.stringify(a.path),JSON.stringify(b.path)));const requirementSources=[...ordered,root].filter(item=>item.execution_requirements),executionRequirements=root.execution_requirements?.closure_complete?root.execution_requirements:requirementSources.length?{format:'peerwork.protocol-execution-requirements.v1' as const,closure_complete:true,ports:requirementSources.flatMap(item=>item.execution_requirements?.ports??[])}:undefined;const manifest=manifestSchema.parse({name:root.name,display_version:root.display_version,semantics:root.semantics,dependencies:[...closure],protocol_roles:[...roles].sort(),capabilities:[...capabilities].sort(),role_conflicts:[...conflicts.values()].sort((a,b)=>compare(a.join(),b.join())),historical_role_conflicts:[...historicalConflicts.values()].sort((a,b)=>compare(a.join(),b.join())),constraints:retainedConstraints,record_schemas:schemas,initial_state:state,...mergedArrayTypes.length?{format_version:2,state_array_types:mergedArrayTypes}:{},...root.state_exports?{state_exports:root.state_exports}:{},actions:resolvedActions,...(executionRequirements?{execution_requirements:executionRequirements}:{})});validateResolvedManifest({actions:manifest.actions});for(const port of manifest.execution_requirements?.ports??[]){const action=manifest.actions.find(item=>item.id===port.action_id);if(!action||!action.variants[port.variant])fail('COMPOSITION_CONFLICT',409);}manifestCanonical(manifest);return {dependencyClosure:closure,manifest};
}
