// Direct tracked TypeScript manifestCanonical oracle cases.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const source=process.env.PEERWORK_TS_SOURCE??fileURLToPath(new URL('reference/src/',import.meta.url));
const dir=await mkdtemp(join(tmpdir(),'peerwork-manifest-vectors-'));
try{
  const output=join(dir,'manifest.mjs');
  await build({entryPoints:[resolve(source,'workspace-manifest.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {manifestCanonical}=await import(pathToFileURL(output));
  const base={name:'demo',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],
    protocol_roles:[],capabilities:[],role_conflicts:[],historical_role_conflicts:[],
    constraints:{},record_schemas:{},initial_state:{count:0},actions:[]};
  const clone=()=>structuredClone(base);
  const cases=[
    {name:'minimal_valid',manifest:clone()},
    {name:'unknown_top_field',manifest:{...clone(),unknown:true}},
    {name:'duplicate_dependency',manifest:{...clone(),dependencies:['a'.repeat(64),'a'.repeat(64)]}},
    {name:'invalid_role_conflict',manifest:{...clone(),protocol_roles:['editor'],role_conflicts:[['editor','editor']]}},
    {name:'unknown_append_schema',manifest:{...clone(),actions:[{id:'add',reads:[],writes:[],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[],effects:[{op:'append',schema:'missing',value:{from:'literal',value:{}}}]}]}]}},
    {name:'state_array_missing_version',manifest:{...clone(),state_array_types:[{path:['refs'],kind:'exact_ref_list'}],initial_state:{refs:[]}}},
    {name:'state_array_valid',manifest:{...clone(),format_version:2,state_array_types:[{path:['refs'],kind:'exact_ref_list'}],initial_state:{refs:[]}}},
    {name:'state_array_wrong_kind',manifest:{...clone(),format_version:2,state_array_types:[{path:['refs'],kind:'exact_ref_list'}],initial_state:{refs:[1]}}},
    {name:'state_export_missing',manifest:{...clone(),state_exports:[{path:['absent'],read:true,write:false}]}},
    {name:'record_required_unknown',manifest:{...clone(),record_schemas:{entry:{type:'object',fields:{text:'string'},required:['absent'],max_bytes:1024}}}},
    {name:'record_schema_valid',manifest:{...clone(),record_schemas:{entry:{type:'object',fields:{text:'string'},required:['text'],max_bytes:1024}}}},
  ];
  const workflowSchema={type:'object',fields:{status:'string',parent:'json'},required:['status','parent'],max_bytes:1024,
    protection:{v:1,fields:{status:{protection:'e2ee',type:'string'},parent:{protection:'e2ee',type:'json'}}},
    workflow:{v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
      transitions:[{action:'task.create',from:null,to:'OPEN'},{action:'task.complete',from:'OPEN',to:'DONE'}]}};
  cases.push({name:'workflow_protected_valid',manifest:{...clone(),record_schemas:{task:structuredClone(workflowSchema)}}});
  const badProtection=structuredClone(workflowSchema);badProtection.protection.fields.status.type='integer';
  cases.push({name:'workflow_protection_type_mismatch',manifest:{...clone(),record_schemas:{task:badProtection}}});
  const missingWorkflowField=structuredClone(workflowSchema);missingWorkflowField.required=['status'];
  cases.push({name:'workflow_required_parent_missing',manifest:{...clone(),record_schemas:{task:missingWorkflowField}}});
  const readableWorkflow=structuredClone(workflowSchema);
  readableWorkflow.protection.fields.status={protection:'server_readable',type:'enum',values:['OPEN','DONE']};
  readableWorkflow.protection.fields.parent={protection:'server_readable',type:'optional_reference'};
  cases.push({name:'workflow_readable_valid',manifest:{...clone(),record_schemas:{task:readableWorkflow}}});
  const partialWorkflow=structuredClone(readableWorkflow);partialWorkflow.protection.fields.parent={protection:'e2ee',type:'json'};
  cases.push({name:'workflow_partial_disclosure',manifest:{...clone(),record_schemas:{task:partialWorkflow}}});
  const duplicateTransition=structuredClone(workflowSchema);duplicateTransition.workflow.transitions.push(duplicateTransition.workflow.transitions[0]);
  cases.push({name:'workflow_duplicate_transition',manifest:{...clone(),record_schemas:{task:duplicateTransition}}});
  const reorderedTransition=structuredClone(workflowSchema);
  reorderedTransition.workflow.transitions.push({to:'OPEN',from:null,action:'task.create'});
  cases.push({name:'workflow_semantic_duplicate_different_key_order',manifest:{...clone(),record_schemas:{task:reorderedTransition}}});
  const requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,
    ports:[{import_path:['library'],action_id:'task.create',variant:0,input_name:'parent',type:'exact_ref',required:true,bound:false}]};
  cases.push({name:'requirements_valid',manifest:{...clone(),execution_requirements:requirements}});
  cases.push({name:'requirements_unsafe_variant',manifest:{...clone(),execution_requirements:{...requirements,ports:[{...requirements.ports[0],variant:32}]}}});
  const refGuard={op:'exact_ref_list',source:'state',path:['refs'],scope:'INSTANCE',max:32};
  const guardedAction={id:'inspect',reads:[['refs']],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[refGuard],effects:[]}]};
  cases.push({name:'json_array_exact_ref_guard',manifest:{...clone(),format_version:2,state_array_types:[{path:['refs'],kind:'json'}],initial_state:{refs:[]},actions:[guardedAction]}});
  cases.push({name:'ref_array_exact_ref_guard',manifest:{...clone(),format_version:2,state_array_types:[{path:['refs'],kind:'exact_ref_list'}],initial_state:{refs:[]},actions:[guardedAction]}});
  const astral='\u{10000}',bmp='\uE000';
  const arrayOrder={...clone(),format_version:2,initial_state:{[astral]:[],[bmp]:[]},
    state_array_types:[{path:[astral],kind:'json'},{path:[bmp],kind:'json'}]};
  cases.push({name:'state_array_utf16_sort_valid',manifest:arrayOrder});
  cases.push({name:'state_array_utf16_sort_reversed',manifest:{...arrayOrder,state_array_types:arrayOrder.state_array_types.toReversed()}});
  for(const item of cases){
    try{const result=manifestCanonical(item.manifest);item.result=result.canonical;}
    catch(error){item.error=error.code??error.name??error.message;}
  }
  await writeFile(new URL('manifest-vectors.json',import.meta.url),JSON.stringify(cases,null,2)+'\n');
}finally{await rm(dir,{recursive:true,force:true});}
