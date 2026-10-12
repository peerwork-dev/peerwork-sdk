// Direct state-transition outcomes from the vendored TypeScript structure engine.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-structure-delta-'));
try {
  const source=resolve(fileURLToPath(new URL('reference/src/',import.meta.url)));
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {applyStructureDelta,validateStructurePolicy} from '${source}/workspace-structure.ts';
    export {validateWorkflowGraph} from '${source}/workspace-workflow.ts';`,resolveDir:source,sourcefile:'oracle.ts'},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {applyStructureDelta,validateStructurePolicy,validateWorkflowGraph}=await import(pathToFileURL(output));
  const actor='a'.repeat(43),instance='i'.repeat(43),recordId='r'.repeat(43),entity='e'.repeat(43),digest='d'.repeat(64);
  const rule={schemas:['discussion.message'],roles:['AUTHOR'],capabilities:[],heads:'APPEND'};
  const contract={v:1,protocols:[{v:1,protocol_digest:digest,schemas:{'discussion.message':{
    fields:{author:{protection:'server_readable',type:'actor'},parent:{protection:'server_readable',type:'optional_reference'}},required:['author']
  }},actions:{'discussion.post':rule}}],disclosure:[{protocol_digest:digest,schema:'discussion.message',fields:['author','parent']}],
    instances:[{instance_id:instance,protocol_digest:digest}]};
  const scope={instance_id:instance,actions:['discussion.post'],protocol_roles:['AUTHOR'],capabilities:[],expires_at:10};
  const policy={payload:{members:[{actor_id:actor,scopes:[scope]}]}};
  const context={actor_id:actor,action_id:'discussion.post',instance_id:instance,issued_at:5,delegation:null};
  const record={record_id:recordId,entity_id:entity,revision:1,instance_id:instance,protocol_digest:digest,
    schema_ref:'discussion.message',actor_id:actor,created:5,fields:{author:actor,parent:null}};
  const head={entity_id:entity,record_id:recordId,revision:1,instance_id:instance};
  const clone=value=>structuredClone(value);
  const cases=[
    ['append_head',contract,policy,context,[record],[head]],
    ['missing_role',contract,{payload:{members:[{actor_id:actor,scopes:[{...scope,protocol_roles:[]}]}]}},context,[record],[head]],
    ['expired_role',contract,{payload:{members:[{actor_id:actor,scopes:[{...scope,expires_at:5}]}]}},context,[record],[head]],
    ['forward_reference',contract,policy,context,[{...record,fields:{...record.fields,parent:{record_id:'z'.repeat(43),revision:1}}}],[head]],
    ['wrong_actor',contract,policy,context,[{...record,actor_id:'z'.repeat(43)}],[head]],
    ['head_without_append',contract,policy,context,[],[head]],
    ['delegated_scope_missing',contract,policy,{...context,delegation:{payload:{actor_id:actor,scope:[{...scope,protocol_roles:[]}]}}},[record],[head]],
    ['delegated_scope_matching',contract,policy,{...context,delegation:{payload:{actor_id:actor,scope:[scope]}}},[record],[head]],
  ];
  const result=[];
  const workflow={v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
    transitions:[{action:'task.create',from:null,to:'OPEN'},{action:'task.finish',from:'OPEN',to:'DONE'}]};
  const taskContract={v:1,protocols:[{v:1,protocol_digest:digest,schemas:{'task.item':{fields:{
    status:{protection:'server_readable',type:'enum',values:['OPEN','DONE']},
    parent:{protection:'server_readable',type:'optional_reference'},author:{protection:'server_readable',type:'actor'}
  },required:['status','parent','author'],workflow}},actions:{
    'task.create':{schemas:['task.item'],roles:[],capabilities:[],heads:'APPEND'},
    'task.finish':{schemas:['task.item'],roles:[],capabilities:[],heads:'APPEND'}
  }}],disclosure:[{protocol_digest:digest,schema:'task.item',fields:['status','parent','author']}],
    instances:[{instance_id:instance,protocol_digest:digest}]};
  const taskRecord={...record,schema_ref:'task.item',fields:{status:'OPEN',parent:null,author:actor}};
  const taskNext={...taskRecord,record_id:'s'.repeat(43),revision:2,created:6,
    fields:{status:'DONE',parent:{record_id:recordId,revision:1},author:actor}};
  const taskNextHead={...head,record_id:taskNext.record_id,revision:2};
  const taskContext={...context,action_id:'task.finish',issued_at:6};
  cases.push(
    ['workflow_create',taskContract,policy,{...context,action_id:'task.create'},[taskRecord],[head]],
    ['workflow_finish',taskContract,policy,taskContext,[taskNext],[taskNextHead],[taskRecord],[head]],
    ['workflow_missing_new_head',taskContract,policy,taskContext,[taskNext],[],[taskRecord],[head]],
    ['workflow_wrong_transition',taskContract,policy,taskContext,[{...taskNext,fields:{...taskNext.fields,status:'OPEN'}}],[taskNextHead],[taskRecord],[head]],
  );
  const taskStatusContract={v:1,protocols:[{v:1,protocol_digest:digest,schemas:{'task.revision':{
    fields:{status:{protection:'server_readable',type:'task_status'},parent:{protection:'server_readable',type:'optional_reference'}},required:['status']
  }},actions:{'task.create':{schemas:['task.revision'],roles:[],capabilities:[],heads:'APPEND',task_transition:[{from:null,to:'OPEN'}]}}}],
    disclosure:[{protocol_digest:digest,schema:'task.revision',fields:['status','parent']}],
    instances:[{instance_id:instance,protocol_digest:digest}]};
  cases.push(['task_initial_parent_omitted',taskStatusContract,policy,{...context,action_id:'task.create'},
    [{...record,schema_ref:'task.revision',fields:{status:'OPEN'}}],[head]]);
  const dependencyWorkflow={v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
    transitions:[{action:'task.create',from:null,to:'OPEN'},{action:'task.create',from:null,to:'DONE'}],
    dependencies:{field:'depends',satisfied_states:['DONE'],gated_states:['OPEN']}};
  const dependencyContract={v:1,protocols:[{v:1,protocol_digest:digest,schemas:{'task.dep':{fields:{
    status:{protection:'server_readable',type:'enum',values:['OPEN','DONE']},
    parent:{protection:'server_readable',type:'optional_reference'},
    depends:{protection:'server_readable',type:'references'}
  },required:['status','parent','depends'],workflow:dependencyWorkflow}},actions:{
    'task.create':{schemas:['task.dep'],roles:[],capabilities:[],heads:'APPEND'}
  }}],disclosure:[{protocol_digest:digest,schema:'task.dep',fields:['status','parent','depends']}],
    instances:[{instance_id:instance,protocol_digest:digest}]};
  const dependencyOld={...record,schema_ref:'task.dep',fields:{status:'DONE',parent:null,depends:[]}};
  const dependencyNew={...record,record_id:'s'.repeat(43),entity_id:'f'.repeat(43),schema_ref:'task.dep',
    fields:{status:'OPEN',parent:null,depends:[{record_id:recordId,revision:1}]}};
  const dependencyHead={...head,record_id:dependencyNew.record_id,entity_id:dependencyNew.entity_id};
  cases.push(
    ['workflow_dependency_satisfied',dependencyContract,policy,{...context,action_id:'task.create'},[dependencyNew],[dependencyHead],[dependencyOld],[head]],
    ['workflow_dependency_unsatisfied',dependencyContract,policy,{...context,action_id:'task.create'},[dependencyNew],[dependencyHead],
      [{...dependencyOld,fields:{...dependencyOld.fields,status:'OPEN'}}],[head]],
  );
  for(const [name,contract,policy,context,records,heads,priorRecords=[],priorHeads=[]] of cases){
    const envelope={v:1,mode:'DELTA',records,heads};
    const state={records:new Map(priorRecords.map(row=>[row.record_id,row])),heads:new Map(priorHeads.map(row=>[row.entity_id,row]))};
    try{validateStructurePolicy(contract);applyStructureDelta(envelope,contract,state,context,policy);
      result.push({name,contract,policy,context,records,heads,priorRecords,priorHeads,ok:true});}
    catch(error){result.push({name,contract,policy,context,records,heads,priorRecords,priorHeads,ok:false,error:error.message});}
  }
  const graphCases=[
    ['snapshot_workflow_dag',[dependencyOld,dependencyNew],[head,dependencyHead]],
    ['snapshot_workflow_cycle',[
      {...dependencyOld,fields:{status:'DONE',parent:null,depends:[{record_id:dependencyNew.record_id,revision:1}]}},
      {...dependencyNew,fields:{status:'DONE',parent:null,depends:[{record_id:recordId,revision:1}]}}
    ],[head,dependencyHead]],
  ];
  for(const [name,records,heads] of graphCases){
    try{validateWorkflowGraph(dependencyWorkflow,'task.dep',instance,digest,
      new Map(records.map(row=>[row.record_id,row])),new Map(heads.map(row=>[row.entity_id,row])));
      result.push({name,contract:dependencyContract,records,heads,kind:'snapshot_graph',ok:true});}
    catch(error){result.push({name,contract:dependencyContract,records,heads,kind:'snapshot_graph',ok:false,error:error.message});}
  }
  await writeFile(new URL('structure-delta-vectors.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
