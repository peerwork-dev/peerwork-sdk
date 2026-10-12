// Direct, deterministic tracked TypeScript secure-engine oracle cases.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
import {createHash} from 'node:crypto';

const source = process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'peerwork-secure-engine-vectors-'));
try {
  const output = join(dir, 'secure-engine.mjs');
  await build({entryPoints:[resolve(source, 'workspace-secure-engine.ts')], outfile:output,
    bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {prepareSecureAction, validateSecureOperation} = await import(pathToFileURL(output));
  const workspaceId = 'W'.repeat(43);
  const context = {v:1, workspace_id:workspaceId, sequence:1, action_id:'test.admin',
    instance_id:null, actor_id:'A'.repeat(43), signing_key:'K'.repeat(43)};
  const policy = {payload:{v:1, workspace_id:workspaceId, visibility:'PRIVATE', epoch:1}};
  const object = (kind, id, revision, value) => ({kind,id,revision,value,provenance:'AUTHOR_SIGNED'});
  const operation = objects => ({v:1,kind:'ADMIN',input:{},objects});
  const cases = [
    {name:'admin_empty',operation:operation([])},
    {name:'admin_workspace_create',operation:operation([object('workspaces',workspaceId,1,{id:workspaceId,workspace_id:workspaceId})])},
    {name:'admin_workspace_revision_two',operation:operation([object('workspaces',workspaceId,2,{id:workspaceId,workspace_id:workspaceId})])},
    {name:'admin_content_denied',operation:operation([object('records','r',1,{workspace_id:workspaceId})])},
    {name:'admin_cross_workspace',operation:operation([object('instances','i',1,{workspace_id:'other'})])},
    {name:'admin_prior_revision',prior:[object('instances','i',1,{workspace_id:workspaceId})],operation:operation([object('instances','i',2,{workspace_id:workspaceId})])},
  ];
  for (const item of cases) {
    item.context = context;
    item.policy = policy;
    try {await validateSecureOperation(item.operation,context,policy,item.prior??[]);item.result='ok';}
    catch (error) {item.error=error.code??error.message;}
  }
  const signingKey=Buffer.alloc(32,7).toString('base64url');
  const actorId=createHash('sha256').update('peerwork.identity.v1\0').update(Buffer.alloc(32,7)).digest('base64url');
  const instanceId='I'.repeat(43),digest='d'.repeat(64);
  const actionContext={...context,actor_id:actorId,signing_key:signingKey,instance_id:instanceId,
    action_id:'test.set',issued_at:2,delegation:null};
  const actionPolicy={payload:{...policy.payload,owner_id:actorId,signing_key:signingKey,issued_at:1,
    members:[{actor_id:actorId,certificate:{payload:{signing_key:signingKey}},role:'OWNER',
      scopes:[{instance_id:null,actions:['test.set'],protocol_roles:[],capabilities:[]}]}]}};
  const manifest={record_schemas:{},role_conflicts:[],historical_role_conflicts:[],actions:[{
    id:'test.set',reads:[['count']],writes:[['count']],revisionEffects:{control:true,contentEntities:[]},
    variants:[{when:[{op:'eq',left:{from:'state',path:['count']},right:{from:'literal',value:0}}],
      effects:[{op:'set',path:['count'],value:{from:'literal',value:1}}]}]}]};
  const actionObjects=[
    object('protocols','protocol',1,{digest,resolved_manifest:manifest}),
    object('instances',instanceId,1,{id:instanceId,workspace_id:workspaceId,protocol_digest:digest,
      state:{count:0},revision:1,event_revision:0})];
  const actionBody={};
  const actionResult=await prepareSecureAction({objects:actionObjects,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations:[]});
  for (const item of [
    {name:'action_control_revision',operation:actionResult},
    {name:'action_output_tamper',operation:structuredClone(actionResult),mutate:true},
    {name:'action_stale_revision',operation:structuredClone(actionResult),stale:true},
    {name:'action_actor_key_mismatch',operation:structuredClone(actionResult),badActor:true},
    {name:'action_scope_denied',operation:structuredClone(actionResult),denyScope:true},
    {name:'action_instance_scope_mismatch',operation:structuredClone(actionResult),wrongWorkspace:true},
    {name:'action_protocol_suspended',operation:structuredClone(actionResult),suspended:true},
  ]) {
    if(item.mutate)item.operation.objects[0].value.state.count=99;
    if(item.stale)item.operation.input.expected_instance_revision=0;
    item.context=structuredClone(actionContext);item.policy=structuredClone(actionPolicy);item.prior=structuredClone(actionObjects);
    if(item.badActor)item.context.actor_id='Z'.repeat(43);
    if(item.denyScope)item.policy.payload.members[0].scopes=[];
    if(item.wrongWorkspace)item.prior[1].value.workspace_id='other';
    if(item.suspended)item.prior.push(object('protocol_status','status',1,{digest,state:'SUSPENDED'}));
    try {await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  for(const type of ['active','historical']){
    const item={name:`action_${type}_role_conflict`,operation:structuredClone(actionResult),
      context:actionContext,policy:structuredClone(actionPolicy),prior:structuredClone(actionObjects)};
    item.prior[0].value.resolved_manifest.role_conflicts=type==='active'?[['reviewer','approver']]:[];
    item.prior[0].value.resolved_manifest.historical_role_conflicts=type==='historical'?[['reviewer','approver']]:[];
    item.policy.payload.members[0].scopes[0].protocol_roles=type==='active'?['reviewer','approver']:['approver'];
    if(type==='historical')item.prior.push(object('grants','legacy',1,{instance_id:instanceId,protocol_digest:digest,
      actor_id:actorId,protocol_roles:['reviewer']}));
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const recordManifest=structuredClone(manifest);
  recordManifest.record_schemas={entry:{type:'object',fields:{text:'string'},required:['text'],max_bytes:16384}};
  recordManifest.actions[0].variants[0].effects=[{op:'append',schema:'entry',recordSlot:'created',
    value:{from:'literal',value:{text:'hello'}}}];
  const recordPrior=structuredClone(actionObjects);
  recordPrior[0].value.resolved_manifest=recordManifest;
  const allocations=[{record_id:'R'.repeat(43),entity_id:'E'.repeat(43)}];
  const recordResult=await prepareSecureAction({objects:recordPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  for(const item of [
    {name:'action_append_record',operation:recordResult},
    {name:'action_append_payload_tamper',operation:structuredClone(recordResult),mutate:true},
    {name:'action_append_allocation_missing',operation:structuredClone(recordResult),missingAllocation:true},
    {name:'action_append_allocation_bad_token',operation:structuredClone(recordResult),badAllocation:true},
    {name:'action_append_record_id_collision',operation:structuredClone(recordResult),recordIdCollision:true},
    {name:'action_append_entity_collision',operation:structuredClone(recordResult),entityCollision:true},
  ]){
    if(item.mutate)item.operation.objects[0].value.payload.text='changed';
    if(item.missingAllocation)item.operation.input.allocations=[];
    if(item.badAllocation)item.operation.input.allocations[0].record_id='*'.repeat(43);
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(recordPrior);
    if(item.recordIdCollision)item.prior.push(object('records','R'.repeat(43),1,{entity_id:'X'.repeat(43)}));
    if(item.entityCollision)item.prior.push(object('records','P'.repeat(43),1,{entity_id:'E'.repeat(43)}));
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const protectedManifest=structuredClone(recordManifest);
  protectedManifest.record_schemas.entry={type:'object',fields:{text:'string',parent:'json',
    assignee:'string',status:'string',count:'integer',tokens:'json'},
    required:['text','parent','assignee','status','count','tokens'],max_bytes:16384,protection:{v:1,fields:{
      text:{protection:'e2ee',type:'string'},
      parent:{protection:'server_readable',type:'optional_reference'},
      assignee:{protection:'server_readable',type:'actor'},
      status:{protection:'server_readable',type:'enum',values:['OPEN','DONE']},
      count:{protection:'server_readable',type:'counter'},
      tokens:{protection:'server_readable',type:'tokens'}}}};
  protectedManifest.actions[0].variants[0].effects[0].value={from:'literal',
    value:{text:'hello',parent:null,assignee:actorId,status:'OPEN',count:1,tokens:[actorId]}};
  const protectedPrior=structuredClone(recordPrior);
  protectedPrior[0].value.resolved_manifest=protectedManifest;
  const protectedResult=await prepareSecureAction({objects:protectedPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  for(const item of [
    {name:'action_protected_readable_optional_reference',operation:structuredClone(protectedResult)},
    {name:'action_protected_readable_bad_reference',operation:structuredClone(protectedResult),bad:true},
    {name:'action_protected_readable_bad_actor',operation:structuredClone(protectedResult),badActor:true},
    {name:'action_protected_readable_bad_enum',operation:structuredClone(protectedResult),badEnum:true},
    {name:'action_protected_readable_bad_counter',operation:structuredClone(protectedResult),badCounter:true},
    {name:'action_protected_readable_duplicate_tokens',operation:structuredClone(protectedResult),duplicateTokens:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(protectedPrior);
    if(item.bad)item.operation.objects[0].value.payload.parent={record_id:'X'.repeat(43),revision:0};
    if(item.badActor)item.operation.objects[0].value.payload.assignee='bad';
    if(item.badEnum)item.operation.objects[0].value.payload.status='UNKNOWN';
    if(item.badCounter)item.operation.objects[0].value.payload.count=-1;
    if(item.duplicateTokens)item.operation.objects[0].value.payload.tokens=[actorId,actorId];
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const slotManifest=structuredClone(recordManifest);
  slotManifest.actions[0].variants[0].effects[0].entitySlot='shared';
  slotManifest.actions[0].revisionEffects.contentEntities=['shared'];
  const slotPrior=structuredClone(recordPrior);slotPrior[0].value.resolved_manifest=slotManifest;
  const slotEntityId=createHash('sha256').update(instanceId+'\0shared').digest('base64url');
  const slotResult=await prepareSecureAction({objects:slotPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  const slotOld=object('records','O'.repeat(43),1,{id:'O'.repeat(43),workspace_id:workspaceId,
    instance_id:instanceId,protocol_digest:digest,entity_id:slotEntityId,schema_ref:'entry',
    payload:{text:'old'},revision:1});
  const slotPriorRevised=[...structuredClone(slotPrior),slotOld];
  const slotRef=[{record_id:slotOld.id,revision:1}];
  const slotRevised=await prepareSecureAction({objects:slotPriorRevised,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:slotRef,allocations});
  for(const item of [
    {name:'action_entity_slot_new',operation:slotResult,prior:structuredClone(slotPrior)},
    {name:'action_entity_slot_revision',operation:slotRevised,prior:structuredClone(slotPriorRevised)},
    {name:'action_entity_slot_stale',operation:structuredClone(slotRevised),prior:structuredClone(slotPriorRevised),stale:true},
  ]){
    if(item.stale)item.operation.input.exact_input_refs=[];
    item.context=actionContext;item.policy=actionPolicy;
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const rawSlot=String.fromCharCode(0xd800);
  const surrogateSlotManifest=structuredClone(slotManifest);
  surrogateSlotManifest.actions[0].variants[0].effects[0].entitySlot=rawSlot;
  surrogateSlotManifest.actions[0].revisionEffects.contentEntities=[rawSlot];
  const surrogateSlotPrior=structuredClone(slotPrior);
  surrogateSlotPrior[0].value.resolved_manifest=surrogateSlotManifest;
  const surrogateSlotResult=await prepareSecureAction({objects:surrogateSlotPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  const surrogateSlotCase={name:'action_entity_slot_lone_surrogate',operation:surrogateSlotResult,
    context:actionContext,policy:actionPolicy,prior:surrogateSlotPrior};
  try{await validateSecureOperation(surrogateSlotResult,actionContext,actionPolicy,surrogateSlotPrior);surrogateSlotCase.result='ok';}
  catch(error){surrogateSlotCase.error=error.code??error.message;}
  cases.push(surrogateSlotCase);
  const collisionManifest=structuredClone(recordManifest);
  collisionManifest.actions[0].revisionEffects.contentEntities=['shared','other'];
  const plainAppend={op:'append',schema:'entry',value:{from:'literal',value:{text:'hello'}}};
  const newAppend={...plainAppend,recordSlot:'first',entity:{mode:'new',slot:'other'}};
  const slotAppend={...plainAppend,recordSlot:'second',entitySlot:'shared'};
  collisionManifest.actions[0].variants[0].effects=[newAppend,slotAppend];
  const collisionPrior=structuredClone(recordPrior);collisionPrior[0].value.resolved_manifest=collisionManifest;
  const collisionEntity=createHash('sha256').update(instanceId+'\0shared').digest('base64url');
  const collisionAllocations=[{record_id:'B'.repeat(43),entity_id:collisionEntity},
    {record_id:'D'.repeat(43),entity_id:'F'.repeat(43)}];
  const reverseCollision=await prepareSecureAction({objects:collisionPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations:collisionAllocations});
  const reverseCollisionCase={name:'action_entity_slot_after_same_new_entity_permitted',operation:reverseCollision,
    context:actionContext,policy:actionPolicy,prior:structuredClone(collisionPrior)};
  try{await validateSecureOperation(reverseCollision,actionContext,actionPolicy,reverseCollisionCase.prior);reverseCollisionCase.result='ok';}
  catch(error){reverseCollisionCase.error=error.code??error.message;}
  cases.push(reverseCollisionCase);
  const forwardCollisionCase={name:'action_new_entity_after_same_entity_slot_rejected',operation:structuredClone(reverseCollision),
    context:actionContext,policy:actionPolicy,prior:structuredClone(collisionPrior)};
  forwardCollisionCase.prior[0].value.resolved_manifest.actions[0].variants[0].effects=[slotAppend,newAppend];
  forwardCollisionCase.operation.input.allocations[1].entity_id=collisionEntity;
  try{await validateSecureOperation(forwardCollisionCase.operation,actionContext,actionPolicy,forwardCollisionCase.prior);forwardCollisionCase.result='ok';}
  catch(error){forwardCollisionCase.error=error.code??error.message;}
  cases.push(forwardCollisionCase);
  const workflowManifest=structuredClone(recordManifest);
  workflowManifest.record_schemas.entry={type:'object',fields:{status:'string',parent:'json'},
    required:['status','parent'],max_bytes:16384,protection:{v:1,fields:{
      status:{protection:'server_readable',type:'enum',values:['OPEN','DONE']},
      parent:{protection:'server_readable',type:'optional_reference'}}},
    workflow:{v:1,status_field:'status',parent_field:'parent',states:['OPEN','DONE'],
      transitions:[{action:'test.set',from:null,to:'OPEN'},{action:'test.set',from:'OPEN',to:'DONE'}]}};
  workflowManifest.actions[0].revisionEffects.contentEntities=['task'];
  workflowManifest.actions[0].variants[0].effects[0]={op:'append',schema:'entry',
    entity:{mode:'new',slot:'task'},selectHead:true,
    value:{from:'literal',value:{status:'OPEN',parent:null}}};
  const workflowPrior=structuredClone(recordPrior);workflowPrior[0].value.resolved_manifest=workflowManifest;
  const workflowResult=await prepareSecureAction({objects:workflowPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  for(const item of [
    {name:'action_workflow_new_selected_head',operation:structuredClone(workflowResult)},
    {name:'action_workflow_transition_denied',operation:structuredClone(workflowResult),badTransition:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(workflowPrior);
    if(item.badTransition)item.prior[0].value.resolved_manifest.record_schemas.entry.workflow.transitions=[
      {action:'test.set',from:null,to:'DONE'}];
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const workflowReviseManifest=structuredClone(workflowManifest);
  const workflowParentSelector={from:'ref',source:'body',path:['parent'],schema:'entry',scope:'INSTANCE'};
  workflowReviseManifest.actions[0].variants[0].effects[0]={op:'append',schema:'entry',
    entity:{mode:'revise',slot:'task',parent:workflowParentSelector},selectHead:true,
    value:{from:'object',fields:{status:{from:'literal',value:'DONE'},parent:workflowParentSelector}}};
  const workflowRevisePrior=structuredClone(workflowPrior);
  workflowRevisePrior[0].value.resolved_manifest=workflowReviseManifest;
  workflowRevisePrior.push(structuredClone(workflowResult.objects[0]),structuredClone(workflowResult.objects[1]));
  const workflowParent={record_id:allocations[0].record_id,revision:1};
  const workflowRevise=await prepareSecureAction({objects:workflowRevisePrior,context:actionContext,
    policy:actionPolicy,body:{parent:workflowParent},exactRefs:[workflowParent],
    allocations:[{record_id:'N'.repeat(43),entity_id:'F'.repeat(43)}]});
  for(const item of [
    {name:'action_workflow_revision_selected_head',operation:structuredClone(workflowRevise)},
    {name:'action_workflow_revision_stale_head',operation:structuredClone(workflowRevise),stale:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(workflowRevisePrior);
    if(item.stale)item.prior[3].value.record_id='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const dependencyManifest=structuredClone(workflowManifest);
  dependencyManifest.record_schemas.entry.fields.depends='json';
  dependencyManifest.record_schemas.entry.required.push('depends');
  dependencyManifest.record_schemas.entry.protection.fields.depends={protection:'server_readable',type:'references'};
  dependencyManifest.record_schemas.entry.workflow.dependencies={field:'depends',
    satisfied_states:['DONE'],gated_states:['OPEN']};
  const anchorId='Q'.repeat(43),anchorEntity='Y'.repeat(43);
  const anchorRef={record_id:anchorId,revision:1};
  dependencyManifest.actions[0].variants[0].effects[0].value={from:'literal',
    value:{status:'OPEN',parent:null,depends:[anchorRef]}};
  const dependencyPrior=structuredClone(recordPrior);
  dependencyPrior[0].value.resolved_manifest=dependencyManifest;
  dependencyPrior.push(object('records',anchorId,1,{id:anchorId,workspace_id:workspaceId,
    instance_id:instanceId,protocol_digest:digest,entity_id:anchorEntity,schema_ref:'entry',
    payload:{status:'DONE',parent:null,depends:[]},actor_id:actorId,revision:1,created:1}));
  dependencyPrior.push(object('entity_heads',anchorEntity,1,{entity_id:anchorEntity,
    workspace_id:workspaceId,instance_id:instanceId,record_id:anchorId,revision:1,updated:1}));
  const dependencyResult=await prepareSecureAction({objects:dependencyPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  for(const item of [
    {name:'action_workflow_dependency_satisfied',operation:structuredClone(dependencyResult)},
    {name:'action_workflow_dependency_unsatisfied',operation:structuredClone(dependencyResult),unsatisfied:true},
    {name:'action_workflow_dependency_cycle',operation:structuredClone(dependencyResult),cycle:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(dependencyPrior);
    if(item.unsatisfied)item.prior[2].value.payload.status='OPEN';
    if(item.cycle)item.prior[2].value.payload.depends=[{record_id:allocations[0].record_id,revision:1}];
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const headManifest=structuredClone(recordManifest);
  headManifest.actions[0].revisionEffects.contentEntities=['entry'];
  headManifest.actions[0].variants[0].effects[0].entity={mode:'new',slot:'entry'};
  headManifest.actions[0].variants[0].effects[0].selectHead=true;
  const headPrior=structuredClone(recordPrior);headPrior[0].value.resolved_manifest=headManifest;
  const headResult=await prepareSecureAction({objects:headPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations});
  for(const item of [
    {name:'action_new_entity_head',operation:headResult},
    {name:'action_new_entity_head_tamper',operation:structuredClone(headResult),mutate:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(headPrior);
    if(item.mutate)item.operation.objects[1].value.record_id='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const reviseManifest=structuredClone(headManifest);
  reviseManifest.actions[0].variants[0].effects[0].entity={mode:'revise',slot:'entry',
    parent:{from:'ref',source:'body',path:['parent'],schema:'entry',scope:'INSTANCE'}};
  const revisePrior=structuredClone(headPrior);
  revisePrior[0].value.resolved_manifest=reviseManifest;
  revisePrior.push(structuredClone(headResult.objects[0]),structuredClone(headResult.objects[1]));
  const reviseAllocations=[{record_id:'N'.repeat(43),entity_id:'F'.repeat(43)}];
  const reviseBody={parent:{record_id:allocations[0].record_id,revision:1}};
  const reviseRefs=[reviseBody.parent];
  const reviseResult=await prepareSecureAction({objects:revisePrior,context:actionContext,
    policy:actionPolicy,body:reviseBody,exactRefs:reviseRefs,allocations:reviseAllocations});
  for(const item of [
    {name:'action_revise_entity_head',operation:reviseResult},
    {name:'action_revise_entity_stale_head',operation:structuredClone(reviseResult),stale:true},
    {name:'action_revise_entity_wrong_parent_scope',operation:structuredClone(reviseResult),wrongScope:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(revisePrior);
    if(item.stale)item.prior[3].value.record_id='X'.repeat(43);
    if(item.wrongScope)item.prior[2].value.instance_id='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const selectionManifest=structuredClone(manifest);
  const selectionRef=path=>({from:'ref',source:'body',path:[path],schema:'entry',scope:'INSTANCE'});
  selectionManifest.actions[0].variants[0].effects=[{op:'select_head',expected:selectionRef('expected'),target:selectionRef('target')}];
  const selectionPrior=structuredClone(actionObjects);
  selectionPrior[0].value.resolved_manifest=selectionManifest;
  selectionPrior.push(structuredClone(headResult.objects[0]),structuredClone(reviseResult.objects[0]),structuredClone(headResult.objects[1]));
  const selectionBody={expected:{record_id:allocations[0].record_id,revision:1},
    target:{record_id:reviseAllocations[0].record_id,revision:2}};
  const selectionRefs=[selectionBody.expected,selectionBody.target];
  const selectionResult=await prepareSecureAction({objects:selectionPrior,context:actionContext,
    policy:actionPolicy,body:selectionBody,exactRefs:selectionRefs,allocations:[]});
  for(const item of [
    {name:'action_explicit_head_selection',operation:selectionResult},
    {name:'action_explicit_head_wrong_entity',operation:structuredClone(selectionResult),wrongEntity:true},
    {name:'action_explicit_head_stale',operation:structuredClone(selectionResult),stale:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(selectionPrior);
    if(item.wrongEntity)item.prior[3].value.entity_id='F'.repeat(43);
    if(item.stale)item.prior[4].value.record_id='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const relationManifest=structuredClone(recordManifest);
  relationManifest.actions[0].variants[0].effects[0].relations=[{kind:'links',
    target:{from:'ref',source:'body',path:['target'],schema:'entry',scope:'INSTANCE'}}];
  const relationPrior=structuredClone(recordPrior);relationPrior[0].value.resolved_manifest=relationManifest;
  relationPrior.push(object('records','Q'.repeat(43),1,{id:'Q'.repeat(43),workspace_id:workspaceId,
    instance_id:instanceId,protocol_digest:digest,entity_id:'Y'.repeat(43),schema_ref:'entry',
    payload:{text:'target'},revision:1}));
  const relationBody={target:{record_id:'Q'.repeat(43),revision:1}};
  const relationResult=await prepareSecureAction({objects:relationPrior,context:actionContext,
    policy:actionPolicy,body:relationBody,exactRefs:[relationBody.target],allocations});
  for(const item of [
    {name:'action_existing_record_relation',operation:relationResult},
    {name:'action_existing_record_relation_tamper',operation:structuredClone(relationResult),mutate:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(relationPrior);
    if(item.mutate)item.operation.objects[1].value.target_record='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const producedManifest=structuredClone(recordManifest);
  producedManifest.record_schemas.entry.fields.peer='json';
  producedManifest.actions[0].writes=[['linked']];
  producedManifest.actions[0].revisionEffects.contentEntities=['buddy'];
  producedManifest.actions[0].variants[0].effects=[
    {op:'set',path:['linked'],value:{from:'produced_entity',slot:'buddy'}},
    {op:'append',schema:'entry',recordSlot:'first',value:{from:'object',fields:{
      text:{from:'literal',value:'first'},peer:{from:'produced_ref',slot:'later'}}},
      relations:[{kind:'links',target:{from:'produced_ref',slot:'later'}}]},
    {op:'append',schema:'entry',recordSlot:'later',entitySlot:'buddy',
      value:{from:'literal',value:{text:'later'}}},
  ];
  const producedPrior=structuredClone(recordPrior);
  producedPrior[0].value.resolved_manifest=producedManifest;
  const producedAllocations=[
    {record_id:'B'.repeat(43),entity_id:'C'.repeat(43)},
    {record_id:'D'.repeat(43),entity_id:'F'.repeat(43)},
  ];
  const producedResult=await prepareSecureAction({objects:producedPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations:producedAllocations});
  for(const item of [
    {name:'action_forward_produced_ref_relation_entity',operation:structuredClone(producedResult)},
    {name:'action_forward_produced_ref_payload_tamper',operation:structuredClone(producedResult),mutatePayload:true},
    {name:'action_forward_produced_ref_relation_tamper',operation:structuredClone(producedResult),mutateRelation:true},
    {name:'action_forward_produced_entity_state_tamper',operation:structuredClone(producedResult),mutateState:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(producedPrior);
    if(item.mutatePayload)item.operation.objects.find(o=>o.kind==='records').value.payload.peer.record_id='X'.repeat(43);
    if(item.mutateRelation)item.operation.objects.find(o=>o.kind==='record_relations').value.target_record='X'.repeat(43);
    if(item.mutateState)item.operation.objects.at(-1).value.state.linked='X'.repeat(43);
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const referenceId='Q'.repeat(43);
  const referenceManifest=structuredClone(manifest);
  const selector={from:'ref',source:'body',path:['ref'],schema:'entry',scope:'INSTANCE'};
  referenceManifest.actions[0].variants=[{when:[{op:'exact_ref',ref:selector}],effects:[
    {op:'set',path:['count'],value:{from:'resolved_payload',ref:selector,path:['value']}}]}];
  const referencePrior=structuredClone(actionObjects);
  referencePrior[0].value.resolved_manifest=referenceManifest;
  referencePrior.push(object('records',referenceId,1,{id:referenceId,workspace_id:workspaceId,
    instance_id:instanceId,protocol_digest:digest,entity_id:'E'.repeat(43),schema_ref:'entry',
    payload:{value:42},revision:1}));
  const referenceBody={ref:{record_id:referenceId,revision:1}};
  const referenceRefs=[{record_id:referenceId,revision:1}];
  const referenceResult=await prepareSecureAction({objects:referencePrior,context:actionContext,
    policy:actionPolicy,body:referenceBody,exactRefs:referenceRefs,allocations:[]});
  for(const item of [
    {name:'action_exact_ref_payload',operation:referenceResult},
    {name:'action_exact_ref_wrong_scope',operation:structuredClone(referenceResult),wrongScope:true},
    {name:'action_exact_ref_missing',operation:structuredClone(referenceResult),missingRef:true},
  ]){
    item.context=actionContext;item.policy=actionPolicy;item.prior=structuredClone(referencePrior);
    if(item.wrongScope)item.prior[2].value.instance_id=null;
    if(item.missingRef)item.operation.input.exact_input_refs=[];
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  const surrogatePrior=structuredClone(referencePrior);
  surrogatePrior[2].value.payload='{"value":"'+String.fromCharCode(0xd800)+'"}';
  const surrogateResult=await prepareSecureAction({objects:surrogatePrior,context:actionContext,
    policy:actionPolicy,body:referenceBody,exactRefs:referenceRefs,allocations:[]});
  const surrogateCase={name:'action_raw_utf16_json_string_payload',operation:surrogateResult,
    context:actionContext,policy:actionPolicy,prior:surrogatePrior};
  try{await validateSecureOperation(surrogateResult,actionContext,actionPolicy,surrogatePrior);surrogateCase.result='ok';}
  catch(error){surrogateCase.error=error.code??error.message;}
  cases.push(surrogateCase);
  const arrayPrior=structuredClone(actionObjects);
  arrayPrior[0].value.resolved_manifest={...structuredClone(manifest),format_version:2,
    state_array_types:[{path:['refs'],kind:'exact_ref_list'}]};
  arrayPrior[1].value.state={count:0,refs:[]};
  const arrayResult=await prepareSecureAction({objects:arrayPrior,context:actionContext,
    policy:actionPolicy,body:actionBody,exactRefs:[],allocations:[]});
  for(const item of [
    {name:'action_state_array_valid',prior:structuredClone(arrayPrior)},
    {name:'action_state_array_invalid_source',prior:structuredClone(arrayPrior),invalid:true},
  ]){
    item.operation=structuredClone(arrayResult);item.context=actionContext;item.policy=actionPolicy;
    if(item.invalid)item.prior[1].value.state.refs=[{record_id:'*',revision:1}];
    try{await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
    catch(error){item.error=error.code??error.message;}
    cases.push(item);
  }
  await writeFile(new URL('secure-engine-vectors.json', import.meta.url),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
