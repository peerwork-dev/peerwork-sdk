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
  ]) {
    if(item.mutate)item.operation.objects[0].value.state.count=99;
    if(item.stale)item.operation.input.expected_instance_revision=0;
    item.context=structuredClone(actionContext);item.policy=structuredClone(actionPolicy);item.prior=structuredClone(actionObjects);
    if(item.badActor)item.context.actor_id='Z'.repeat(43);
    if(item.denyScope)item.policy.payload.members[0].scopes=[];
    if(item.wrongWorkspace)item.prior[1].value.workspace_id='other';
    try {await validateSecureOperation(item.operation,item.context,item.policy,item.prior);item.result='ok';}
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
  await writeFile(new URL('secure-engine-vectors.json', import.meta.url),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
