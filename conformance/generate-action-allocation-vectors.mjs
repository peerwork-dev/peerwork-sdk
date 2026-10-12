// Direct pinned TypeScript assignment outcomes for the private Rust phase.
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const originals=JSON.parse(await readFile(join(root,'secure-engine-vectors.json'),'utf8'));
const named=name=>structuredClone(originals.find(row=>row.name===name));
const names=[
  'action_append_record','action_append_allocation_missing','action_append_allocation_bad_token',
  'action_append_record_id_collision','action_append_entity_collision',
  'action_entity_slot_new','action_entity_slot_revision','action_entity_slot_stale',
  'action_entity_slot_lone_surrogate','action_entity_slot_after_same_new_entity_permitted',
  'action_new_entity_after_same_entity_slot_rejected','action_new_entity_head',
  'action_revise_entity_head','action_revise_entity_stale_head',
];
const cases=names.map(named);
const headWithoutEntity=named('action_append_record');
headWithoutEntity.name='action_select_head_without_entity';
headWithoutEntity.prior[0].value.resolved_manifest.actions[0].variants[0].effects[0].selectHead=true;
cases.push(headWithoutEntity);
const latest=(objects,kind,id)=>objects.filter(object=>object.kind===kind&&object.id===id)
  .sort((a,b)=>b.revision-a.revision)[0];
const decoded=value=>typeof value==='string'?JSON.parse(value):value;
const temp=await mkdtemp(join(tmpdir(),'peerwork-action-allocations-'));
try {
  const output=join(temp,'oracle.mjs');
  await build({stdin:{contents:`export {prepareSecureAction} from '${resolve(source,'workspace-secure-engine.ts')}';\nexport {evaluateAction} from '${resolve(source,'workspace-interpreter.ts')}';\nexport {resolveSecureAuthor} from '${resolve(source,'workspace-secure-client.ts')}';`,
    resolveDir:source,sourcefile:'oracle.ts'},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {prepareSecureAction,evaluateAction,resolveSecureAuthor}=await import(pathToFileURL(output));
  const vectors=[];
  for(const item of cases){
    const {context,policy,prior}=item, input=item.operation.input;
    const instance=latest(prior,'instances',context.instance_id).value;
    const protocol=prior.find(object=>object.kind==='protocols'&&object.value.digest===instance.protocol_digest).value;
    const manifest=decoded(protocol.resolved_manifest??protocol.manifest);
    const member=await resolveSecureAuthor(context,policy);
    const scopes=member.scopes.filter(scope=>scope.instance_id===null||scope.instance_id===context.instance_id);
    const exactInputs=input.exact_input_refs.map(ref=>{
      const found=prior.find(object=>object.kind==='records'&&object.id===ref.record_id&&object.value.revision===ref.revision).value;
      return {recordId:ref.record_id,revision:ref.revision,schema:String(found.schema_ref),
        payload:decoded(found.payload),entityId:String(found.entity_id),
        scope:found.instance_id===context.instance_id&&found.protocol_digest===instance.protocol_digest?'INSTANCE':'WORKSPACE'};
    });
    const interpreted=evaluateAction({manifest:{actions:manifest.actions},actionId:context.action_id,
      state:decoded(instance.state),body:input.body,
      auth:{actorId:member.actor_id,workspaceRoles:[member.role],
        protocolRoles:[...new Set(scopes.flatMap(scope=>scope.protocol_roles))],
        capabilities:[...new Set(scopes.flatMap(scope=>scope.capabilities))]},exactInputs});
    const row={name:item.name,records:interpreted.records,allocations:input.allocations,
      prior_objects:prior,exact_refs:exactInputs,context,instance_id:context.instance_id,
      protocol_digest:instance.protocol_digest};
    try {
      const operation=await prepareSecureAction({objects:prior,context,policy,body:input.body,
        exactRefs:input.exact_input_refs,allocations:input.allocations});
      const assigned=operation.objects.filter(object=>object.kind==='records').map(object=>({
        id:object.id,entity_id:object.value.entity_id,revision:object.value.revision}));
      const record_slots={},entity_slots={},assigned_records={};
      interpreted.records.forEach((record,index)=>{
        const actual=assigned[index];
        if(record.recordSlot)record_slots[record.recordSlot]={record_id:actual.id,revision:actual.revision};
        if(record.entitySlot)entity_slots[record.entitySlot]=actual.entity_id;
        else if(record.entity?.slot)entity_slots[record.entity.slot]=actual.entity_id;
        assigned_records[actual.id]=actual.revision;
      });
      row.result={assigned,record_slots,entity_slots,assigned_records};
    }catch(error){row.error=error.code??error.message;}
    vectors.push(row);
  }
  await writeFile(join(root,'action-allocation-vectors.json'),JSON.stringify(vectors,null,2)+'\n');
} finally {await rm(temp,{recursive:true,force:true});}
