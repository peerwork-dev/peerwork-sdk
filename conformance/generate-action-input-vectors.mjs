// Direct pinned TypeScript prepareSecureAction acceptance around exact refs.
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const vectors=JSON.parse(await readFile(join(root,'secure-engine-vectors.json'),'utf8'));
const original=name=>structuredClone(vectors.find(row=>row.name===name));
const temp=await mkdtemp(join(tmpdir(),'peerwork-action-input-'));
try {
  const output=join(temp,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-secure-engine.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {prepareSecureAction}=await import(pathToFileURL(output));
  const base=original('action_exact_ref_payload');
  const control=original('action_control_revision');
  const refs=base.operation.input.exact_input_refs;
  const missing={record_id:'M'.repeat(43),revision:1};
  const workspace=structuredClone(control);
  const row=structuredClone(base.prior.find(value=>value.kind==='records'));
  row.value.instance_id='Z'.repeat(43);
  row.value.protocol_digest='f'.repeat(64);
  workspace.prior.push(row);
  const cases=[
    ['instance_reference',base,refs],
    ['workspace_reference',workspace,refs],
    ['raw_utf16_payload',original('action_raw_utf16_json_string_payload'),refs],
    ['duplicate_reference',base,[...refs,...refs]],
    ['too_many_references',base,Array.from({length:33},(_,index)=>
      ({record_id:String(index).padStart(43,'M'),revision:1}))],
    ['missing_reference',base,[missing]],
    ['wrong_revision',base,[{...refs[0],revision:2}]],
    ['malformed_record_id',base,[{record_id:null,revision:1}]],
    ['malformed_revision',base,[{...refs[0],revision:'1'}]],
    ['cross_workspace',(()=>{const c=structuredClone(base);c.prior.find(o=>o.kind==='records').value.workspace_id='X'.repeat(43);return c;})(),refs],
    ['participation_request',(()=>{const c=structuredClone(base);c.prior.find(o=>o.kind==='records').value.schema_ref='participation.request';return c;})(),refs],
  ];
  const outputRows=[];
  for(const [name,fixture,exactRefs] of cases){
    const row={name,refs:exactRefs,prior_objects:fixture.prior,
      workspace_id:fixture.context.workspace_id,
      instance_id:fixture.context.instance_id,
      protocol_digest:fixture.prior.find(o=>o.kind==='instances').value.protocol_digest};
    try {
      await prepareSecureAction({objects:fixture.prior,context:fixture.context,
        policy:fixture.policy,body:fixture.operation.input.body,exactRefs,
        allocations:fixture.operation.input.allocations});
      row.result=exactRefs.map(ref=>{
        const record=fixture.prior.find(o=>o.kind==='records'&&o.id===ref.record_id&&o.value.revision===ref.revision).value;
        return {record_id:ref.record_id,revision:ref.revision,schema:record.schema_ref,
          payload:typeof record.payload==='string'?JSON.parse(record.payload):record.payload,
          entity_id:record.entity_id,scope:record.instance_id===row.instance_id&&
          record.protocol_digest===row.protocol_digest?'INSTANCE':'WORKSPACE'};
      });
    } catch(error){row.error=error.code??error.message;}
    outputRows.push(row);
  }
  await writeFile(join(root,'action-input-vectors.json'),JSON.stringify(outputRows,null,2)+'\n');
} finally {await rm(temp,{recursive:true,force:true});}
