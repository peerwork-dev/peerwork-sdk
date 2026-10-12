// Direct pinned TypeScript secure ACTION relation objects. The native module
// receives already-interpreted relation specs and authenticated prior rows.
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const existing=JSON.parse(await readFile(join(root,'secure-engine-vectors.json'),'utf8'));
const caseNamed=name=>structuredClone(existing.find(row=>row.name===name));
const base=caseNamed('action_existing_record_relation');
const forward=caseNamed('action_forward_produced_ref_relation_entity');
const relation=operation=>operation.objects.find(object=>object.kind==='record_relations');
const existingRef=base.operation.input.body.target;
const temp=await mkdtemp(join(tmpdir(),'peerwork-action-relations-'));
try {
  const output=join(temp,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-secure-engine.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {prepareSecureAction}=await import(pathToFileURL(output));
  const repeated=structuredClone(base);
  repeated.prior.push(relation(base.operation));
  const repeatedResult=await prepareSecureAction({objects:repeated.prior,context:repeated.context,
    policy:repeated.policy,body:repeated.operation.input.body,
    exactRefs:repeated.operation.input.exact_input_refs,
    allocations:repeated.operation.input.allocations});
  const unicode=structuredClone(base);
  unicode.prior[0].value.resolved_manifest.actions[0].variants[0].effects[0].relations[0].kind='é😀';
  const unicodeResult=await prepareSecureAction({objects:unicode.prior,context:unicode.context,
    policy:unicode.policy,body:unicode.operation.input.body,
    exactRefs:unicode.operation.input.exact_input_refs,
    allocations:unicode.operation.input.allocations});
  const rows=[
    {name:'existing_target',prior_objects:base.prior,
      pending:[{position:1,source_id:base.operation.input.allocations[0].record_id,
        relation:{kind:'links',target:{recordId:existingRef.record_id,revision:existingRef.revision}}}],
      record_slots:{},entity_slots:{},assigned_records:
        {[base.operation.input.allocations[0].record_id]:1},
      expected:[{position:1,object:relation(base.operation)}]},
    {name:'forward_produced_target',prior_objects:forward.prior,
      pending:[{position:1,source_id:forward.operation.input.allocations[0].record_id,
        relation:{kind:'links',target:{$produced:'record',slot:'later'}}}],
      record_slots:{later:{record_id:forward.operation.input.allocations[1].record_id,revision:1}},
      entity_slots:{},assigned_records:Object.fromEntries(forward.operation.input.allocations.map(a=>[a.record_id,1])),
      expected:[{position:1,object:relation(forward.operation)}]},
    {name:'prior_relation_revision',prior_objects:repeated.prior,
      pending:[{position:1,source_id:base.operation.input.allocations[0].record_id,
        relation:{kind:'links',target:{recordId:existingRef.record_id,revision:existingRef.revision}}}],
      record_slots:{},entity_slots:{},assigned_records:
        {[base.operation.input.allocations[0].record_id]:1},
      expected:[{position:1,object:relation(repeatedResult)}]},
    {name:'unicode_relation_kind',prior_objects:unicode.prior,
      pending:[{position:1,source_id:base.operation.input.allocations[0].record_id,
        relation:{kind:'é😀',target:{recordId:existingRef.record_id,revision:existingRef.revision}}}],
      record_slots:{},entity_slots:{},assigned_records:
        {[base.operation.input.allocations[0].record_id]:1},
      expected:[{position:1,object:relation(unicodeResult)}]},
  ];
  await writeFile(join(root,'action-relation-vectors.json'),JSON.stringify(rows,null,2)+'\n');
} finally {await rm(temp,{recursive:true,force:true});}
