// Exact source-derived genesis structure policies for native owner-create.
import {mkdtemp, rm, writeFile, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-genesis-structure-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({entryPoints:[resolve('reference/src/workspace-structure.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {structurePolicyFromObjects}=await import(pathToFileURL(output));
  const fixture=JSON.parse(await readFile(new URL('bootstrap-presets.json',import.meta.url),'utf8'));
  const official=JSON.parse(await readFile(new URL('protocol-package-source-vectors.json',import.meta.url),'utf8'))[0].result;
  const rows=(extra=[])=>[...fixture.entries.map((entry,index)=>[
    {kind:'protocols',id:entry.digest,revision:1,provenance:'AUTHOR_SIGNED',
      value:{workspace_id:'w'.repeat(43),digest:entry.digest,
        manifest:entry.manifest,resolved_manifest:entry.manifest}},
    {kind:'instances',id:String.fromCharCode(105+index).repeat(43),revision:1,
      provenance:'AUTHOR_SIGNED',value:{id:String.fromCharCode(105+index).repeat(43),
        workspace_id:'w'.repeat(43),protocol_digest:entry.digest}},
  ]).flat(),...extra];
  const custom=[
    {kind:'protocols',id:official.protocol_digest,revision:1,provenance:'AUTHOR_SIGNED',
      value:{workspace_id:'w'.repeat(43),digest:official.protocol_digest,
        manifest:official.manifest,resolved_manifest:official.manifest}},
    {kind:'instances',id:'z'.repeat(43),revision:1,provenance:'AUTHOR_SIGNED',
      value:{id:'z'.repeat(43),workspace_id:'w'.repeat(43),protocol_digest:official.protocol_digest}},
  ];
  const cases=[{name:'six_presets',objects:rows()},
    {name:'six_presets_plus_public_proposal_package',objects:rows(custom)},
    {name:'six_presets_keep_author_encrypted',objects:rows(),
      keep_encrypted:[{schema:'discussion.message',fields:['author'],
        protocol_digest:fixture.entries[0].digest}]}];
  for(const item of cases){item.objects_wire=JSON.stringify(item.objects);
    item.choices_wire=JSON.stringify(item.keep_encrypted??[]);
    item.policy=structurePolicyFromObjects(item.objects,{keep_encrypted:item.keep_encrypted??[]});}
  await writeFile(new URL('genesis-structure-vectors.json',import.meta.url),
    JSON.stringify(cases.map(({name,objects_wire,choices_wire,policy})=>
      ({name,objects_wire,choices_wire,policy})),null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
