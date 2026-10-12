// Direct ordering oracle from the pinned tracked structure implementation.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir = await mkdtemp(join(tmpdir(), 'peerwork-structure-order-'));
try {
  const entry = resolve(fileURLToPath(new URL('reference/src/', import.meta.url)), 'workspace-structure.ts');
  const output = join(dir, 'structure.mjs');
  await build({entryPoints:[entry], outfile:output, bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {structureDelta, structureSnapshotData} = await import(pathToFileURL(output));
  const z = 'z'.repeat(43), a = 'a'.repeat(43);
  const objects = [z,a].map(id => ({kind:'entity_heads',id,revision:1,provenance:'AUTHOR_SIGNED',
    value:{entity_id:id,record_id:id,revision:1,instance_id:id}}));
  const delta = structureDelta({v:1,kind:'ACTION',input:{},objects}, {v:1,protocols:[],disclosure:[],instances:[]});
  const snapshot = structureSnapshotData({records:new Map(),
    heads:new Map(delta.heads.map(head => [head.entity_id,head]))});
  await writeFile(new URL('structure-order-vectors.json', import.meta.url),
    JSON.stringify({objects,delta,snapshot},null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
