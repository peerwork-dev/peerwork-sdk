// Direct tracked object-source proof cases; no keys or journal state.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/',import.meta.url));
const dir=await mkdtemp(join(tmpdir(),'peerwork-object-source-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-protocol-object-source.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {createProtocolObjectSource,readProtocolObjectSource}=await import(pathToFileURL(output));
  const workspace='W'.repeat(43),digest='a'.repeat(64);
  const checkpoint={v:1,workspace_id:workspace,owner_id:'O'.repeat(43),owner_key:'K'.repeat(43),
    sequence:1,head:'b'.repeat(64),policy_hash:'c'.repeat(64)};
  const value={workspace_id:workspace,digest,manifest:{name:'demo',text:'\ud800',array:[1,2,3]},
    resolved_manifest:{name:'demo',text:'\ud800',array:[1,2,3]}};
  const created=createProtocolObjectSource(value,checkpoint);
  const base=(name)=>({name,proof:structuredClone(created.proof),parts:structuredClone(created.parts)});
  const cases=[base('valid'),base('changed_text'),base('missing_part'),base('duplicate_part'),base('wrong_descriptor_bytes'),base('wrong_source_id')];
  cases[1].parts[0].value.text+='x';
  cases[2].parts=[];
  cases[3].parts.push(structuredClone(cases[3].parts[0]));
  cases[4].proof.parts[0].bytes++;
  cases[5].proof.source_id='d'.repeat(64);
  for(const test of cases){try{test.result=readProtocolObjectSource(test.proof,test.parts);}catch(error){test.error=error.message;}}
  await writeFile(join(root,'protocol-object-source-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
