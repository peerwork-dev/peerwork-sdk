// Direct retained package-source proof cases from the pinned TypeScript oracle.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const fixture=JSON.parse(await readFile(join(root,'public-package-vectors.json'),'utf8'));
const workspace='W'.repeat(43);
const checkpoint={v:1,workspace_id:workspace,owner_id:'O'.repeat(43),owner_key:'K'.repeat(43),
  sequence:1,head:'b'.repeat(64),policy_hash:'c'.repeat(64)};
const temp=await mkdtemp(join(tmpdir(),'peerwork-package-source-'));
try {
  const output=join(temp,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-protocol-package-source.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {createProtocolPackageSource,verifyProtocolPackageSource}=await import(pathToFileURL(output));
  const material={v:1,closure:fixture.closure,bindings:{}};
  const created=createProtocolPackageSource(material,checkpoint);
  const base=name=>({name,proof:structuredClone(created.proof),parts:structuredClone(created.parts)});
  const cases=[base('valid'),base('changed_part_text'),base('missing_part'),base('duplicate_part'),
    base('wrong_descriptor_bytes'),base('wrong_source_id'),base('wrong_protocol_digest')];
  cases[1].parts[0].value.text+='x';
  cases[2].parts=[];
  cases[3].parts.push(structuredClone(cases[3].parts[0]));
  cases[4].proof.parts[0].bytes++;
  cases[5].proof.source_id='d'.repeat(64);
  cases[6].proof.protocol_digest='e'.repeat(64);
  for(const test of cases){
    try {const compiled=verifyProtocolPackageSource(test.proof,test.parts);
      test.result={protocol_digest:compiled.protocolDigest,manifest:compiled.manifest};}
    catch(error){test.error=error.message;}
  }
  await writeFile(join(root,'protocol-package-source-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(temp,{recursive:true,force:true});}
