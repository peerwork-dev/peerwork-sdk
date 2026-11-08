// Direct tracked historical protocol oracle for source encoding and format ceilings.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';

const root = fileURLToPath(new URL('.', import.meta.url));
const source = process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'peerwork-historical-protocol-'));
try {
  const output = join(dir, 'oracle.mjs');
  await build({stdin:{contents:`export {verifyHistoricalProtocolBindings} from './workspace-structure.ts'; export {encodeCanonicalJson} from './workspace-secure-crypto.ts';`,resolveDir:resolve(source)},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {verifyHistoricalProtocolBindings,encodeCanonicalJson} = await import(pathToFileURL(output));
  const vectors = JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8'));
  const format2 = vectors.find(item=>item.name==='state_array_utf16_sort_valid').manifest;
  const format1 = structuredClone(format2);
  delete format1.format_version;
  delete format1.state_array_types;
  delete format1.initial_state['𐀀'];
  delete format1.initial_state[''];
  const digest = manifest=>createHash('sha256').update(encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest})).digest('hex');
  const item = (name,manifest,format,asString=false) => {
    const id=digest(manifest);
    return {name,format,workspace_id:'workspace',object:{kind:'protocols',id,revision:1,provenance:'AUTHOR_SIGNED',
      value:{digest:id,workspace_id:'workspace',manifest:asString?JSON.stringify(manifest):manifest,
        resolved_manifest:asString?JSON.stringify(manifest):manifest}}};
  };
  const omitted=structuredClone(format2);
  delete omitted.capabilities;
  const cases=[item('format1_object',format1,1),item('format2_object',format2,2),
    item('format2_string',format2,2,true),item('format2_ceiling_one',format2,1),
    item('format2_omitted_default',omitted,2)];
  for(const test of cases){
    try {await verifyHistoricalProtocolBindings([test.object],test.workspace_id,test.format);test.result='ok';}
    catch(error){test.error=error.message;}
  }
  await writeFile(join(root,'historical-protocol-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
