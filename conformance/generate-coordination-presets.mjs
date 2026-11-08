// Pinned TypeScript coordination variants for native owner-create fixtures.
import {createHash} from 'node:crypto';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const source=resolve('reference/src/workspace-presets.ts');
const sha=createHash('sha256').update(await readFile(source)).digest('hex');
if(sha!=='2e85ed64b4ff63737cfe5fc2fd47f270dc8bb488533a5a287a0270d5702223bd')
  throw new Error('tracked presets source changed');
const dir=await mkdtemp(join(tmpdir(),'peerwork-coordination-presets-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {coordinationPreset,coordinationResultPreset} from '${source}';
    export {manifestCanonical} from '${resolve('reference/src/workspace-manifest.ts')}';`,
    resolveDir:resolve('reference/src'),sourcefile:'oracle.ts'},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {coordinationPreset,coordinationResultPreset,manifestCanonical}=await import(pathToFileURL(output));
  const entries=[coordinationPreset,coordinationResultPreset].map((factory,index)=>{
    const manifest=factory(),canonical=manifestCanonical(manifest).canonical;
    return {version:index+1,digest:createHash('sha256').update(canonical).digest('hex'),manifest};
  });
  await writeFile(new URL('coordination-presets.json',import.meta.url),
    JSON.stringify({source_sha256:sha,entries})+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
