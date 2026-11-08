// Direct fragment outcomes from the vendored tracked TypeScript implementation.
import {createHash} from 'node:crypto';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-migration-fragments-'));
try {
  const source=resolve(fileURLToPath(new URL('reference/src/',import.meta.url)));
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {inflateSecureFragments} from '${source}/workspace-secure-migration.ts';
    export {encodeCanonicalJson} from '${source}/workspace-secure-crypto.ts';`,resolveDir:source,sourcefile:'oracle.ts'},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {inflateSecureFragments,encodeCanonicalJson}=await import(pathToFileURL(output));
  const value={example:1};
  const descriptor={kind:'protocols',id:'proto',revision:1};
  const key=createHash('sha256').update(encodeCanonicalJson(descriptor)).digest('hex');
  const fragment=(data,index=0,count=1)=>({kind:'secure_fragment',id:`${key}-${index}`,revision:1,
    provenance:'AUTHOR_SIGNED',value:{fragment:{...descriptor,index,count,provenance:'AUTHOR_SIGNED'},data}});
  const base64=bytes=>Buffer.from(bytes).toString('base64url');
  const bytes=encodeCanonicalJson(value);
  const good=fragment(base64(bytes));
  const normal={...descriptor,provenance:'AUTHOR_SIGNED',value};
  const cases=[
    ['one_fragment',[good]],
    ['missing_part',[fragment(base64(bytes),0,2)]],
    ['duplicate_part',[good,good]],
    ['noncanonical_json',[fragment(base64(new TextEncoder().encode('{ "example":1}')))]],
    ['invalid_utf8',[fragment(base64(Uint8Array.of(0xff)))]],
    ['normal_collision',[normal,good]],
    ['wrong_fragment_id',[{...good,id:'wrong-0'}]],
    ['zero_part',[fragment('')]],
  ];
  const results=[];
  for(const [name,objects] of cases){
    try{const inflated=await inflateSecureFragments(objects);results.push({name,objects,ok:true,inflated});}
    catch(error){results.push({name,objects,ok:false,error:String(error.message)});}
  }
  await writeFile(fileURLToPath(new URL('migration-fragment-vectors.json',import.meta.url)),JSON.stringify(results,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
