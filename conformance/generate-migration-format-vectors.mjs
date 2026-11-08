// Direct decrypted-content format ceiling outcomes from tracked TypeScript.
import {createHash} from 'node:crypto';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-migration-format-'));
try {
  const source=resolve(fileURLToPath(new URL('reference/src/',import.meta.url)));
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {assertProtocolFormatCeiling} from '${source}/workspace-secure-format-ceiling.ts';
    export {encodeCanonicalJson} from '${source}/workspace-secure-crypto.ts';`,resolveDir:source,sourcefile:'oracle.ts'},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {assertProtocolFormatCeiling,encodeCanonicalJson}=await import(pathToFileURL(output));
  const v1={name:'simple'},v2={name:'simple',format_version:2};
  const protocol=(manifest=v1,extra={})=>({kind:'protocols',id:'p',revision:1,provenance:'AUTHOR_SIGNED',
    value:{manifest,resolved_manifest:manifest,...extra}});
  const archived=(object,mode='PUBLIC')=>({kind:'secure_commits',id:'c',revision:1,provenance:'LEGACY_OWNER_ATTESTED',
    value:{payload:{mode,body:{objects:[object]}}}});
  const descriptor={kind:'protocols',id:'p',revision:1};
  const digest=createHash('sha256').update(encodeCanonicalJson(descriptor)).digest('hex');
  const fragment={kind:'secure_fragment',id:`${digest}-0`,revision:1,provenance:'AUTHOR_SIGNED',
    value:{fragment:{...descriptor,index:0,count:1,provenance:'AUTHOR_SIGNED'},
      data:Buffer.from(encodeCanonicalJson(protocol(v2).value)).toString('base64url')}};
  const legacy={kind:'protocols',id:'p',revision:1,provenance:'LEGACY_OWNER_ATTESTED',
    value:{manifest:JSON.stringify({manifest:v2}),resolved_manifest:JSON.stringify(v2)}};
  const cases=[
    ['empty',[],1],['author_v1',[protocol()],1],['author_v2_denied',[protocol(v2)],1],
    ['author_v2_allowed',[protocol(v2)],2],['author_v3_denied',[protocol({format_version:3})],2],
    ['archive_v2_denied',[archived(protocol(v2))],1],
    ['archive_private_denied',[archived(protocol(),'PRIVATE')],1],
    ['fragment_v2_denied',[fragment],1],['legacy_v2_denied',[legacy],1],
    ['missing_resolved_denied',[{...protocol(),value:{manifest:v1}}],1],
    ['composition_dependency_v2_denied',[protocol(v1,{composition:{source_manifest:v1,dependencies:[{manifest:v2}]}})],1],
    ['wrong_provenance_denied',[{...protocol(),provenance:'OTHER'}],1],
  ];
  const results=[];
  for(const [name,objects,ceiling] of cases){
    try{await assertProtocolFormatCeiling(objects,ceiling);results.push({name,objects,ceiling,ok:true});}
    catch(error){results.push({name,objects,ceiling,ok:false,error:String(error.message)});}
  }
  await writeFile(fileURLToPath(new URL('migration-format-vectors.json',import.meta.url)),JSON.stringify(results,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
