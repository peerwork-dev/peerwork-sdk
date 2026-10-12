// Object-derived policy binding oracle from the vendored tracked TypeScript.
import {mkdtemp, rm, writeFile, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const dir=await mkdtemp(join(tmpdir(),'peerwork-structure-binding-'));
try {
  const source=resolve(fileURLToPath(new URL('reference/src/',import.meta.url)));
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {structurePolicyFromObjects,verifyStructureBindings,structureProtocolFromManifest} from '${source}/workspace-structure.ts';
    export {encodeCanonicalJson,sha256} from '${source}/workspace-secure-crypto.ts';`,resolveDir:source,sourcefile:'oracle.ts'},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {structurePolicyFromObjects,verifyStructureBindings,structureProtocolFromManifest,encodeCanonicalJson,sha256}=await import(pathToFileURL(output));
  const hex=bytes=>Buffer.from(bytes).toString('hex');
  const manifest={name:'binding',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],
    record_schemas:{'discussion.message':{type:'object',fields:{author:'string',body:'string'},required:['author','body'],max_bytes:4096}},
    initial_state:{},actions:[]};
  const digest=hex(await sha256(encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest})));
  const workspace='w'.repeat(43),instance='i'.repeat(43);
  const protocol={kind:'protocols',id:digest,revision:1,provenance:'AUTHOR_SIGNED',value:{digest,workspace_id:workspace,manifest,resolved_manifest:manifest}};
  const row={kind:'instances',id:instance,revision:1,provenance:'AUTHOR_SIGNED',value:{id:instance,protocol_digest:digest}};
  const objects=[protocol,row];
  const policy=structurePolicyFromObjects(objects);
  const cases=[['valid',policy,objects],['missing_protocol',{...policy,protocols:[]},objects],
    ['wrong_instance',{...policy,instances:[]},objects],
    ['extra_action',{...policy,protocols:[{...policy.protocols[0],actions:{extra:{schemas:[],roles:[],capabilities:[],heads:'NONE'}}}]},objects],
    ['readable_to_e2ee',{...policy,protocols:[{...policy.protocols[0],schemas:{'discussion.message':{...policy.protocols[0].schemas['discussion.message'],fields:{...policy.protocols[0].schemas['discussion.message'].fields,author:{protection:'e2ee',type:'string'}}}}}],disclosure:[{...policy.disclosure[0],fields:[]}]},objects],
  ];
  const result=[];
  for(const [name,input,rows] of cases){try{await verifyStructureBindings(input,rows,workspace);result.push({name,policy:input,objects:rows,ok:true});}
    catch(error){result.push({name,policy:input,objects:rows,ok:false,error:error.message});}}
  const official=JSON.parse(await readFile(new URL('protocol-package-source-vectors.json',import.meta.url),'utf8'))[0];
  result.push({name:'official_proposal_declaration',manifest:official.result.manifest,
    digest:official.result.protocol_digest,
    expected_protocol:structureProtocolFromManifest(official.result.protocol_digest,official.result.manifest)});
  await writeFile(new URL('structure-binding-vectors.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
