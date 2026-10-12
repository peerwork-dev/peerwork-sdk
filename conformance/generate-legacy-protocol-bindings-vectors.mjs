// Direct pinned TypeScript oracle for archived legacy protocol bindings.
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE??fileURLToPath(new URL('reference/src/',import.meta.url));
const dir=await mkdtemp(join(tmpdir(),'peerwork-legacy-bindings-'));
try {
 const output=join(dir,'oracle.mjs');
 await build({stdin:{contents:`export {verifyHistoricalProtocolBindings} from './workspace-structure.ts'; export {manifestCanonical,canonicalStructured} from './workspace-manifest.ts'; export {composeProtocol} from './workspace-protocol-composition.ts'; export {encodeCanonicalJson} from './workspace-secure-crypto.ts';`,resolveDir:resolve(source)},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
 const {verifyHistoricalProtocolBindings,manifestCanonical,canonicalStructured,composeProtocol,encodeCanonicalJson}=await import(pathToFileURL(output));
 const vectors=JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8'));
 const minimal=vectors.find(v=>v.name==='minimal_valid').manifest;
 const hash=value=>createHash('sha256').update(value).digest('hex');
 const digest=manifest=>hash(encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest}));
 const workspace='w'.repeat(43),actor='a'.repeat(43);
 function legacy(sourceManifest,load=()=>undefined){
  const sourceEnvelope={semantics:'peerwork.kernel.v1',manifest:sourceManifest};
  const sourceText=canonicalStructured(sourceEnvelope);
  const composed=composeProtocol(sourceManifest,load,(a,b)=>a.localeCompare(b));
  const resolved=composed.manifest;
  const id=digest(resolved);
  return {kind:'protocols',id,revision:1,provenance:'LEGACY_OWNER_ATTESTED',value:{digest:id,workspace_id:workspace,
   source_digest:hash(sourceText),resolved_manifest:canonicalStructured(resolved),manifest:sourceText,
   dependency_closure:canonicalStructured(composed.dependencyClosure),created_by:actor,created:1}};
 }
 async function result(name,objects,valid=true){
  try {await verifyHistoricalProtocolBindings(objects,workspace,1);return {name,workspace_id:workspace,objects,valid,result:'ok'};}
  catch(error){if(valid)throw new Error(`${name}: oracle rejected valid case (${error.message})`);return {name,workspace_id:workspace,objects,valid,result:'reject'};}
 }
 const standalone=legacy(minimal);
 const omitted=structuredClone(minimal);for(const key of ['protocol_roles','capabilities','role_conflicts','historical_role_conflicts','constraints'])delete omitted[key];
 const omittedDefault=legacy(omitted);
 const childSource=structuredClone(minimal);childSource.name='child';
 const child=legacy(childSource);
 const parentSource=structuredClone(minimal);parentSource.name='parent';parentSource.dependencies=[child.id];
 const parent=legacy(parentSource,d=>d===child.id?childSource:undefined);
 const cases=[];
 cases.push(await result('standalone_legacy', [standalone]));
 cases.push(await result('root_omitted_defaults_normalize', [omittedDefault]));
 cases.push(await result('dependency_closure_postorder', [child,parent]));
 cases.push(await result('dependency_missing', [parent],false));
 const wrongOrder=structuredClone(parent);wrongOrder.value.dependency_closure=canonicalStructured([]);
 cases.push(await result('dependency_closure_mismatch', [child,wrongOrder],false));
 const wrongSource=structuredClone(standalone);wrongSource.value.source_digest='0'.repeat(64);
 cases.push(await result('raw_source_digest_mismatch', [wrongSource],false));
 const noncanonical=structuredClone(standalone);noncanonical.value.manifest=JSON.stringify(JSON.parse(noncanonical.value.manifest),null,2);
 cases.push(await result('noncanonical_source_envelope', [noncanonical],false));
 const wrongWorkspace=structuredClone(standalone);wrongWorkspace.value.workspace_id='x'.repeat(43);
 cases.push(await result('workspace_mismatch', [wrongWorkspace],false));
 const action=(id)=>({id,reads:[],writes:[],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[],effects:[]}]});
 const punctuation=structuredClone(minimal);punctuation.actions=[action('a-1'),action('a_1')];
 const punctuationCase=await result('locale_compare_action_order', [legacy(punctuation)]);punctuationCase.check_rust=false;cases.push(punctuationCase);
 function unsatisfiedPortRow(manifest){const normalized=manifestCanonical(manifest).manifest,id=digest(normalized),sourceText=canonicalStructured({semantics:'peerwork.kernel.v1',manifest});
  return {kind:'protocols',id,revision:1,provenance:'LEGACY_OWNER_ATTESTED',value:{digest:id,workspace_id:workspace,source_digest:hash(sourceText),resolved_manifest:canonicalStructured(normalized),manifest:sourceText,dependency_closure:'[]',created_by:actor,created:1}};}
 const missingPort=structuredClone(minimal);missingPort.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,ports:[{import_path:[],action_id:'missing.action',variant:0,input_name:'input',type:'actor_id',required:true,bound:false}]};
 cases.push(await result('execution_requirement_missing_action', [unsatisfiedPortRow(missingPort)],false));
 const missingVariant=structuredClone(minimal);missingVariant.actions=[action('present.action')];missingVariant.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,ports:[{import_path:[],action_id:'present.action',variant:1,input_name:'input',type:'actor_id',required:true,bound:false}]};
 cases.push(await result('execution_requirement_missing_variant', [unsatisfiedPortRow(missingVariant)],false));
 await writeFile(join(root,'legacy-protocol-bindings-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
