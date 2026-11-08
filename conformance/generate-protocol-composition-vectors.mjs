// Direct tracked TypeScript resolver cases for private lossless Rust composition.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root = fileURLToPath(new URL('.', import.meta.url));
const source = process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/', import.meta.url));
const dir = await mkdtemp(join(tmpdir(), 'peerwork-protocol-composition-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-secure-composition.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {resolveSecureProtocol,secureManifestDigest}=await import(pathToFileURL(output));
  const manifests=JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8'));
  const base=manifests.find(item=>item.name==='minimal_valid').manifest;
  const dep=structuredClone(base);
  dep.name='dependency';dep.initial_state={left:0};dep.protocol_roles=['reviewer'];
  const depDigest=(await secureManifestDigest(dep)).digest;
  const member=structuredClone(base);
  member.name='composed';member.dependencies=[depDigest];member.initial_state={right:1};member.protocol_roles=['approver'];
  const arrayDep=manifests.find(item=>item.name==='state_array_valid').manifest;
  const arrayDigest=(await secureManifestDigest(arrayDep)).digest;
  const arrayRoot=structuredClone(base);
  arrayRoot.name='array-composed';arrayRoot.dependencies=[arrayDigest];arrayRoot.initial_state={other:1};
  const engineCases=JSON.parse(await readFile(join(root,'secure-engine-vectors.json'),'utf8'));
  const controlAction=engineCases.find(item=>item.name==='action_control_revision').prior[0].value.resolved_manifest.actions[0];
  const actionDep=structuredClone(base);
  actionDep.name='action-dependency';actionDep.actions=[controlAction];
  const actionDigest=(await secureManifestDigest(actionDep)).digest;
  const actionRoot=structuredClone(base);
  actionRoot.name='action-composed';actionRoot.dependencies=[actionDigest];
  const port=structuredClone(manifests.find(item=>item.name==='requirements_valid').manifest.execution_requirements.ports[0]);
  port.action_id=controlAction.id;
  const validPort=structuredClone(actionRoot);
  validPort.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,ports:[{...port,variant:0}]};
  const missingActionPort=structuredClone(actionRoot);
  missingActionPort.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,ports:[{...port,action_id:'absent.action',variant:0}]};
  const missingVariantPort=structuredClone(actionRoot);
  missingVariantPort.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:false,ports:[{...port,variant:1}]};
  const cases=[
    {name:'standalone',root:base,nodes:[]},
    {name:'single_dependency',root:member,nodes:[{digest:depDigest,manifest:dep}]},
    {name:'format2_array_dependency',root:arrayRoot,nodes:[{digest:arrayDigest,manifest:arrayDep}]},
    {name:'action_dependency',root:actionRoot,nodes:[{digest:actionDigest,manifest:actionDep}]},
    {name:'merged_port_valid',root:validPort,nodes:[{digest:actionDigest,manifest:actionDep}]},
    {name:'merged_port_missing_action',root:missingActionPort,nodes:[{digest:actionDigest,manifest:actionDep}]},
    {name:'merged_port_missing_variant',root:missingVariantPort,nodes:[{digest:actionDigest,manifest:actionDep}]},
    {name:'missing_dependency',root:member,nodes:[]},
    {name:'dependency_digest_mismatch',root:member,nodes:[{digest:depDigest,manifest:{...dep,name:'mutated'}}]},
    {name:'state_conflict',root:{...member,initial_state:{left:2}},nodes:[{digest:depDigest,manifest:dep}]},
  ];
  for(const test of cases){
    try {const resolved=await resolveSecureProtocol(test.root,digest=>test.nodes.find(node=>node.digest===digest)?.manifest);
      test.result={manifest:resolved.manifest,composition:resolved.composition,closure:resolved.composition.dependencies.map(node=>node.digest),digest:resolved.digest};}
    catch(error){test.error=error.code??error.message;}
  }
  await writeFile(join(root,'protocol-composition-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
