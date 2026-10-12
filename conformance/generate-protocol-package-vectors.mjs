// Synthetic, public package/closure vectors from the tracked parser; no workspace data.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/',import.meta.url));
const dir=await mkdtemp(join(tmpdir(),'peerwork-package-vector-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {parseProtocolPackage,canonicalProtocolPackageBytes} from './protocol-package.ts'; export {createProtocolPackageClosure,canonicalProtocolPackageClosureBytes,parseProtocolPackageClosureBytes} from './protocol-package-closure.ts';`,resolveDir:resolve(source)},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {parseProtocolPackage,canonicalProtocolPackageBytes,createProtocolPackageClosure,canonicalProtocolPackageClosureBytes,parseProtocolPackageClosureBytes}=await import(pathToFileURL(output));
  const manifest=JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8')).find(item=>item.name==='minimal_valid').manifest;
  const metadata={format:'peerwork.protocol-package-metadata.v1',package_id:'demo',version:'1.0.0',name:'Demo',description:'Synthetic parser vector',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Example'}]};
  const packageSource={format:'peerwork.protocol-source.v1',semantics:'peerwork.kernel.v1',manifest,imports:[],parameters:[],exports:[],bindings:[],derive:[]};
  const lock={format:'peerwork.protocol-lock.v1',compiler_version:'peerwork.protocol-compiler.v1',semantics:'peerwork.kernel.v1',dependencies:[],baseline_bindings:{},output_protocol_digest:'a'.repeat(64)};
  const fixture={id:'basic',action_id:'demo.none',state:{count:0},body:{},auth:{actorId:'A'.repeat(43),workspaceRoles:[],protocolRoles:[],capabilities:[]},exact_inputs:[],expected:{accepted:false,code:'INVALID_PAYLOAD'}};
  const bundle={format:'peerwork.protocol-package.v1',files:{'package.json':JSON.stringify(metadata),'protocol.source.json':JSON.stringify(packageSource),'release.lock.json':JSON.stringify(lock),'README.md':'Synthetic parser vector.','LICENSE':'Apache License 2.0','fixtures/basic.json':JSON.stringify(fixture)}};
  const parsed=parseProtocolPackage(bundle);
  const closure=createProtocolPackageClosure(bundle,[]);
  const closureBytes=canonicalProtocolPackageClosureBytes(closure);
  parseProtocolPackageClosureBytes(closureBytes);
  const cases=[{name:'valid',bundle,package_digest:parsed.packageDigest,canonical_package_base64:Buffer.from(canonicalProtocolPackageBytes(bundle)).toString('base64url'),closure,canonical_closure_base64:Buffer.from(closureBytes).toString('base64url'),result:'ok'}];
  const changed=structuredClone(closure);
  changed.packages[parsed.packageDigest]=changed.packages[parsed.packageDigest]+'A';
  try {canonicalProtocolPackageClosureBytes(changed);cases.push({name:'changed_package_bytes',closure:changed,result:'ok'});}catch(error){cases.push({name:'changed_package_bytes',closure:changed,error:error.message});}
  await writeFile(join(root,'protocol-package-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
