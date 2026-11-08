// Synthetic, public package/closure vectors from the tracked parser; no workspace data.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE ?? fileURLToPath(new URL('reference/src/',import.meta.url));
const dir=await mkdtemp(join(tmpdir(),'peerwork-package-vector-'));
try {
  const output=join(dir,'oracle.mjs');
  await build({stdin:{contents:`export {parseProtocolPackage,canonicalProtocolPackageBytes} from './protocol-package.ts'; export {createProtocolPackageClosure,canonicalProtocolPackageClosureBytes,parseProtocolPackageClosureBytes} from './protocol-package-closure.ts'; export {previewProtocolPackage,compileProtocolPackage} from './protocol-compiler.ts';`,resolveDir:resolve(source)},
    outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {parseProtocolPackage,canonicalProtocolPackageBytes,createProtocolPackageClosure,canonicalProtocolPackageClosureBytes,parseProtocolPackageClosureBytes,previewProtocolPackage,compileProtocolPackage}=await import(pathToFileURL(output));
  const manifest=JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8')).find(item=>item.name==='minimal_valid').manifest;
  const metadata={format:'peerwork.protocol-package-metadata.v1',package_id:'demo',version:'1.0.0',name:'Demo',description:'Synthetic parser vector',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Example'}]};
  const packageSource={format:'peerwork.protocol-source.v1',semantics:'peerwork.kernel.v1',manifest,imports:[],parameters:[],exports:[],bindings:[],derive:[]};
  const lock={format:'peerwork.protocol-lock.v1',compiler_version:'peerwork.protocol-compiler.v1',semantics:'peerwork.kernel.v1',dependencies:[],baseline_bindings:{},output_protocol_digest:'a'.repeat(64)};
  const fixture={id:'basic',action_id:'demo.none',state:{count:0},body:{},auth:{actorId:'A'.repeat(43),workspaceRoles:[],protocolRoles:[],capabilities:[]},exact_inputs:[],expected:{accepted:false,code:'FORBIDDEN'}};
  const bundle={format:'peerwork.protocol-package.v1',files:{'package.json':JSON.stringify(metadata),'protocol.source.json':JSON.stringify(packageSource),'release.lock.json':JSON.stringify(lock),'README.md':'Synthetic parser vector.','LICENSE':'Apache License 2.0','fixtures/basic.json':JSON.stringify(fixture)}};
  const preview=previewProtocolPackage(bundle,{loadExactPackage:()=>undefined});
  lock.output_protocol_digest=preview.protocolDigest;bundle.files['release.lock.json']=JSON.stringify(lock);
  const compilation=compileProtocolPackage(bundle,{loadExactPackage:()=>undefined});
  if(!compilation.passed||!compilation.validation.baselineLockVerified)throw new Error('synthetic baseline fixture did not compile');
  const parsed=parseProtocolPackage(bundle);
  const closure=createProtocolPackageClosure(bundle,[]);
  const closureBytes=canonicalProtocolPackageClosureBytes(closure);
  parseProtocolPackageClosureBytes(closureBytes);
  const cases=[{name:'valid',bundle,package_digest:parsed.packageDigest,package_count:1,protocol_digest:compilation.protocolDigest,source_digest:compilation.sourceDigest,compiled_manifest:compilation.manifest,compilation_lock:compilation.lock,canonical_package_base64:Buffer.from(canonicalProtocolPackageBytes(bundle)).toString('base64url'),closure,canonical_closure_base64:Buffer.from(closureBytes).toString('base64url'),result:'ok'}];
  const imported=structuredClone(bundle);const importedMetadata=JSON.parse(imported.files['package.json']);importedMetadata.package_id='imported';imported.files['package.json']=JSON.stringify(importedMetadata);
  const importedPackage=parseProtocolPackage(imported);
  const rootBundle=structuredClone(bundle);const rootSource=JSON.parse(rootBundle.files['protocol.source.json']);rootSource.imports=[{alias:'dep',package_digest:importedPackage.packageDigest,namespace:'Dep'}];rootBundle.files['protocol.source.json']=JSON.stringify(rootSource);
  const rootLock=JSON.parse(rootBundle.files['release.lock.json']);rootLock.dependencies=rootSource.imports;rootBundle.files['release.lock.json']=JSON.stringify(rootLock);
  const exactLoad=digest=>digest===importedPackage.packageDigest?imported:undefined;
  const dependencyPreview=previewProtocolPackage(rootBundle,{loadExactPackage:exactLoad});
  rootLock.output_protocol_digest=dependencyPreview.protocolDigest;rootBundle.files['release.lock.json']=JSON.stringify(rootLock);
  const dependencyCompilation=compileProtocolPackage(rootBundle,{loadExactPackage:exactLoad});
  if(!dependencyCompilation.passed||!dependencyCompilation.validation.baselineLockVerified)throw new Error('dependent synthetic fixture did not compile');
  const rootPackage=parseProtocolPackage(rootBundle);const dependentClosure=createProtocolPackageClosure(rootBundle,[imported]);
  const dependentBytes=canonicalProtocolPackageClosureBytes(dependentClosure);parseProtocolPackageClosureBytes(dependentBytes);
  cases.push({name:'two_package_closure',bundle:rootBundle,package_digest:rootPackage.packageDigest,package_count:2,protocol_digest:dependencyCompilation.protocolDigest,source_digest:dependencyCompilation.sourceDigest,compilation_lock:dependencyCompilation.lock,compiled_manifest:dependencyCompilation.manifest,canonical_package_base64:Buffer.from(canonicalProtocolPackageBytes(rootBundle)).toString('base64url'),closure:dependentClosure,canonical_closure_base64:Buffer.from(dependentBytes).toString('base64url'),result:'ok'});
  const v2Bundle=structuredClone(bundle);const v2Source=JSON.parse(v2Bundle.files['protocol.source.json']);v2Source.format='peerwork.protocol-source.v2';v2Source.interfaces={outputs:[],inputs:[],action_bodies:[]};v2Bundle.files['protocol.source.json']=JSON.stringify(v2Source);
  const v2Lock=JSON.parse(v2Bundle.files['release.lock.json']);v2Lock.compiler_version='peerwork.protocol-compiler.v3';v2Bundle.files['release.lock.json']=JSON.stringify(v2Lock);
  const v2Preview=previewProtocolPackage(v2Bundle,{loadExactPackage:()=>undefined});v2Lock.output_protocol_digest=v2Preview.protocolDigest;v2Bundle.files['release.lock.json']=JSON.stringify(v2Lock);
  const v2Compiled=compileProtocolPackage(v2Bundle,{loadExactPackage:()=>undefined});if(!v2Compiled.passed)throw new Error('v2 baseline fixture did not compile');
  const v2Package=parseProtocolPackage(v2Bundle),v2Closure=createProtocolPackageClosure(v2Bundle,[]),v2Bytes=canonicalProtocolPackageClosureBytes(v2Closure);
  cases.push({name:'v2_empty_interfaces',bundle:v2Bundle,package_digest:v2Package.packageDigest,package_count:1,protocol_digest:v2Compiled.protocolDigest,source_digest:v2Compiled.sourceDigest,compilation_lock:v2Compiled.lock,compiled_manifest:v2Compiled.manifest,canonical_package_base64:Buffer.from(canonicalProtocolPackageBytes(v2Bundle)).toString('base64url'),closure:v2Closure,canonical_closure_base64:Buffer.from(v2Bytes).toString('base64url'),result:'ok'});
  const changed=structuredClone(closure);
  changed.packages[parsed.packageDigest]=changed.packages[parsed.packageDigest]+'A';
  try {canonicalProtocolPackageClosureBytes(changed);cases.push({name:'changed_package_bytes',closure:changed,result:'ok'});}catch(error){cases.push({name:'changed_package_bytes',closure:changed,error:error.message});}
  const rejected=(name,mutation)=>{
    const altered=structuredClone(bundle);mutation(altered);
    const files=Object.fromEntries(Object.entries(altered.files).sort(([a],[b])=>a<b?-1:a>b?1:0));
    const bytes=Buffer.from(JSON.stringify({format:altered.format,files}));
    const digest=createHash('sha256').update(bytes).digest('hex');
    const envelope={format:closure.format,root_package_digest:digest,packages:{[digest]:bytes.toString('base64url')}};
    try {canonicalProtocolPackageClosureBytes(envelope);cases.push({name,closure:envelope,result:'ok'});}catch(error){cases.push({name,closure:envelope,error:error.message});}
  };
  rejected('unsafe_file_path',value=>{value.files['../escape.txt']='bad';});
  rejected('missing_required_file',value=>{delete value.files.LICENSE;});
  rejected('missing_fixture',value=>{delete value.files['fixtures/basic.json'];});
  rejected('lock_source_mismatch',value=>{const changed=JSON.parse(value.files['release.lock.json']);changed.dependencies=[{alias:'other',package_digest:'b'.repeat(64),namespace:'Other'}];value.files['release.lock.json']=JSON.stringify(changed);});
  rejected('unsafe_metadata_key',value=>{value.files['package.json']=value.files['package.json'].replace('"package_id"','"__proto__":null,"package_id"');});
  rejected('source_manifest_dependencies',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.manifest.dependencies=['a'.repeat(64)];value.files['protocol.source.json']=JSON.stringify(changed);});
  rejected('source_manifest_execution_requirements',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.manifest.execution_requirements={format:'peerwork.protocol-execution-requirements.v1',closure_complete:true,ports:[]};value.files['protocol.source.json']=JSON.stringify(changed);});
  rejected('v1_interface_extension',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.interfaces={outputs:[],inputs:[],action_bodies:[]};value.files['protocol.source.json']=JSON.stringify(changed);});
  rejected('invalid_metadata_package_id',value=>{const changed=JSON.parse(value.files['package.json']);changed.package_id='Bad_ID';value.files['package.json']=JSON.stringify(changed);});
  rejected('unknown_source_field',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.unrecognized=true;value.files['protocol.source.json']=JSON.stringify(changed);});
  rejected('enum_parameter_missing_values',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.parameters=[{name:'choice',type:'enum',default:'A'}];changed.exports=[{slot:'choice',parameter:'choice'}];value.files['protocol.source.json']=JSON.stringify(changed);});
  rejected('interface_required_field_undeclared',value=>{const changed=JSON.parse(value.files['protocol.source.json']);changed.format='peerwork.protocol-source.v2';changed.interfaces={outputs:[],inputs:[],action_bodies:[{action:'demo.none',body:{fields:{},required:['missing'],additionalProperties:false}}]};value.files['protocol.source.json']=JSON.stringify(changed);});
  const compileRejected=(name,mutation)=>{
    const altered=structuredClone(bundle);mutation(altered);
    const pkg=parseProtocolPackage(altered),candidate=createProtocolPackageClosure(altered,[]);
    let outcome;try {const result=compileProtocolPackage(altered,{loadExactPackage:()=>undefined});outcome=result.passed?'ok':'fixture_failed';}catch(error){outcome=error.code??error.message;}
    cases.push({name,package_digest:pkg.packageDigest,closure:candidate,compile_result:outcome});
  };
  compileRejected('baseline_lock_wrong_digest',value=>{const changed=JSON.parse(value.files['release.lock.json']);changed.output_protocol_digest='a'.repeat(64);value.files['release.lock.json']=JSON.stringify(changed);});
  compileRejected('fixture_wrong_expectation',value=>{const changed=JSON.parse(value.files['fixtures/basic.json']);changed.expected={accepted:true};value.files['fixtures/basic.json']=JSON.stringify(changed);});
  await writeFile(join(root,'protocol-package-vectors.json'),JSON.stringify(cases,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
