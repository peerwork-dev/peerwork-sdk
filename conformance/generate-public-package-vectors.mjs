// Tracked, public proposal-adoption package through the pinned package compiler.
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const fixtureDir=join(root,'public-fixtures/proposal-adoption');
const names=['LICENSE','README.md','package.json','protocol.source.json','release.lock.json',
 'fixtures/author-cannot-adopt-own-candidate.json','fixtures/author-proposes.json',
 'fixtures/different-author-adopts-exact-candidate.json','fixtures/different-candidate-reference-rejected.json'];
const files={};for(const name of names)files[name]=await readFile(join(fixtureDir,name),'utf8');
const bundle={format:'peerwork.protocol-package.v1',files};
const dir=await mkdtemp(join(tmpdir(),'peerwork-public-package-'));
try {
 const output=join(dir,'oracle.mjs');
 await build({stdin:{contents:`export {parseProtocolPackage,canonicalProtocolPackageBytes} from './protocol-package.ts'; export {createProtocolPackageClosure} from './protocol-package-closure.ts'; export {previewProtocolPackage,compileProtocolPackage} from './protocol-compiler.ts';`,resolveDir:resolve(source)},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
 const {parseProtocolPackage,canonicalProtocolPackageBytes,createProtocolPackageClosure,previewProtocolPackage,compileProtocolPackage}=await import(pathToFileURL(output));
 const parsed=parseProtocolPackage(bundle),compiled=compileProtocolPackage(bundle,{loadExactPackage:()=>undefined});
 const vector={name:'proposal_adoption',bundle,closure:createProtocolPackageClosure(bundle,[]),package_digest:parsed.packageDigest,canonical_package_base64:Buffer.from(canonicalProtocolPackageBytes(bundle)).toString('base64url'),protocol_digest:compiled.protocolDigest,source_digest:compiled.sourceDigest,compiled_manifest:compiled.manifest,compilation_lock:compiled.lock,fixture_results:compiled.fixtureResults,passed:compiled.passed,validation:compiled.validation};
 await writeFile(join(root,'public-package-vectors.json'),JSON.stringify(vector,null,2)+'\n');
 const component=structuredClone(bundle),componentSource=JSON.parse(component.files['protocol.source.json']);
 componentSource.format='peerwork.protocol-source.v2';
 componentSource.interfaces={outputs:[],inputs:[{action:'proposal.adopt',variant:0,name:'candidate',type:'exact_ref',scope:'INSTANCE',body_path:['candidate_ref'],required:true,action_body:{fields:{candidate_ref:{type:'exact_ref',input:'candidate',scope:'INSTANCE'}},required:['candidate_ref'],additionalProperties:false}}],action_bodies:[]};
 component.files['protocol.source.json']=JSON.stringify(componentSource);
 const componentLock=JSON.parse(component.files['release.lock.json']);componentLock.compiler_version='peerwork.protocol-compiler.v3';component.files['release.lock.json']=JSON.stringify(componentLock);
 const componentPreview=previewProtocolPackage(component,{loadExactPackage:()=>undefined});componentLock.output_protocol_digest=componentPreview.protocolDigest;component.files['release.lock.json']=JSON.stringify(componentLock);
 const componentParsed=parseProtocolPackage(component),componentCompiled=compileProtocolPackage(component,{loadExactPackage:()=>undefined});
 const componentVector={name:'synthetic_proposal_adoption_v2_input',bundle:component,closure:createProtocolPackageClosure(component,[]),package_digest:componentParsed.packageDigest,protocol_digest:componentCompiled.protocolDigest,source_digest:componentCompiled.sourceDigest,compiled_manifest:componentCompiled.manifest,compilation_lock:componentCompiled.lock,fixture_results:componentCompiled.fixtureResults,passed:componentCompiled.passed,interfaces_complete:componentCompiled.interfacesComplete};
 await writeFile(join(root,'public-package-v2-vectors.json'),JSON.stringify(componentVector,null,2)+'\n');
 const derived=structuredClone(bundle),derivedSource=JSON.parse(derived.files['protocol.source.json']);
 derivedSource.derive=[{op:'add_constraint',action_id:'proposal.adopt',guard:{op:'has_protocol_role',role:'ADOPTER'}}];
 derived.files['protocol.source.json']=JSON.stringify(derivedSource);
 const derivedLock=JSON.parse(derived.files['release.lock.json']);
 const derivedPreview=previewProtocolPackage(derived,{loadExactPackage:()=>undefined});
 derivedLock.output_protocol_digest=derivedPreview.protocolDigest;
 derived.files['release.lock.json']=JSON.stringify(derivedLock);
 const derivedParsed=parseProtocolPackage(derived),derivedCompiled=compileProtocolPackage(derived,{loadExactPackage:()=>undefined});
 if(!derivedCompiled.passed)throw new Error('derived public package failed TS fixtures');
 const derivedVector={name:'synthetic_proposal_adoption_derived_guard',closure:createProtocolPackageClosure(derived,[]),package_digest:derivedParsed.packageDigest,protocol_digest:derivedCompiled.protocolDigest,source_digest:derivedCompiled.sourceDigest,compiled_manifest:derivedCompiled.manifest,compilation_lock:derivedCompiled.lock,passed:derivedCompiled.passed};
 await writeFile(join(root,'public-package-derived-vectors.json'),JSON.stringify(derivedVector,null,2)+'\n');
 const child=structuredClone(bundle),childSource=JSON.parse(child.files['protocol.source.json']);
 childSource.manifest.actions.push({id:'unused.gate',reads:[],writes:[],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[{op:'has_protocol_role',role:'AUTHOR'}],effects:[]}]});
 childSource.parameters.push({name:'roleChoice',type:'enum',values:['AUTHOR','REVIEWER'],default:'AUTHOR',binding:{kind:'protocol_role_guard',action_id:'unused.gate',variant_index:0,guard_index:0}});
 childSource.exports.push({slot:'chosenRole',parameter:'roleChoice'});
 child.files['protocol.source.json']=JSON.stringify(childSource);
 const childLock=JSON.parse(child.files['release.lock.json']);childLock.output_protocol_digest=previewProtocolPackage(child,{loadExactPackage:()=>undefined}).protocolDigest;child.files['release.lock.json']=JSON.stringify(childLock);
 const childParsed=parseProtocolPackage(child);
 const minimal=JSON.parse(await readFile(join(root,'manifest-vectors.json'),'utf8')).find(item=>item.name==='minimal_valid').manifest;
 const parent={format:'peerwork.protocol-package.v1',files:{'LICENSE':'Apache License 2.0','README.md':'Synthetic parent binding vector.',
  'package.json':JSON.stringify({format:'peerwork.protocol-package-metadata.v1',package_id:'binding-parent',version:'1.0.0',name:'Binding parent',description:'Parent parameter binding vector',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Example'}]}),
  'protocol.source.json':JSON.stringify({format:'peerwork.protocol-source.v1',semantics:'peerwork.kernel.v1',manifest:minimal,imports:[{alias:'dep',package_digest:childParsed.packageDigest,namespace:'Dep'}],parameters:[{name:'selectedRole',type:'enum',values:['AUTHOR','REVIEWER'],default:'REVIEWER'}],exports:[{slot:'parentSelected',parameter:'selectedRole'}],bindings:[{parameter:'selectedRole',import_alias:'dep',slot:'chosenRole'}],derive:[]}),
  'release.lock.json':'',
  'fixtures/basic.json':JSON.stringify({id:'basic',action_id:'demo.none',state:{count:0},body:{},auth:{actorId:'A'.repeat(43),workspaceRoles:[],protocolRoles:[],capabilities:[]},exact_inputs:[],expected:{accepted:false,code:'FORBIDDEN'}})}};
 const parentLock={format:'peerwork.protocol-lock.v1',compiler_version:'peerwork.protocol-compiler.v1',semantics:'peerwork.kernel.v1',dependencies:[{alias:'dep',package_digest:childParsed.packageDigest,namespace:'Dep'}],baseline_bindings:{selectedRole:'REVIEWER'},output_protocol_digest:'a'.repeat(64)};
 parent.files['release.lock.json']=JSON.stringify(parentLock);
 const load=digest=>digest===childParsed.packageDigest?child:undefined;
 parentLock.output_protocol_digest=previewProtocolPackage(parent,{loadExactPackage:load}).protocolDigest;
 parent.files['release.lock.json']=JSON.stringify(parentLock);
 const parentParsed=parseProtocolPackage(parent),parentCompiled=compileProtocolPackage(parent,{loadExactPackage:load});
 if(!parentCompiled.passed)throw new Error('parent-binding package failed TS fixtures');
 const parentVector={name:'parent_exported_parameter_binding',closure:createProtocolPackageClosure(parent,[child]),package_digest:parentParsed.packageDigest,protocol_digest:parentCompiled.protocolDigest,source_digest:parentCompiled.sourceDigest,compiled_manifest:parentCompiled.manifest,compilation_lock:parentCompiled.lock,passed:parentCompiled.passed};
 await writeFile(join(root,'public-package-binding-vectors.json'),JSON.stringify(parentVector,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
