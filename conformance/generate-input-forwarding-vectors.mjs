// Public deterministic examples: no identities, live services or workspace data.
import {mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE??join(root,'reference/src');
const temporary=await mkdtemp(join(tmpdir(),'peerwork-input-forwarding-'));
try {
 const output=join(temporary,'compiler.mjs');
 await build({stdin:{contents:"export {parseProtocolPackage,canonicalProtocolPackageBytes} from './protocol-package.ts'; export {previewProtocolPackage,compileProtocolPackage} from './protocol-compiler.ts'; export {createProtocolPackageClosure} from './protocol-package-closure.ts';",resolveDir:resolve(source)},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
 const {parseProtocolPackage,canonicalProtocolPackageBytes,previewProtocolPackage,compileProtocolPackage,createProtocolPackageClosure}=await import(pathToFileURL(output));
 const packages=new Map();
 async function directory(at,prefix='',files={}) {for(const entry of await readdir(at,{withFileTypes:true})){const name=prefix+entry.name;if(entry.isDirectory())await directory(join(at,entry.name),name+'/',files);else files[name]=await readFile(join(at,entry.name),'utf8');}return files;}
 const load=digest=>packages.get(digest);
 function remember(bundle) {const pkg=parseProtocolPackage(bundle);packages.set(pkg.packageDigest,pkg);return pkg;}
 const draft=remember({format:'peerwork.protocol-package.v1',files:await directory(join(root,'public-fixtures/wiki-draft-component'))});
 const review=remember({format:'peerwork.protocol-package.v1',files:await directory(join(root,'public-fixtures/wiki-review-component'))});
 const names=review.source.interfaces.inputs.map(input=>input.name);
 const manifest=name=>({name,display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],protocol_roles:[],capabilities:[],role_conflicts:[],historical_role_conflicts:[],constraints:{},record_schemas:{},initial_state:{},actions:[]});
 function bundle(id,imports,interfaces,connections=[]) {
  const source={format:'peerwork.protocol-source.v2',semantics:'peerwork.kernel.v1',manifest:manifest(id),imports,parameters:[],exports:[],bindings:[],derive:[],interfaces,connections};
  const metadata={format:'peerwork.protocol-package-metadata.v1',package_id:id,version:'1.0.0',name:id,description:'Public synthetic recursive-input conformance example.',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Peerwork'}]};
  const fixture={id:'no-implicit-action',action_id:'absent.action',state:{},body:{},auth:{actorId:'A'.repeat(43),workspaceRoles:[],protocolRoles:[],capabilities:[]},exact_inputs:[],expected:{accepted:false,code:'FORBIDDEN'}};
  return {format:'peerwork.protocol-package.v1',files:{'package.json':JSON.stringify(metadata),'protocol.source.json':JSON.stringify(source),'release.lock.json':JSON.stringify({format:'peerwork.protocol-lock.v1',compiler_version:'peerwork.protocol-compiler.v3',semantics:'peerwork.kernel.v1',dependencies:imports,baseline_bindings:{},output_protocol_digest:'0'.repeat(64)}),'README.md':'Public synthetic recursive input example.','LICENSE':draft.bundle.files.LICENSE,'fixtures/no-implicit-action.json':JSON.stringify(fixture)}};
 }
 function lock(value) {const preview=previewProtocolPackage(value,{loadExactPackage:load});if(!preview.passed)throw new Error(JSON.stringify(preview.fixtureResults));value.files['release.lock.json']=JSON.stringify({...JSON.parse(value.files['release.lock.json']),output_protocol_digest:preview.protocolDigest});return remember(value);}
 const imported=(alias,pkg,namespace=alias)=>({alias,package_digest:pkg.packageDigest,namespace});
 const exportsFor=alias=>names.map(name=>({name,from:{import:alias,input:name}}));
 const first=lock(bundle('input-wrapper-one',[imported('child',review,'leaf')],{outputs:[],inputs:[],input_exports:exportsFor('child')}));
 const second=lock(bundle('input-wrapper-two',[imported('child',first,'wrapped')],{outputs:[],inputs:[],input_exports:exportsFor('child')}));
 const outputFor=name=>name.includes('author')?'draft_author':'current_draft';
 const connections=alias=>names.map(name=>({from:{import:'draft',output:outputFor(name)},to:{import:alias,input:name}}));
 const outer=()=>bundle('nested-input-consumer',[imported('draft',draft),imported('review',second)],{outputs:[],inputs:[]},connections('review'));
 const cases=[];
 function exactClosure(value) {
  const seen=new Map(),encoded={};
  const add=bundle=>{const bytes=canonicalProtocolPackageBytes(bundle),digest=createHash('sha256').update(bytes).digest('hex');encoded[digest]=Buffer.from(bytes).toString('base64url');return digest;};
  const rootDigest=add(value);
  const visit=source=>{for(const item of source.imports){const child=load(item.package_digest);if(!child)throw new Error('missing dependency');if(!seen.has(child.packageDigest)){seen.set(child.packageDigest,child);add(child.bundle);visit(child.source);}}};visit(JSON.parse(value.files['protocol.source.json']));
  return {format:'peerwork.protocol-package-closure.v1',root_package_digest:rootDigest,packages:encoded};
 }
 // Only exact transitive dependencies belong in a portable closure.
 function accepted(name,value){const pkg=lock(value),compiled=compileProtocolPackage(pkg,{loadExactPackage:load});if(!compiled.validation.passed)throw new Error(JSON.stringify(compiled.fixtureResults));cases.push({name,closure:exactClosure(pkg.bundle),protocol_digest:compiled.protocolDigest,source_digest:compiled.sourceDigest,compiled_manifest:compiled.manifest,compilation_lock:compiled.lock,interfaces_complete:compiled.interfacesComplete});}
 function rejected(name,value){let error,stage='parse';try{parseProtocolPackage(value);stage='compile';const preview=previewProtocolPackage(value,{loadExactPackage:load});error=preview.passed?null:'fixture_failed';}catch(failure){error=failure.code??failure.message;}if(!error)throw new Error(name+' unexpectedly accepted');cases.push({name,closure:exactClosure(value),stage,error});}
 accepted('two_wrappers_all_ports_bound',outer());
 accepted('unresolved_forwarded_ports_remain_required',first.bundle);
 accepted('same_package_two_distinct_occurrences',bundle('two-consumers',[imported('draft',draft),imported('left',second),imported('right',second)],{outputs:[],inputs:[]},[...connections('left'),...connections('right')]));
 const unknown=outer();const unknownSource=JSON.parse(unknown.files['protocol.source.json']);unknownSource.connections[0].to.input='absent';unknown.files['protocol.source.json']=JSON.stringify(unknownSource);rejected('unknown_public_input',unknown);
 const duplicate=outer();const duplicateSource=JSON.parse(duplicate.files['protocol.source.json']);duplicateSource.connections.push({...duplicateSource.connections[0],to:{...duplicateSource.connections[0].to,action:'wrapped.leaf.review.submit',variant:0}});duplicate.files['protocol.source.json']=JSON.stringify(duplicateSource);rejected('duplicate_short_and_long_producer',duplicate);
 const bound=bundle('export-connected-port',[imported('draft',draft),imported('review',review)],{outputs:[],inputs:[],input_exports:[{name:'again',from:{import:'review',input:names[0]}}]},[{from:{import:'draft',output:outputFor(names[0])},to:{import:'review',input:names[0]}}]);rejected('export_of_connected_input',bound);
 const missing=bundle('export-missing-port',[imported('child',review)],{outputs:[],inputs:[],input_exports:[{name:'missing',from:{import:'child',input:'absent'}}]});rejected('export_of_unknown_input',missing);
 const wrongType=outer();const wrongTypeSource=JSON.parse(wrongType.files['protocol.source.json']);wrongTypeSource.connections[0].from.output='draft_author';wrongType.files['protocol.source.json']=JSON.stringify(wrongTypeSource);rejected('forwarded_input_type_mismatch',wrongType);
 const wrongAction=outer();const wrongActionSource=JSON.parse(wrongAction.files['protocol.source.json']);wrongActionSource.connections[0].to={...wrongActionSource.connections[0].to,action:'wiki.publish',variant:0};wrongAction.files['protocol.source.json']=JSON.stringify(wrongActionSource);rejected('forwarded_input_wrong_explicit_action',wrongAction);
 const scoped=structuredClone(draft.bundle),scopedSource=JSON.parse(scoped.files['protocol.source.json']);scopedSource.interfaces.outputs.find(output=>output.name==='current_draft').scope='WORKSPACE';scoped.files['protocol.source.json']=JSON.stringify(scopedSource);const scopedDraft=lock(scoped);
 const wrongScope=outer(),wrongScopeSource=JSON.parse(wrongScope.files['protocol.source.json']);wrongScopeSource.imports[0]=imported('draft',scopedDraft);wrongScope.files['protocol.source.json']=JSON.stringify(wrongScopeSource);rejected('forwarded_input_scope_mismatch',wrongScope);
 const hooked=structuredClone(review.bundle),hookedSource=JSON.parse(hooked.files['protocol.source.json']);
 hookedSource.interfaces.inputs.find(input=>input.name==='published_draft').provenance_hook={record_slot:'publication',record_schema:'wiki.publication',relation_kind:'forwarded_evidence',target_input:'published_draft'};
 hooked.files['protocol.source.json']=JSON.stringify(hookedSource);const hookedReview=lock(hooked);
 const hookInner=lock(bundle('hook-wrapper-one',[imported('inside',hookedReview,'implementation')],{outputs:[],inputs:[],input_exports:exportsFor('inside')}));
 const hookOuter=lock(bundle('hook-wrapper-two',[imported('api',hookInner,'layer')],{outputs:[],inputs:[],input_exports:exportsFor('api')}));
 const hookConsumer=bundle('nested-provenance',[imported('draft',draft),imported('review',hookOuter)],{outputs:[],inputs:[]},connections('review'));
 accepted('forwarded_provenance_with_distinct_aliases_and_namespaces',hookConsumer);
 if(!cases.at(-1).compiled_manifest.actions.some(action=>action.variants.some(variant=>variant.effects.some(effect=>effect.op==='append'&&effect.relations.some(relation=>relation.kind==='review.layer.implementation.forwarded_evidence')))))throw new Error('nested provenance relation missing');
 await writeFile(join(root,'input-forwarding-vectors.json'),JSON.stringify(cases,null,2)+'\n');
 process.stdout.write(`Wrote ${cases.length} recursive-input vectors\n`);
} finally {await rm(temporary,{recursive:true,force:true});}
