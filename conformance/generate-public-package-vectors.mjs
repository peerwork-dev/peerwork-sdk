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
 const mappedParent=structuredClone(parent),mappedSource=JSON.parse(mappedParent.files['protocol.source.json']);
 mappedSource.format='peerwork.protocol-source.v2';mappedSource.interfaces={outputs:[],inputs:[],action_bodies:[]};
 mappedSource.manifest.protocol_roles=['PARENT_AUTHOR'];mappedSource.manifest.capabilities=['PARENT_PROPOSE'];
 mappedSource.role_mappings=[{from:{import:'dep',role:'AUTHOR'},to:'PARENT_AUTHOR'}];
 mappedSource.capability_mappings=[{from:{import:'dep',capability:'PROPOSE'},to:'PARENT_PROPOSE'}];
 mappedParent.files['protocol.source.json']=JSON.stringify(mappedSource);
 const mappedLock=JSON.parse(mappedParent.files['release.lock.json']);mappedLock.compiler_version='peerwork.protocol-compiler.v3';
 mappedParent.files['release.lock.json']=JSON.stringify(mappedLock);
 mappedLock.output_protocol_digest=previewProtocolPackage(mappedParent,{loadExactPackage:load}).protocolDigest;
 mappedParent.files['release.lock.json']=JSON.stringify(mappedLock);
 const mappedParsed=parseProtocolPackage(mappedParent),mappedCompiled=compileProtocolPackage(mappedParent,{loadExactPackage:load});
 if(!mappedCompiled.passed)throw new Error('mapped public dependency failed TS fixtures');
 const mappedVector={name:'parent_symbol_mapping',closure:createProtocolPackageClosure(mappedParent,[child]),package_digest:mappedParsed.packageDigest,protocol_digest:mappedCompiled.protocolDigest,source_digest:mappedCompiled.sourceDigest,compiled_manifest:mappedCompiled.manifest,compilation_lock:mappedCompiled.lock,passed:mappedCompiled.passed};
 await writeFile(join(root,'public-package-mapping-vectors.json'),JSON.stringify(mappedVector,null,2)+'\n');
 const exactFixture=structuredClone(bundle),propose=JSON.parse(exactFixture.files['fixtures/author-proposes.json']);
 const observed=compiled.fixtureResults.find(row=>row.id==='author-proposes')?.observed;
 if(!observed?.accepted)throw new Error('missing accepted tracked proposal fixture');
 propose.expected={accepted:true,state:observed.state,records:observed.records,headSelections:observed.headSelections,revisionEffects:observed.revisionEffects};
 exactFixture.files['fixtures/author-proposes.json']=JSON.stringify(propose);
 const exactCompiled=compileProtocolPackage(exactFixture,{loadExactPackage:()=>undefined});
 if(!exactCompiled.passed)throw new Error('exact-output fixture failed TS');
 const wrongFixture=structuredClone(exactFixture),wrongPropose=JSON.parse(wrongFixture.files['fixtures/author-proposes.json']);
 wrongPropose.expected.state={unexpected:true};wrongFixture.files['fixtures/author-proposes.json']=JSON.stringify(wrongPropose);
 let wrongOutcome;try{compileProtocolPackage(wrongFixture,{loadExactPackage:()=>undefined});wrongOutcome='ok';}catch(error){wrongOutcome=error.code??error.message;}
 const exactFixtureVector={name:'exact_single_fixture_outputs',valid:{closure:createProtocolPackageClosure(exactFixture,[]),package_digest:parseProtocolPackage(exactFixture).packageDigest,protocol_digest:exactCompiled.protocolDigest},wrong:{closure:createProtocolPackageClosure(wrongFixture,[]),package_digest:parseProtocolPackage(wrongFixture).packageDigest,result:wrongOutcome}};
 await writeFile(join(root,'public-package-exact-fixture-vectors.json'),JSON.stringify(exactFixtureVector,null,2)+'\n');
 const sequenceBundle=structuredClone(bundle),proposal=JSON.parse(sequenceBundle.files['fixtures/author-proposes.json']),selfAdopt=JSON.parse(sequenceBundle.files['fixtures/author-cannot-adopt-own-candidate.json']);
 const refBody={candidate_ref:{$fixture_ref:'candidate'}};
 const sequence={kind:'sequence',id:'adoption-sequence',state:{},steps:[
  {action_id:'proposal.propose',body:proposal.body,auth:proposal.auth,exact_inputs:[],bind_refs:[{name:'candidate',record_slot:'candidate'}],expected:{accepted:true}},
  {action_id:'proposal.adopt',body:refBody,auth:selfAdopt.auth,exact_inputs:['candidate'],bind_refs:[],expected:{accepted:false,code:'CONSTRAINT_FAILED'}},
  {action_id:'proposal.adopt',body:refBody,auth:{...selfAdopt.auth,actorId:'B'.repeat(43)},exact_inputs:['candidate'],bind_refs:[],expected:{accepted:true}},
 ]};
 sequenceBundle.files['fixtures/adoption-sequence.json']=JSON.stringify(sequence);
 const sequenceCompiled=compileProtocolPackage(sequenceBundle,{loadExactPackage:()=>undefined});
 if(!sequenceCompiled.passed)throw new Error('tracked sequence fixture failed TS');
 const sequenceWrong=structuredClone(sequenceBundle),wrongSequence=JSON.parse(sequenceWrong.files['fixtures/adoption-sequence.json']);
 wrongSequence.steps[0].bind_refs[0].record_slot='missing';sequenceWrong.files['fixtures/adoption-sequence.json']=JSON.stringify(wrongSequence);
 let sequenceWrongOutcome;try{compileProtocolPackage(sequenceWrong,{loadExactPackage:()=>undefined});sequenceWrongOutcome='ok';}catch(error){sequenceWrongOutcome=error.code??error.message;}
 const sequenceVector={name:'proposal_adoption_sequence',valid:{closure:createProtocolPackageClosure(sequenceBundle,[]),package_digest:parseProtocolPackage(sequenceBundle).packageDigest,protocol_digest:sequenceCompiled.protocolDigest,fixture:sequenceCompiled.fixtureResults.find(row=>row.id==='adoption-sequence')},wrong:{closure:createProtocolPackageClosure(sequenceWrong,[]),package_digest:parseProtocolPackage(sequenceWrong).packageDigest,result:sequenceWrongOutcome}};
 await writeFile(join(root,'public-package-sequence-vectors.json'),JSON.stringify(sequenceVector,null,2)+'\n');
 const sequenceOnlyChild=structuredClone(sequenceBundle);
 for(const name of names.filter(name=>name.startsWith('fixtures/')))delete sequenceOnlyChild.files[name];
 const sequenceChild=parseProtocolPackage(sequenceOnlyChild),inheritedParent=structuredClone(parent);
 const inheritedSource=JSON.parse(inheritedParent.files['protocol.source.json']);
 inheritedSource.imports=[{alias:'dep',package_digest:sequenceChild.packageDigest,namespace:'Dep'}];
 inheritedSource.parameters=[];inheritedSource.exports=[];inheritedSource.bindings=[];
 inheritedParent.files['protocol.source.json']=JSON.stringify(inheritedSource);
 const inheritedLock=JSON.parse(inheritedParent.files['release.lock.json']);inheritedLock.dependencies=inheritedSource.imports;inheritedLock.baseline_bindings={};
 inheritedParent.files['release.lock.json']=JSON.stringify(inheritedLock);
 const inheritedLoad=digest=>digest===sequenceChild.packageDigest?sequenceOnlyChild:undefined;
 inheritedLock.output_protocol_digest=previewProtocolPackage(inheritedParent,{loadExactPackage:inheritedLoad}).protocolDigest;
 inheritedParent.files['release.lock.json']=JSON.stringify(inheritedLock);
 const inheritedCompiled=compileProtocolPackage(inheritedParent,{loadExactPackage:inheritedLoad});
 if(!inheritedCompiled.passed||!inheritedCompiled.fixtureResults.find(row=>row.id==='dep/adoption-sequence')?.passed)throw new Error('inherited sequence fixture failed TS');
 const blockedParent=structuredClone(inheritedParent),blockedSource=JSON.parse(blockedParent.files['protocol.source.json']);
 blockedSource.derive=[{op:'add_constraint',action_id:'Dep.proposal.propose',guard:{op:'has_protocol_role',role:'Dep.REVIEWER'}}];
 blockedParent.files['protocol.source.json']=JSON.stringify(blockedSource);
 const blockedLock=JSON.parse(blockedParent.files['release.lock.json']);blockedLock.output_protocol_digest=previewProtocolPackage(blockedParent,{loadExactPackage:inheritedLoad}).protocolDigest;
 blockedParent.files['release.lock.json']=JSON.stringify(blockedLock);
 let blockedOutcome;try{compileProtocolPackage(blockedParent,{loadExactPackage:inheritedLoad});blockedOutcome='ok';}catch(error){blockedOutcome=error.code??error.message;}
 const inheritedVector={name:'inherited_sequence_replay',valid:{closure:createProtocolPackageClosure(inheritedParent,[sequenceOnlyChild]),package_digest:parseProtocolPackage(inheritedParent).packageDigest,protocol_digest:inheritedCompiled.protocolDigest,fixture:inheritedCompiled.fixtureResults.find(row=>row.id==='dep/adoption-sequence')},blocked:{closure:createProtocolPackageClosure(blockedParent,[sequenceOnlyChild]),package_digest:parseProtocolPackage(blockedParent).packageDigest,result:blockedOutcome}};
 await writeFile(join(root,'public-package-inherited-sequence-vectors.json'),JSON.stringify(inheritedVector,null,2)+'\n');
 const disposed=structuredClone(blockedParent),disposedSource=JSON.parse(disposed.files['protocol.source.json']);
 disposedSource.format='peerwork.protocol-source.v2';disposedSource.interfaces={outputs:[],inputs:[],action_bodies:[]};
 disposedSource.fixture_dispositions=[{origin:{package_digest:sequenceChild.packageDigest,import_path:['dep'],fixture_id:'adoption-sequence'},expected_rejection:'CONSTRAINT_FAILED',rationale:'The parent adds a stricter reviewer guard.',replacement_scenario_id:'basic'}];
 disposed.files['protocol.source.json']=JSON.stringify(disposedSource);
 const disposedLock=JSON.parse(disposed.files['release.lock.json']);disposedLock.compiler_version='peerwork.protocol-compiler.v3';
 disposed.files['release.lock.json']=JSON.stringify(disposedLock);
 disposedLock.output_protocol_digest=previewProtocolPackage(disposed,{loadExactPackage:inheritedLoad}).protocolDigest;
 disposed.files['release.lock.json']=JSON.stringify(disposedLock);
 const disposedParsed=parseProtocolPackage(disposed),disposedCompiled=compileProtocolPackage(disposed,{loadExactPackage:inheritedLoad});
 if(!disposedCompiled.passed||!disposedCompiled.fixtureResults.find(row=>row.id==='dep/adoption-sequence')?.disposition)throw new Error('fixture disposition failed TS');
 const wrongDisposition=structuredClone(disposed),wrongDispositionSource=JSON.parse(wrongDisposition.files['protocol.source.json']);
 wrongDispositionSource.fixture_dispositions[0].expected_rejection='FORBIDDEN';wrongDisposition.files['protocol.source.json']=JSON.stringify(wrongDispositionSource);
 let wrongDispositionOutcome;try{compileProtocolPackage(wrongDisposition,{loadExactPackage:inheritedLoad});wrongDispositionOutcome='ok';}catch(error){wrongDispositionOutcome=error.code??error.message;}
 const wrongOrigin=structuredClone(disposed),wrongOriginSource=JSON.parse(wrongOrigin.files['protocol.source.json']);
 wrongOriginSource.fixture_dispositions[0].origin.import_path=['other'];wrongOrigin.files['protocol.source.json']=JSON.stringify(wrongOriginSource);
 let wrongOriginOutcome;try{compileProtocolPackage(wrongOrigin,{loadExactPackage:inheritedLoad});wrongOriginOutcome='ok';}catch(error){wrongOriginOutcome=error.code??error.message;}
 const wrongReplacement=structuredClone(disposed),wrongReplacementSource=JSON.parse(wrongReplacement.files['protocol.source.json']);
 wrongReplacementSource.fixture_dispositions[0].replacement_scenario_id='missing';wrongReplacement.files['protocol.source.json']=JSON.stringify(wrongReplacementSource);
 let wrongReplacementOutcome;try{compileProtocolPackage(wrongReplacement,{loadExactPackage:inheritedLoad});wrongReplacementOutcome='ok';}catch(error){wrongReplacementOutcome=error.code??error.message;}
 const nestedParent=structuredClone(inheritedParent),nestedSource=JSON.parse(nestedParent.files['protocol.source.json']);
 nestedSource.format='peerwork.protocol-source.v2';nestedSource.interfaces={outputs:[],inputs:[],action_bodies:[]};nestedSource.imports=[{alias:'outer',package_digest:disposedParsed.packageDigest,namespace:'Outer'}];
 nestedParent.files['protocol.source.json']=JSON.stringify(nestedSource);
 const nestedLock=JSON.parse(nestedParent.files['release.lock.json']);nestedLock.compiler_version='peerwork.protocol-compiler.v3';nestedLock.dependencies=nestedSource.imports;
 nestedParent.files['release.lock.json']=JSON.stringify(nestedLock);
 const nestedLoad=digest=>digest===disposedParsed.packageDigest?disposed:digest===sequenceChild.packageDigest?sequenceOnlyChild:undefined;
 nestedLock.output_protocol_digest=previewProtocolPackage(nestedParent,{loadExactPackage:nestedLoad}).protocolDigest;
 nestedParent.files['release.lock.json']=JSON.stringify(nestedLock);
 const nestedCompiled=compileProtocolPackage(nestedParent,{loadExactPackage:nestedLoad});
 if(!nestedCompiled.passed||!nestedCompiled.fixtureResults.find(row=>row.id==='outer/dep/adoption-sequence')?.disposition)throw new Error('nested disposition failed TS');
 const dispositionVector={name:'inherited_fixture_disposition',valid:{closure:createProtocolPackageClosure(disposed,[sequenceOnlyChild]),package_digest:disposedParsed.packageDigest,protocol_digest:disposedCompiled.protocolDigest,fixture:disposedCompiled.fixtureResults.find(row=>row.id==='dep/adoption-sequence')},nested:{closure:createProtocolPackageClosure(nestedParent,[disposed,sequenceOnlyChild]),package_digest:parseProtocolPackage(nestedParent).packageDigest,protocol_digest:nestedCompiled.protocolDigest,fixture:nestedCompiled.fixtureResults.find(row=>row.id==='outer/dep/adoption-sequence')},wrong_code:{closure:createProtocolPackageClosure(wrongDisposition,[sequenceOnlyChild]),result:wrongDispositionOutcome},wrong_origin:{closure:createProtocolPackageClosure(wrongOrigin,[sequenceOnlyChild]),result:wrongOriginOutcome},wrong_replacement:{closure:createProtocolPackageClosure(wrongReplacement,[sequenceOnlyChild]),result:wrongReplacementOutcome}};
 await writeFile(join(root,'public-package-disposition-vectors.json'),JSON.stringify(dispositionVector,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
