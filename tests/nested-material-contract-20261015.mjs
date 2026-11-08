// Public package author/compiler and raw protocol resolver contract witness.
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createLegacyComposedInstallMaterial} from './legacy-owner-install-composition-material.mjs';
const [reference,output]=process.argv.slice(2);if(!reference||!output)throw Error('INPUT');
const load=name=>import(pathToFileURL(reference+'/dist-workspace/src/'+name+'.js').href);
const {manifestCanonical,SEMANTICS}=await load('workspace-manifest');
const {previewProtocolPackage}=await load('protocol-compiler');
const {parseProtocolPackage,PROTOCOL_PACKAGE_FORMAT,PROTOCOL_SOURCE_FORMAT,PROTOCOL_METADATA_FORMAT,PROTOCOL_LOCK_FORMAT,PROTOCOL_COMPILER_VERSION}=await load('protocol-package');
const {validateProtocolPackageClosure,createProtocolPackageClosure,exactPackageLoader}=await load('protocol-package-closure');
const {compilePackageMaterial}=await load('workspace-protocol-package-source');
const {resolveSecureProtocol,secureManifestDigest,verifyProtocolComposition}=await load('workspace-secure-composition');
const {secureEqual}=await load('workspace-secure-client');
const base=await createLegacyComposedInstallMaterial(reference);
// Decode the exact accepted two-package material using its public loader.
const loader=exactPackageLoader(base.material.closure),middle=loader(base.material.closure.root_package_digest);
if(!middle||middle.source.imports.length!==1)throw Error('MIDDLE_IMPORT');
const leaf=loader(middle.source.imports[0].package_digest);if(!leaf||leaf.source.imports.length)throw Error('LEAF_IMPORT');
const own=manifestCanonical({...base.sourceManifest,name:'example.nested-package-root.v1',dependencies:[]}).manifest;
const selectedImport={alias:'middle',package_digest:middle.packageDigest,namespace:'outer'};
const files={
 'package.json':JSON.stringify({format:PROTOCOL_METADATA_FORMAT,package_id:'nested-package-contract',version:'1.0.0',name:'Nested package contract',description:'Exact public three-package import chain',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Test'}]}),
 'protocol.source.json':JSON.stringify({format:PROTOCOL_SOURCE_FORMAT,semantics:SEMANTICS,manifest:own,imports:[selectedImport],parameters:[],exports:[],bindings:[],derive:[]}),
 'release.lock.json':JSON.stringify({format:PROTOCOL_LOCK_FORMAT,compiler_version:PROTOCOL_COMPILER_VERSION,semantics:SEMANTICS,dependencies:[selectedImport],baseline_bindings:{},output_protocol_digest:'0'.repeat(64)}),
 'README.md':'Public author/compiler three-package chain.',LICENSE:'Test fixture.',
 'fixtures/root-authorized.json':middle.bundle.files['fixtures/root-authorized.json'],
};
const bundle={format:PROTOCOL_PACKAGE_FORMAT,files};
const preview=previewProtocolPackage(bundle,{loadExactPackage:loader});
if(!preview.passed||preview.unresolvedRequiredInputs.length)throw Error('AUTHOR_PREVIEW');
files['release.lock.json']=JSON.stringify({...JSON.parse(files['release.lock.json']),output_protocol_digest:preview.protocolDigest});
const root=parseProtocolPackage(bundle),material={v:1,closure:createProtocolPackageClosure(root,[middle,leaf]),bindings:{}};
const compiled=compilePackageMaterial(material);
if(Object.keys(material.closure.packages).length!==3||compiled.resolvedDependencyManifests.length!==1||compiled.resolvedDependencyManifests[0].manifest.dependencies.length)throw Error('FLATTENED_SHAPE');
const nodes=compiled.resolvedDependencyManifests.map(n=>({digest:n.protocolDigest,manifest:n.manifest}));
const flatSource=manifestCanonical({...own,dependencies:nodes.map(n=>n.digest)}).manifest;
const flat=await resolveSecureProtocol(flatSource,id=>nodes.find(n=>n.digest===id)?.manifest);
if(flat.digest!==compiled.protocolDigest||!secureEqual(flat.manifest,compiled.manifest))throw Error('MATERIAL_EQUALITY');
const extraValue={...own,name:'example.nested-protocol-middle.v1',dependencies:[nodes[0].digest],protocol_roles:[],capabilities:[],role_conflicts:[],historical_role_conflicts:[],constraints:{},record_schemas:{},initial_state:{},actions:[]};
delete extraValue.state_array_types;delete extraValue.state_exports;delete extraValue.execution_requirements;
const extra=await secureManifestDigest(manifestCanonical(extraValue).manifest);
const nestedSource=manifestCanonical({...own,dependencies:[extra.digest]}).manifest;
const available=new Map([[nodes[0].digest,nodes[0].manifest],[extra.digest,extra.manifest]]);
const nested=await resolveSecureProtocol(nestedSource,id=>available.get(id));
await verifyProtocolComposition({digest:nested.digest,manifest:nested.manifest,resolved_manifest:nested.manifest,composition:nested.composition});
const sameExecutable=secureEqual({...nested.manifest,dependencies:[]},{...compiled.manifest,dependencies:[]});
if(!sameExecutable||nested.digest===compiled.protocolDigest||nested.composition.dependencies.length!==2)throw Error('DISCRIMINATOR');
writeFileSync(output,JSON.stringify({material,compiled,flat,nested},null,2)+'\n',{mode:0o600,flag:'wx'});
console.log(JSON.stringify({classification:'source_contract_only_no_HTTP_native_acceptance',author_preview_passed:preview.passed,package_import_depth:2,package_count:3,root_package_digest:root.packageDigest,middle_package_digest:middle.packageDigest,leaf_package_digest:leaf.packageDigest,compiler_version:PROTOCOL_COMPILER_VERSION,compiled_protocol_digest:compiled.protocolDigest,compiled_dependency_nodes:nodes.length,compiled_dependency_child_counts:nodes.map(n=>n.manifest.dependencies.length),flat_source_matches_material:true,raw_nested_resolver_verified:true,raw_nested_dependency_nodes:nested.composition.dependencies.length,raw_nested_protocol_digest:nested.digest,executable_equal_except_dependency_closure:sameExecutable,nested_material_digest_matches:false,nested_material_composition_matches:secureEqual(nested.composition,flat.composition)}));
