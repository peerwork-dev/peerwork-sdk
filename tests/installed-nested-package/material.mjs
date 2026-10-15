// Public package author/compiler and raw protocol resolver contract witness.
import {writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createLegacyComposedInstallMaterial as createBaseMaterial} from '../legacy-owner-install-composition-material.mjs';
export async function createLegacyComposedInstallMaterial(reference){
const load=name=>import(pathToFileURL(reference+'/dist-workspace/src/'+name+'.js').href);
const {manifestCanonical,SEMANTICS}=await load('workspace-manifest');
const {previewProtocolPackage}=await load('protocol-compiler');
const {parseProtocolPackage,PROTOCOL_PACKAGE_FORMAT,PROTOCOL_SOURCE_FORMAT,PROTOCOL_METADATA_FORMAT,PROTOCOL_LOCK_FORMAT,PROTOCOL_COMPILER_VERSION}=await load('protocol-package');
const {validateProtocolPackageClosure,createProtocolPackageClosure,exactPackageLoader}=await load('protocol-package-closure');
const {compilePackageMaterial}=await load('workspace-protocol-package-source');
const {resolveSecureProtocol,secureManifestDigest,verifyProtocolComposition}=await load('workspace-secure-composition');
const {secureEqual}=await load('workspace-secure-client');
const base=await createBaseMaterial(reference);
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
return {material,sourceManifest:flatSource,dependencies:nodes,compiledManifest:compiled.manifest,protocolDigest:compiled.protocolDigest,sourceDigest:flat.composition.source_digest,compilerOwnSourceDigest:compiled.sourceDigest,composition:flat.composition,nestedPackageCount:3,nestedPackageImportDepth:2};
}
