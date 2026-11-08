// Bounded pure public f828 contract witness; no service/native call or source edit.
import {pathToFileURL} from 'node:url';
import {createLegacyComposedInstallMaterial} from './legacy-owner-install-composition-material.mjs';
const reference=process.argv[2];if(!reference)throw Error('reference root required');
const load=name=>import(pathToFileURL(reference+'/dist-workspace/src/'+name+'.js').href);
const {manifestCanonical}=await load('workspace-manifest');
const {secureManifestDigest,resolveSecureProtocol,verifyProtocolComposition}=await load('workspace-secure-composition');
const {compilePackageMaterial}=await load('workspace-protocol-package-source');
const {secureEqual}=await load('workspace-secure-client');
const base=await createLegacyComposedInstallMaterial(reference);
if(base.dependencies.length!==1||base.dependencies[0].manifest.dependencies.length!==0)throw Error('baseline dependency shape');
const leaf=base.dependencies[0];
const middleValue={...base.sourceManifest,name:'example.nested-implicit.middle.v1',dependencies:[leaf.digest],
 protocol_roles:[],capabilities:[],role_conflicts:[],historical_role_conflicts:[],constraints:{},record_schemas:{},initial_state:{},actions:[]};
delete middleValue.state_array_types;delete middleValue.state_exports;delete middleValue.execution_requirements;
const middle=await secureManifestDigest(manifestCanonical(middleValue).manifest);
const source=manifestCanonical({...base.sourceManifest,dependencies:[middle.digest]}).manifest;
const nodes=new Map([[leaf.digest,leaf.manifest],[middle.digest,middle.manifest]]);
const resolved=await resolveSecureProtocol(source,digest=>nodes.get(digest));
await verifyProtocolComposition({digest:resolved.digest,manifest:resolved.manifest,resolved_manifest:resolved.manifest,composition:resolved.composition});
if(resolved.composition.dependencies.length!==2||resolved.composition.dependencies.find(n=>n.digest===middle.digest)?.manifest.dependencies[0]!==leaf.digest)throw Error('not a nested protocol graph');
const compiled=compilePackageMaterial(base.material);
const sameExceptDependencies=(a,b)=>secureEqual({...a,dependencies:[]},{...b,dependencies:[]});
if(!sameExceptDependencies(resolved.manifest,compiled.manifest))throw Error('unexpected executable difference');
if(resolved.digest===compiled.protocolDigest||secureEqual(resolved.composition,base.composition))throw Error('nested provenance unexpectedly equals flattened package');
console.log(JSON.stringify({classification:'pure_f828_resolver_valid_not_HTTP_or_native_acceptance',
 leaf_digest:leaf.digest,middle_source_digest:middle.digest,nested_source_digest:resolved.composition.source_digest,
 nested_protocol_digest:resolved.digest,material_compiled_digest:compiled.protocolDigest,
 nested_dependency_count:resolved.composition.dependencies.length,material_dependency_count:compiled.resolvedDependencyManifests.length,
 middle_declares_leaf:true,explicit_options_dependencies:'omitted in the proposed install',
 executable_equal_except_dependency_closure:true,exact_material_digest_matches_nested:false,
 exact_composition_matches_nested:false,source_manifest:source,composition:resolved.composition},null,2));
