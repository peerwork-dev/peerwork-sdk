import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';

const root = process.argv[2];
if (!root) throw new Error('REFERENCE_ROOT_REQUIRED');
const load = name => import(pathToFileURL(resolve(root, 'dist-workspace/src', `${name}.js`)).href);
const {manifestCanonical, SEMANTICS} = await load('workspace-manifest');
const {previewProtocolPackage} = await load('protocol-compiler');
const {
  parseProtocolPackage, PROTOCOL_COMPILER_VERSION, PROTOCOL_LOCK_FORMAT,
  PROTOCOL_METADATA_FORMAT, PROTOCOL_PACKAGE_FORMAT, PROTOCOL_SOURCE_FORMAT,
} = await load('protocol-package');
const {createProtocolPackageClosure} = await load('protocol-package-closure');
const {compilePackageMaterial} = await load('workspace-protocol-package-source');

// Mirrors the source-valid typed()/material() package in the pinned format-two test.
const manifest = manifestCanonical({
  name:'Typed state', display_version:'1', semantics:SEMANTICS, dependencies:[], format_version:2,
  initial_state:{data:[],refs:[]},
  state_array_types:[{path:['data'],kind:'json'},{path:['refs'],kind:'exact_ref_list'}],
  record_schemas:{item:{type:'object',fields:{label:'string'},required:['label'],max_bytes:1024}},
  actions:[
    {id:'replace',reads:[],writes:[['data']],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[],effects:[{op:'set',path:['data'],value:{from:'body',path:['value']}}]}]},
    {id:'produce',reads:[],writes:[['refs']],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[],effects:[{op:'append',schema:'item',recordSlot:'created',value:{from:'literal',value:{label:'private typed record'}},relations:[]},{op:'set',path:['refs'],value:{from:'array',items:[{from:'produced_ref',slot:'created'}]}}]}]},
    {id:'consume',reads:[['refs']],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[{op:'exact_ref_list',source:'state',path:['refs'],schema:'item',scope:'INSTANCE',max:8}],effects:[]}]},
  ],
}).manifest;
const auth={actorId:'A'.repeat(43),workspaceRoles:[],protocolRoles:[],capabilities:[]};
const pkg=(name,sourceManifest,dependencies=[])=>{
  const imports=dependencies.map(dependency=>({alias:'lib',namespace:'lib',package_digest:dependency.packageDigest}));
  const fixture={id:'replace',action_id:dependencies.length?'lib.replace':'replace',state:{},body:{value:[1]},auth,exact_inputs:[],expected:{accepted:true}};
  const files={
    'package.json':JSON.stringify({format:PROTOCOL_METADATA_FORMAT,package_id:name,version:'1.0.0',name,description:'Typed private source',license:'Apache-2.0',license_file:'LICENSE',source_maintainers:[{name:'Test'}]}),
    'protocol.source.json':JSON.stringify({format:PROTOCOL_SOURCE_FORMAT,semantics:SEMANTICS,manifest:sourceManifest,imports,parameters:[],exports:[],bindings:[],derive:[]}),
    'release.lock.json':JSON.stringify({format:PROTOCOL_LOCK_FORMAT,compiler_version:PROTOCOL_COMPILER_VERSION,semantics:SEMANTICS,dependencies:imports,baseline_bindings:{},output_protocol_digest:'0'.repeat(64)}),
    'README.md':'Synthetic format-two source.','LICENSE':'Test fixture.',
    'fixtures/replace.json':JSON.stringify(fixture),
  };
  const bundle={format:PROTOCOL_PACKAGE_FORMAT,files};
  const preview=previewProtocolPackage(bundle,{loadExactPackage:digest=>dependencies.find(p=>p.packageDigest===digest)});
  assert.equal(preview.passed,true);
  files['release.lock.json']=JSON.stringify({...JSON.parse(files['release.lock.json']),output_protocol_digest:preview.protocolDigest});
  return parseProtocolPackage(bundle);
};
const leaf=pkg('typed-leaf',manifest);
const rootPackage=pkg('typed-root',{name:'Typed imports',display_version:'1',semantics:SEMANTICS,dependencies:[],initial_state:{},record_schemas:{},actions:[]},[leaf]);
const material={v:1,closure:createProtocolPackageClosure(rootPackage,[leaf]),bindings:{}};
const compiled=compilePackageMaterial(material);
assert.equal(compiled.manifest.format_version,2);
assert.equal(compiled.fixtureResults.length,2);
process.stdout.write(JSON.stringify({material,root_package_digest:material.closure.root_package_digest,protocol_digest:compiled.protocolDigest}));
