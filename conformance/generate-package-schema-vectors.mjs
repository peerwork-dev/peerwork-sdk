// Direct package schema oracle cases from the pinned TypeScript implementation.
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
const dir=await mkdtemp(join(tmpdir(),'peerwork-package-schema-'));
try {
 const output=join(dir,'oracle.mjs');
 await build({stdin:{contents:`export {parseProtocolPackage} from './protocol-package.ts';`,resolveDir:resolve(source)},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
 const {parseProtocolPackage}=await import(pathToFileURL(output));
 const cases=[];
 const capture=(name,kind,candidate,valid)=>{
   try {
     const parsed=parseProtocolPackage(candidate);
     if(!valid)throw new Error(`unexpected valid ${name}`);
     const input=kind==='source'?JSON.parse(candidate.files['protocol.source.json']):kind==='metadata'?JSON.parse(candidate.files['package.json']):kind==='lock'?JSON.parse(candidate.files['release.lock.json']):JSON.parse(candidate.files[Object.keys(candidate.files).find(p=>p.startsWith('fixtures/')&&p.endsWith('.json'))]);
     const normalized=kind==='fixture'?parsed.fixtures.find(item=>item.id===input.id):parsed[{source:'source',metadata:'metadata',lock:'lock'}[kind]];
     cases.push({name,kind,valid:true,input,normalized});
   } catch(error) {
     if(valid)throw error;
     cases.push({name,kind,valid:false,input:kind==='source'?JSON.parse(candidate.files['protocol.source.json']):kind==='metadata'?JSON.parse(candidate.files['package.json']):kind==='lock'?JSON.parse(candidate.files['release.lock.json']):JSON.parse(candidate.files[Object.keys(candidate.files).find(p=>p.startsWith('fixtures/')&&p.endsWith('.json'))])});
   }
 };
 const vary=(kind,edit)=>{const b=structuredClone(bundle);const path={source:'protocol.source.json',metadata:'package.json',lock:'release.lock.json'}[kind];const files=kind==='fixture'?Object.keys(b.files).filter(p=>p.startsWith('fixtures/')&&p.endsWith('.json')):[path];for(const file of files){const value=JSON.parse(b.files[file]);edit(value,file);b.files[file]=JSON.stringify(value);if(kind==='fixture')break;}return b;};
const varySourceAndLock=(editSource,editLock=()=>{})=>{const b=structuredClone(bundle);const source=JSON.parse(b.files['protocol.source.json']);const lock=JSON.parse(b.files['release.lock.json']);editSource(source);editLock(lock);b.files['protocol.source.json']=JSON.stringify(source);b.files['release.lock.json']=JSON.stringify(lock);return b;};
 capture('source_defaults','source',vary('source',s=>{delete s.imports;delete s.parameters;delete s.exports;delete s.bindings;delete s.derive;}),true);
 capture('source_parameter_required_default','source',vary('source',s=>{s.parameters=[{name:'mode',type:'enum',values:['A','B']}];s.exports=[{slot:'selectedMode',parameter:'mode'}]}),true);
capture('source_parameter_local_binding_without_export','source',vary('source',s=>{s.parameters=[{name:'mode',type:'enum',values:['A'],binding:{kind:'protocol_role_guard',action_id:'proposal.propose',variant_index:0,guard_index:0}}];s.exports=[]}),true);
capture('source_parent_binding_does_not_bind_parameter','source',varySourceAndLock(s=>{s.imports=[{alias:'dep',package_digest:'a'.repeat(64),namespace:'dep'}];s.parameters=[{name:'mode',type:'enum',values:['A']}];s.exports=[];s.bindings=[{parameter:'mode',import_alias:'dep',slot:'selected'}]},l=>{l.dependencies=[{alias:'dep',package_digest:'a'.repeat(64),namespace:'dep'}]}),false);
for(const [name,slot] of [['source_parent_binding_empty_slot',''],['source_parent_binding_oversize_slot','x'.repeat(121)]])capture(name,'source',varySourceAndLock(s=>{s.imports=[{alias:'dep',package_digest:'a'.repeat(64),namespace:'dep'}];s.parameters=[{name:'mode',type:'enum',values:['A'],binding:{kind:'protocol_role_guard',action_id:'proposal.propose',variant_index:0,guard_index:0}}];s.exports=[];s.bindings=[{parameter:'mode',import_alias:'dep',slot}]},l=>{l.dependencies=[{alias:'dep',package_digest:'a'.repeat(64),namespace:'dep'}]}),false);
 capture('source_interfaces_defaults','source',vary('source',s=>{s.format='peerwork.protocol-source.v2';s.interfaces={}}),true);
 capture('metadata_valid','metadata',bundle,true);
 capture('metadata_lone_surrogate_string','metadata',vary('metadata',m=>{m.description='valid lone surrogate \ud800'}),true);
 capture('lock_valid','lock',bundle,true);
capture('lock_compiler_version_allows_surrogate','lock',vary('lock',l=>{l.compiler_version='compiler\ud800'}),true);
 capture('fixture_defaults','fixture',vary('fixture',f=>{delete f.exact_inputs;delete f.auth.workspaceRoles;delete f.auth.protocolRoles;delete f.auth.capabilities;}),true);
capture('fixture_plain_action_id_allows_surrogate','fixture',vary('fixture',f=>{f.action_id='action\ud800'}),true);
 capture('fixture_duplicate_auth_strings','fixture',vary('fixture',f=>{f.auth.protocolRoles=['R','R']}),true);
 capture('source_unknown_member','source',vary('source',s=>{s.unknown=true}),false);
 capture('source_enum_requires_values','source',vary('source',s=>{s.parameters=[{name:'mode',type:'enum',required:false}];s.exports=[{slot:'modeValue',parameter:'mode'}]}),false);
 capture('source_unsafe_integer','source',vary('source',s=>{s.parameters=[{name:'count',type:'integer',minimum:9007199254740992,required:false}];s.exports=[{slot:'countValue',parameter:'count'}]}),false);
 capture('source_v2_requires_interfaces','source',vary('source',s=>{s.format='peerwork.protocol-source.v2'}),false);
 capture('metadata_unknown_member','metadata',vary('metadata',m=>{m.extra='reject'}),false);
 capture('lock_bad_digest','lock',vary('lock',l=>{l.output_protocol_digest='A'.repeat(64)}),false);
 capture('fixture_unknown_member','fixture',vary('fixture',f=>{f.unknown=true}),false);
 capture('fixture_unsafe_time','fixture',vary('fixture',f=>{f.time_ms=9007199254740992}),false);
 await writeFile(join(root,'package-schema-vectors.json'),JSON.stringify({format:'peerwork.package-schema-vectors.v1',oracle:{commit:'dd8a9d2',protocol_package_blob:'9902100352cd6db99919b16580bbb513d6a57f7f',zod:'4.5.4'},cases},null,2)+'\n');
} finally { await rm(dir,{recursive:true,force:true}); }
