// Read-only reconciliation of retained signed service artifacts; no HTTP client.
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const [root,reference]=process.argv.slice(2),load=n=>import(pathToFileURL(reference+'/dist-workspace/src/'+n+'.js').href);
const {verifyJournal,secureEqual}=await load('workspace-secure-client');
const {compilePackageMaterial}=await load('workspace-protocol-package-source');
const fixture=JSON.parse(readFileSync(root+'/host-fixture.json')),i=fixture.sources[0];
const state=JSON.parse(readFileSync(root+'/source-removed/'+i.state_path.split('/').at(-1)));
const material=JSON.parse(readFileSync(root+'/source-removed/'+i.material_path.split('/').at(-1)));
const input=JSON.parse(readFileSync(root+'/offline-signed-input.json'));
const local=state.workspaces[i.workspace_id];
const journal=await verifyJournal({...input,trustedOwner:{actorId:i.owner_actor_id,key:i.owner_key_id},pinned:local.checkpoint,keyring:local.keyring});
const compiled=compilePackageMaterial(material);
if(journal.structure.state!=='ACTIVE'||journal.checkpoint.sequence!==10)throw Error('offline signed ACTIVE10 required');
const protocols=journal.objects.filter(o=>o.kind==='protocols'&&o.id===i.protocol_digest);
const instances=journal.objects.filter(o=>o.kind==='instances'&&o.id===i.instance_id);
if(protocols.length!==1||!instances.length||compiled.protocolDigest!==i.protocol_digest
 ||!secureEqual(protocols[0].value.manifest,compiled.manifest)||!secureEqual(protocols[0].value.resolved_manifest,compiled.manifest)
 ||!secureEqual(protocols[0].value.package_source,i.package_source)
 ||instances.some(o=>o.value.protocol_digest!==i.protocol_digest||o.value.origin_entrypoint!==i.entrypoint||!secureEqual(o.value.package_source,i.package_source)))throw Error('offline compiled protocol/source/instance mismatch');
writeFileSync(root+'/offline-verified-read.json',JSON.stringify({checkpoint:journal.checkpoint,structure:journal.structure,objects:journal.objects}),{mode:0o600});
console.log(JSON.stringify({offline_signed_replay:true,source_floor:local.checkpoint.sequence,final_sequence:10,structure:'ACTIVE',full_compiler_manifest:true,original_package_proof:true,instance_binding:true,network_calls:0}));
