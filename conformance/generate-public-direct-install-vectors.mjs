// Direct PUBLIC install plan from the pinned integration planner. This is a
// pure planner oracle; it does not attest signed history or HTTP acceptance.
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {build} from 'esbuild';
import {createHash} from 'node:crypto';

const root = new URL('.', import.meta.url);
const tracked = new URL('../../e2ee-main-integration-20261006/src/', root);
const sourceHash = createHash('sha256').update(await readFile(new URL('workspace-protocol-install-plan.ts',tracked))).digest('hex');
if (sourceHash !== '9acf020aa02e1b8bfc429736e791d0642c798562c84b3dc75be281531f4ea77c') throw new Error('tracked install planner source changed');
const dir = await mkdtemp(join(tmpdir(), 'peerwork-direct-install-'));
try {
  const output = join(dir, 'oracle.mjs');
  await build({stdin:{contents:"export {resolveProtocolInstall,planProtocolInstall} from './workspace-protocol-install-plan.ts'; export {structurePolicyFromObjects} from './workspace-structure.ts';",resolveDir:tracked.pathname},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {resolveProtocolInstall, planProtocolInstall, structurePolicyFromObjects} = await import(pathToFileURL(output));
  const published = JSON.parse(await readFile(new URL('public-package-vectors.json',root),'utf8'));
  const presets = JSON.parse(await readFile(new URL('bootstrap-presets.json',root),'utf8'));
  const workspaceId = 'w'.repeat(43), ownerId = 'a'.repeat(43), adopterId = 'b'.repeat(43), ownerKey = 'k'.repeat(43);
  const objects = presets.entries.flatMap((entry,index) => {
    const id = String.fromCharCode(105+index).repeat(43);
    return [
      {kind:'protocols',id:entry.digest,revision:1,provenance:'AUTHOR_SIGNED',value:{workspace_id:workspaceId,digest:entry.digest,manifest:entry.manifest,resolved_manifest:entry.manifest}},
      {kind:'instances',id,revision:1,provenance:'AUTHOR_SIGNED',value:{id,workspace_id:workspaceId,protocol_digest:entry.digest,origin_entrypoint:entry.entrypoint,semantics:'peerwork.kernel.v1',state:entry.manifest.initial_state,revision:0,event_revision:0,created:1}}
    ];
  });
  const policy = {payload:{v:3,workspace_id:workspaceId,owner_id:ownerId,signing_key:ownerKey,version:1,previous_policy:null,effective_sequence:1,visibility:'PUBLIC',epoch:0,issued_at:1,structure_mode:'STRUCTURED',members:[{actor_id:ownerId,role:'MEMBER',scopes:[]},{actor_id:adopterId,role:'MEMBER',scopes:[]}],structure:structurePolicyFromObjects(objects)},signature:''};
  const checkpoint = {v:1,workspace_id:workspaceId,owner_id:ownerId,owner_key:ownerKey,sequence:1,head:'a'.repeat(64),policy_hash:'b'.repeat(64)};
  const journal = {checkpoint,policy,objects,operations:[],installations:[],trust:'PINNED',legacy:false,recoveries:[],structure:{state:'ACTIVE',records:[],heads:[]}};
  const options = {instance_id:'z'.repeat(43),entrypoint:'proposalAdoption',manifest:published.compiled_manifest,grants:[{actor_id:ownerId,actions:['proposal.propose'],protocol_roles:['AUTHOR'],capabilities:['PROPOSE']},{actor_id:adopterId,actions:['proposal.adopt'],protocol_roles:['ADOPTER'],capabilities:['ADOPT']}]};
  const resolved = await resolveProtocolInstall(journal,options);
  if (resolved.digest!==published.protocol_digest || resolved.packageSource!==undefined) throw new Error('direct install digest/source mismatch');
  const planned = await planProtocolInstall(journal,[policy],resolved,2);
  const vector = {name:'official_proposal_public_direct_install',source_commit:'f828b6c50a0a58d1e718af90f653b214adcc3328',source_sha256:sourceHash,package_digest:published.package_digest,protocol_digest:published.protocol_digest,workspace_id:workspaceId,owner_id:ownerId,instance_id:options.instance_id,entrypoint:options.entrypoint,at:2,prior_objects:objects,prior_policy:policy,checkpoint,options,resolved:{digest:resolved.digest,manifest:resolved.manifest,grants:resolved.grants,instanceId:resolved.instanceId,entrypoint:resolved.entrypoint},added:planned.added,structure:planned.structure,policy_payload:planned.payload};
  await writeFile(new URL('public-direct-install-vectors.json',root),JSON.stringify(vector,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
