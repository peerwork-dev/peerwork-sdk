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
  await build({stdin:{contents:"export {resolveProtocolInstall,planProtocolInstall} from './workspace-protocol-install-plan.ts'; export {structurePolicyFromObjects,structureSnapshotData,projectStructureRecords,projectStructureHeads} from './workspace-structure.ts'; export {secureHash} from './workspace-secure-client.ts';",resolveDir:tracked.pathname},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {resolveProtocolInstall, planProtocolInstall, structurePolicyFromObjects, structureSnapshotData, projectStructureRecords, projectStructureHeads, secureHash} = await import(pathToFileURL(output));
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
  const policy = {payload:{v:3,workspace_id:workspaceId,owner_id:ownerId,signing_key:ownerKey,version:1,previous_policy:null,effective_sequence:1,visibility:'PUBLIC',epoch:0,issued_at:1,structure_mode:'STRUCTURED',protocol_format_ceiling:1,members:[{actor_id:ownerId,role:'MEMBER',scopes:[]},{actor_id:adopterId,role:'MEMBER',scopes:[]}],structure:structurePolicyFromObjects(objects)},signature:''};
  const checkpoint = {v:1,workspace_id:workspaceId,owner_id:ownerId,owner_key:ownerKey,sequence:1,head:'a'.repeat(64),policy_hash:'b'.repeat(64)};
  const journal = {checkpoint,policy,objects,operations:[],installations:[],trust:'PINNED',legacy:false,recoveries:[],structure:{state:'ACTIVE',records:[],heads:[]}};
  const options = {instance_id:'z'.repeat(43),entrypoint:'proposalAdoption',manifest:published.compiled_manifest,grants:[{actor_id:ownerId,actions:['proposal.propose'],protocol_roles:['AUTHOR'],capabilities:['PROPOSE']},{actor_id:adopterId,actions:['proposal.adopt'],protocol_roles:['ADOPTER'],capabilities:['ADOPT']}]};
  const resolved = await resolveProtocolInstall(journal,options);
  if (resolved.digest!==published.protocol_digest || resolved.packageSource!==undefined) throw new Error('direct install digest/source mismatch');
  const planned = await planProtocolInstall(journal,[policy],resolved,2);
  const data=structureSnapshotData({records:new Map(),heads:new Map()});
  const snapshot={source:checkpoint,root:await secureHash(data),records:0,heads:0,offset:0};
  const begin_operation={v:1,kind:'ADMIN',input:{install:{instance_id:options.instance_id,protocol_digest:resolved.digest,entrypoint:options.entrypoint}},objects:planned.added};
  const begin_structure={v:1,mode:'SNAPSHOT_BEGIN',records:[],heads:[],snapshot};
  const vector = {name:'official_proposal_public_direct_install',source_commit:'f828b6c50a0a58d1e718af90f653b214adcc3328',source_sha256:sourceHash,package_digest:published.package_digest,protocol_digest:published.protocol_digest,workspace_id:workspaceId,owner_id:ownerId,instance_id:options.instance_id,entrypoint:options.entrypoint,at:2,prior_objects:objects,prior_policy:policy,checkpoint,options,resolved:{digest:resolved.digest,manifest:resolved.manifest,grants:resolved.grants,instanceId:resolved.instanceId,entrypoint:resolved.entrypoint},added:planned.added,structure:planned.structure,policy_payload:planned.payload,begin_operation,begin_structure};
  await writeFile(new URL('public-direct-install-vectors.json',root),JSON.stringify(vector,null,2)+'\n');

  // A valid prior discussion record and selected head force an authenticated
  // multi-step snapshot, rather than the empty first-install shortcut.
  const discussion = presets.entries.find(entry=>entry.entrypoint==='discussion');
  const discussionIndex = presets.entries.findIndex(entry=>entry.entrypoint==='discussion');
  const discussionInstance = String.fromCharCode(105+discussionIndex).repeat(43);
  const recordId='r'.repeat(43), entityId='e'.repeat(43);
  const record={kind:'records',id:recordId,revision:1,provenance:'AUTHOR_SIGNED',value:{id:recordId,workspace_id:workspaceId,instance_id:discussionInstance,protocol_digest:discussion.digest,entity_id:entityId,schema_ref:'wiki.revision',actor_id:ownerId,created:2,payload:{title:'Prior discussion',body:'Authenticated prior history',source_refs:[],author:ownerId},revision:1}};
  const head={kind:'entity_heads',id:entityId,revision:1,provenance:'AUTHOR_SIGNED',value:{entity_id:entityId,workspace_id:workspaceId,instance_id:discussionInstance,record_id:recordId,revision:1,updated:2}};
  const priorObjects=[...objects,record,head];
  const priorContract=structurePolicyFromObjects(priorObjects);
  const priorData=structureSnapshotData({records:new Map(projectStructureRecords(priorObjects,priorContract).map(row=>[row.record_id,row])),heads:new Map(projectStructureHeads(priorObjects).map(row=>[row.entity_id,row]))});
  const nonemptyJournal={...journal,objects:priorObjects,structure:{state:'ACTIVE',...priorData}};
  const nonemptyPolicy={...policy,payload:{...policy.payload,structure:priorContract}};
  nonemptyJournal.policy=nonemptyPolicy;
  const nonemptyResolved=await resolveProtocolInstall(nonemptyJournal,options);
  const nonemptyPlanned=await planProtocolInstall(nonemptyJournal,[nonemptyPolicy],nonemptyResolved,3);
  const projected=structureSnapshotData({records:new Map(projectStructureRecords(priorObjects,nonemptyPlanned.structure).map(row=>[row.record_id,row])),heads:new Map(projectStructureHeads(priorObjects).map(row=>[row.entity_id,row]))});
  const nonemptySnapshot={source:checkpoint,root:await secureHash(projected),records:projected.records.length,heads:projected.heads.length,offset:0};
  const nonempty={name:'official_proposal_public_direct_install_nonempty_prior',source_commit:vector.source_commit,source_sha256:sourceHash,package_digest:published.package_digest,protocol_digest:published.protocol_digest,workspace_id:workspaceId,owner_id:ownerId,instance_id:options.instance_id,entrypoint:options.entrypoint,at:3,prior_objects:priorObjects,prior_policy:nonemptyPolicy,checkpoint,options,added:nonemptyPlanned.added,structure:nonemptyPlanned.structure,policy_payload:nonemptyPlanned.payload,projected,snapshot:nonemptySnapshot};
  await writeFile(new URL('public-direct-install-nonempty-vectors.json',root),JSON.stringify(nonempty,null,2)+'\n');
} finally {await rm(dir,{recursive:true,force:true});}
