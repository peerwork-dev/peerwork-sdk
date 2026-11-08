// Direct, writer-generated multi-effect ACTION through the pinned TypeScript
// journal verifier. Fresh test keys and fixed synthetic epoch bytes only.
import {mkdtemp, rm, writeFile, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const directory = await mkdtemp(join(tmpdir(), 'peerwork-signed-many-'));
try {
  const source = resolve(fileURLToPath(new URL('reference/src/', import.meta.url)));
  const output = join(directory, 'oracle.mjs');
  await build({stdin: {contents: `
    export {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey} from '${source}/workspace-secure-crypto.ts';
    export {createPolicy,createCommit,createCommitContext,secureHash,verifyJournal,verifiedJournalAction} from '${source}/workspace-secure-client.ts';
    export {secureManifestDigest} from '${source}/workspace-secure-composition.ts';
    export {prepareSecureAction} from '${source}/workspace-secure-engine.ts';`,
    resolveDir: source, sourcefile: 'oracle.ts'}, outfile: output, bundle: true,
    platform: 'node', format: 'esm', logLevel: 'silent'});
  const {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,
    createPolicy,createCommit,createCommitContext,secureHash,verifyJournal,
    verifiedJournalAction,secureManifestDigest,prepareSecureAction} = await import(pathToFileURL(output));
  const preset = JSON.parse(await readFile(new URL('./bootstrap-presets.json', import.meta.url), 'utf8'));
  const wiki = preset.entries.find(entry => entry.entrypoint === 'wiki');
  const manifest = structuredClone(wiki.manifest);
  const action = manifest.actions.find(entry => entry.id === 'wiki.create');
  const second = structuredClone(action.variants[0].effects[0]);
  second.recordSlot = 'second';
  second.entity = {mode:'new',slot:'second'};
  action.variants[0].effects.push(second);
  action.revisionEffects.contentEntities.push('second');
  const {digest} = await secureManifestDigest(manifest);
  const identity = await createSigningIdentity();
  const recipient = await createEncryptionIdentity();
  const certificate = await certifyEncryptionKey(identity,recipient,1,100000);
  const workspaceId = 'm'.repeat(43);
  const instanceId = 'i'.repeat(43);
  const objects = [
    {kind:'workspaces',id:workspaceId,revision:1,provenance:'AUTHOR_SIGNED',value:{
      id:workspaceId,name:'Signed many effects',visibility:'PRIVATE',owner:identity.actorId,created:3}},
    {kind:'protocols',id:digest,revision:1,provenance:'AUTHOR_SIGNED',value:{
      workspace_id:workspaceId,digest,manifest,resolved_manifest:manifest}},
    {kind:'instances',id:instanceId,revision:1,provenance:'AUTHOR_SIGNED',value:{
      id:instanceId,workspace_id:workspaceId,protocol_digest:digest,
      origin_entrypoint:'wiki',semantics:'peerwork.kernel.v1',state:manifest.initial_state,
      revision:0,event_revision:0,created:3}},
  ];
  const policy = await createPolicy(identity,{v:1,workspace_id:workspaceId,
    owner_id:identity.actorId,signing_key:identity.keyId,version:1,
    previous_policy:null,effective_sequence:1,visibility:'PRIVATE',epoch:1,
    issued_at:2,members:[{actor_id:identity.actorId,certificate,role:'OWNER',scopes:[{
      instance_id:instanceId,actions:['wiki.create'],protocol_roles:['EDITOR'],
      capabilities:['EDIT'],expires_at:null}]}]});
  const checkpoint0 = {v:1,workspace_id:workspaceId,owner_id:identity.actorId,
    owner_key:identity.keyId,sequence:0,head:null,policy_hash:await secureHash(policy)};
  const keyring = {v:1,workspace_id:workspaceId,
    keys:[{epoch:1,key:Buffer.alloc(32,99).toString('base64url')}]};
  const bootstrap = await createCommit({identity,policy,checkpoint:checkpoint0,
    operation:{v:1,kind:'BOOTSTRAP',input:{},objects},actionId:'secure.bootstrap',
    instanceId:null,commandId:'b'.repeat(43),issuedAt:3,keyring});
  const checkpoint1 = {...checkpoint0,sequence:1,head:await secureHash(bootstrap)};
  const context = await createCommitContext({identity,policy,checkpoint:checkpoint1,
    operation:{v:1,kind:'ACTION',input:{},objects:[]},actionId:'wiki.create',
    instanceId,commandId:'a'.repeat(43),issuedAt:4});
  const operation = await prepareSecureAction({objects,context,policy,
    body:{title:'Two',body:'Writer-generated multi effect'},allocations:[
      {record_id:'r'.repeat(43),entity_id:'e'.repeat(43)},
      {record_id:'s'.repeat(43),entity_id:'f'.repeat(43)}]});
  const actionCommit = await createCommit({identity,policy,checkpoint:checkpoint1,
    operation,actionId:'wiki.create',instanceId,commandId:'a'.repeat(43),issuedAt:4,keyring});
  const checkpoint = {...checkpoint0,sequence:2,head:await secureHash(actionCommit)};
  const journal = await verifyJournal({workspaceId,policies:[policy],
    commits:[bootstrap,actionCommit],checkpoint,keyring,
    trustedOwner:{actorId:identity.actorId,key:identity.keyId}});
  const receipt = verifiedJournalAction(journal,actionCommit.payload.command_id);
  if(receipt.effects.length !== 2)throw Error(`expected two writer effects, got ${receipt.effects.length}`);
  const wrongOperation = structuredClone(operation);
  wrongOperation.objects.find(object=>object.kind==='entity_heads').value.record_id = 'z'.repeat(43);
  const wrongHeadCommit = await createCommit({identity,policy,checkpoint:checkpoint1,
    operation:wrongOperation,actionId:'wiki.create',instanceId,
    commandId:'a'.repeat(43),issuedAt:4,keyring});
  const wrongHeadCheckpoint = {...checkpoint0,sequence:2,head:await secureHash(wrongHeadCommit)};
  let wrongHeadError;
  try {
    await verifyJournal({workspaceId,policies:[policy],commits:[bootstrap,wrongHeadCommit],
      checkpoint:wrongHeadCheckpoint,keyring,
      trustedOwner:{actorId:identity.actorId,key:identity.keyId}});
    throw Error('re-signed wrong produced head unexpectedly accepted');
  } catch(error) { wrongHeadError = String(error.message); }
  await writeFile(new URL('./signed-many-action-vectors.json', import.meta.url),
    `${JSON.stringify({workspace_id:workspaceId,owner:{actor_id:identity.actorId,key:identity.keyId},
      policies:[policy],commits:[bootstrap,actionCommit],checkpoint,keyring,
      objects:journal.objects,operations:journal.operations,receipt,
      wrong_head:{commits:[bootstrap,wrongHeadCommit],checkpoint:wrongHeadCheckpoint,
        error:wrongHeadError}},null,2)}\n`);
} finally {
  await rm(directory,{recursive:true,force:true});
}
