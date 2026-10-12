// Direct signed recovery outcomes from the pinned TypeScript journal verifier.
// All keys are freshly generated test identities or fixed synthetic epoch bytes.
import {mkdtemp, rm, writeFile, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const directory = await mkdtemp(join(tmpdir(), 'peerwork-signed-recovery-'));
try {
  const source = resolve(fileURLToPath(new URL('reference/src/', import.meta.url)));
  const output = join(directory, 'oracle.mjs');
  await build({stdin: {contents: `export {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,encodeCanonicalJson,sealContent} from '${source}/workspace-secure-crypto.ts';
    export {createPolicy,createCommit,createCommitContext,secureHash,verifyJournal,prepareJournalRecovery,signSecure} from '${source}/workspace-secure-client.ts';
    export {structurePolicyFromObjects,projectStructureRecords,projectStructureHeads} from '${source}/workspace-structure.ts';
    export {prepareSecureAction} from '${source}/workspace-secure-engine.ts';`,
    resolveDir: source, sourcefile: 'oracle.ts'}, outfile: output, bundle: true,
    platform: 'node', format: 'esm', logLevel: 'silent'});
  const {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,encodeCanonicalJson,sealContent,signSecure,createPolicy,
    createCommit,createCommitContext,secureHash,verifyJournal,prepareJournalRecovery,
    structurePolicyFromObjects,projectStructureRecords,projectStructureHeads,prepareSecureAction} = await import(pathToFileURL(output));
  const identity = await createSigningIdentity();
  const recipient = await createEncryptionIdentity();
  const certificate = await certifyEncryptionKey(identity, recipient, 1, 100000);
  const workspaceId = 'r'.repeat(43);
  const policy = await createPolicy(identity, {v: 1, workspace_id: workspaceId,
    owner_id: identity.actorId, signing_key: identity.keyId, version: 1,
    previous_policy: null, effective_sequence: 1, visibility: 'PRIVATE', epoch: 1,
    members: [{actor_id: identity.actorId, certificate, role: 'OWNER', scopes: []}],
    issued_at: 2});
  const policyHash = await secureHash(policy);
  const checkpoint0 = {v: 1, workspace_id: workspaceId, owner_id: identity.actorId,
    owner_key: identity.keyId, sequence: 0, head: null, policy_hash: policyHash};
  const keyring = {v: 1, workspace_id: workspaceId,
    keys: [{epoch: 1, key: Buffer.alloc(32, 123).toString('base64url')}]};
  const bootstrap = await createCommit({identity, policy, checkpoint: checkpoint0,
    operation: {v: 1, kind: 'BOOTSTRAP', input: {}, objects: []},
    actionId: 'secure.bootstrap', instanceId: null, commandId: 'b'.repeat(43),
    issuedAt: 3, keyring});
  const checkpoint1 = {...checkpoint0, sequence: 1, head: await secureHash(bootstrap)};
  const bad = await createCommit({identity, policy, checkpoint: checkpoint1,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: [{kind: 'forbidden',
      id: 'x'.repeat(43), revision: 1, provenance: 'AUTHOR_SIGNED', value: {}}]},
    actionId: 'secure.invalid', instanceId: null, commandId: 'x'.repeat(43),
    issuedAt: 4, keyring});
  const checkpoint2 = {...checkpoint0, sequence: 2, head: await secureHash(bad)};
  const baseInput = {workspaceId, policies: [policy], commits: [bootstrap, bad],
    checkpoint: checkpoint2, keyring,
    trustedOwner: {actorId: identity.actorId, key: identity.keyId}};
  const prepared = await prepareJournalRecovery(baseInput);
  const marker = await createCommit({identity, policy, checkpoint: checkpoint2,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: 'm'.repeat(43),
    issuedAt: 5, keyring, recovery: prepared.recovery});
  const checkpoint3 = {...checkpoint0, sequence: 3, head: await secureHash(marker)};
  const wrongRoot = await createCommit({identity, policy, checkpoint: checkpoint2,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: 'n'.repeat(43),
    issuedAt: 5, keyring,
    recovery: {...prepared.recovery, excluded_root: '0'.repeat(64)}});
  const wrongRootCheckpoint = {...checkpoint0, sequence: 3, head: await secureHash(wrongRoot)};
  const valid = await createCommit({identity, policy, checkpoint: checkpoint1,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.noop', instanceId: null, commandId: 'v'.repeat(43),
    issuedAt: 4, keyring});
  const validCheckpoint2 = {...checkpoint0, sequence: 2, head: await secureHash(valid)};
  const inventedRecovery = {...prepared.recovery, through: validCheckpoint2,
    excluded_root: await secureHash([{sequence: 2, hash: validCheckpoint2.head}])};
  const inventedMarker = await createCommit({identity, policy, checkpoint: validCheckpoint2,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: 'i'.repeat(43),
    issuedAt: 5, keyring, recovery: inventedRecovery});
  const inventedCheckpoint3 = {...checkpoint0, sequence: 3,
    head: await secureHash(inventedMarker)};
  const nullableContext = {...marker.payload, migration: null,
    conversion_excluded_members: null};
  delete nullableContext.mode;
  delete nullableContext.body;
  const epochKey = await crypto.subtle.importKey('raw', Buffer.alloc(32, 123),
    {name: 'AES-GCM'}, false, ['encrypt']);
  const nullableBody = await sealContent(epochKey,
    encodeCanonicalJson({v: 1, kind: 'ADMIN', input: {}, objects: []}), nullableContext);
  const nullableMarker = await signSecure(identity, 'peerwork.secure.commit.v1',
    {...nullableContext, mode: 'PRIVATE', body: nullableBody});
  const nullableCheckpoint3 = {...checkpoint0, sequence: 3,
    head: await secureHash(nullableMarker)};
  const cases = [];
  for (const [name, commits, checkpoint] of [
    ['unrecovered_invalid_encrypted_commit', [bootstrap, bad], checkpoint2],
    ['recovered_invalid_encrypted_commit', [bootstrap, bad, marker], checkpoint3],
    ['signed_wrong_excluded_root', [bootstrap, bad, wrongRoot], wrongRootCheckpoint],
    ['invented_failure_over_valid_content', [bootstrap, valid, inventedMarker], inventedCheckpoint3],
    ['v1_null_migration_and_conversion_marker', [bootstrap, bad, nullableMarker], nullableCheckpoint3],
  ]) {
    try {
      const journal = await verifyJournal({...baseInput, commits, checkpoint});
      cases.push({name, policy, commits, checkpoint, keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: true,
        operations: journal.operations, objects: journal.objects,
        recoveries: journal.recoveries, legacy: journal.legacy,
        structure_state: journal.structure?.state ?? null});
    } catch (error) {
      cases.push({name, policy, commits, checkpoint, keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: false,
        error: String(error.message)});
    }
  }
  const policy3 = await createPolicy(identity, {v: 3, workspace_id: workspaceId,
    owner_id: identity.actorId, signing_key: identity.keyId, version: 1,
    previous_policy: null, effective_sequence: 1, visibility: 'PRIVATE', epoch: 1,
    members: [{actor_id: identity.actorId, certificate, role: 'OWNER', scopes: []}],
    issued_at: 2, protocol_format_ceiling: 1, structure_mode: 'NONE'});
  const policy3Hash = await secureHash(policy3);
  const cp30 = {...checkpoint0, policy_hash: policy3Hash};
  const boot3 = await createCommit({identity, policy: policy3, checkpoint: cp30,
    operation: {v: 1, kind: 'BOOTSTRAP', input: {}, objects: []},
    actionId: 'secure.bootstrap', instanceId: null, commandId: '3'.repeat(43),
    issuedAt: 3, keyring});
  const cp31 = {...cp30, sequence: 1, head: await secureHash(boot3)};
  const bad3 = await createCommit({identity, policy: policy3, checkpoint: cp31,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: [{kind: 'forbidden',
      id: 'z'.repeat(43), revision: 1, provenance: 'AUTHOR_SIGNED', value: {}}]},
    actionId: 'secure.invalid', instanceId: null, commandId: '4'.repeat(43),
    issuedAt: 4, keyring});
  const cp32 = {...cp30, sequence: 2, head: await secureHash(bad3)};
  const prepared3 = await prepareJournalRecovery({workspaceId, policies: [policy3],
    commits: [boot3, bad3], checkpoint: cp32, keyring,
    trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
  const marker3 = await createCommit({identity, policy: policy3, checkpoint: cp32,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: '5'.repeat(43),
    issuedAt: 5, keyring, recovery: prepared3.recovery});
  const cp33 = {...cp30, sequence: 3, head: await secureHash(marker3)};
  const hiddenContext = {...bad3.payload, command_id: 'h'.repeat(43)};
  delete hiddenContext.mode;
  delete hiddenContext.body;
  const hiddenBody = await sealContent(epochKey,
    encodeCanonicalJson({v: 1, kind: 'MIGRATE', input: {}, objects: []}), hiddenContext);
  const hiddenMigration = await signSecure(identity, 'peerwork.secure.commit.v1',
    {...hiddenContext, mode: 'PRIVATE', body: hiddenBody});
  const hiddenCp32 = {...cp30, sequence: 2, head: await secureHash(hiddenMigration)};
  const hiddenRecovery = {...prepared3.recovery, through: hiddenCp32,
    excluded_root: await secureHash([{sequence: 2, hash: hiddenCp32.head}])};
  const hiddenMarker = await createCommit({identity, policy: policy3,
    checkpoint: hiddenCp32, operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: 'j'.repeat(43),
    issuedAt: 5, keyring, recovery: hiddenRecovery});
  const hiddenCp33 = {...cp30, sequence: 3, head: await secureHash(hiddenMarker)};
  for (const [name, commits, checkpoint] of [
    ['v3_recovered_invalid_admin', [boot3, bad3, marker3], cp33],
    ['v3_hidden_decryptable_migration_denied', [boot3, hiddenMigration, hiddenMarker], hiddenCp33],
  ]) {
    try {
      const journal = await verifyJournal({workspaceId, policies: [policy3], commits,
        checkpoint, keyring,
        trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
      cases.push({name, policy: policy3, commits, checkpoint, keyring,
        workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
        ok: true, operations: journal.operations, objects: journal.objects,
        recoveries: journal.recoveries, legacy: journal.legacy,
        structure_state: journal.structure?.state ?? null});
    } catch (error) {
      cases.push({name, policy: policy3, commits, checkpoint, keyring,
        workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
        ok: false, error: String(error.message)});
    }
  }
  const structure = {v: 1, protocols: [], disclosure: [], instances: []};
  const policy2 = await createPolicy(identity, {v: 2, workspace_id: workspaceId,
    owner_id: identity.actorId, signing_key: identity.keyId, version: 1,
    previous_policy: null, effective_sequence: 1, visibility: 'PRIVATE', epoch: 1,
    members: [{actor_id: identity.actorId, certificate, role: 'OWNER', scopes: []}],
    issued_at: 2, structure});
  const cp20 = {...checkpoint0, policy_hash: await secureHash(policy2)};
  const boot2 = await createCommit({identity, policy: policy2, checkpoint: cp20,
    operation: {v: 1, kind: 'BOOTSTRAP', input: {}, objects: []},
    actionId: 'secure.bootstrap', instanceId: null, commandId: '6'.repeat(43),
    issuedAt: 3, keyring});
  const cp21 = {...cp20, sequence: 1, head: await secureHash(boot2)};
  const bad2 = await createCommit({identity, policy: policy2, checkpoint: cp21,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: [{kind: 'forbidden',
      id: 'y'.repeat(43), revision: 1, provenance: 'AUTHOR_SIGNED', value: {}}]},
    actionId: 'secure.invalid', instanceId: null, commandId: '7'.repeat(43),
    issuedAt: 4, keyring});
  const cp22 = {...cp20, sequence: 2, head: await secureHash(bad2)};
  const prepared2 = await prepareJournalRecovery({workspaceId, policies: [policy2],
    commits: [boot2, bad2], checkpoint: cp22, keyring,
    trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
  const snapshot = {source: prepared2.recovery.base,
    root: await secureHash({records: [], heads: []}), records: 0, heads: 0, offset: 0};
  const marker2 = await createCommit({identity, policy: policy2, checkpoint: cp22,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.recover', instanceId: null, commandId: '8'.repeat(43),
    issuedAt: 5, keyring, recovery: prepared2.recovery,
    structure: {v: 1, mode: 'SNAPSHOT_BEGIN', records: [], heads: [], snapshot}});
  const cp23 = {...cp20, sequence: 3, head: await secureHash(marker2)};
  try {
    const journal = await verifyJournal({workspaceId, policies: [policy2],
      commits: [boot2, bad2, marker2], checkpoint: cp23, keyring,
      trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
    cases.push({name: 'v2_structured_recovery_snapshot_base', policy: policy2,
      commits: [boot2, bad2, marker2], checkpoint: cp23, keyring,
      workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
      ok: true, operations: journal.operations, objects: journal.objects,
      recoveries: journal.recoveries, legacy: journal.legacy,
      structure_state: journal.structure?.state ?? null});
  } catch (error) {
    cases.push({name: 'v2_structured_recovery_snapshot_base', policy: policy2,
      commits: [boot2, bad2, marker2], checkpoint: cp23, keyring,
      workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
      ok: false, error: String(error.message)});
  }
  const end2 = await createCommit({identity, policy: policy2, checkpoint: cp23,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.structure.end', instanceId: null, commandId: '9'.repeat(43),
    issuedAt: 6, keyring,
    structure: {v: 1, mode: 'SNAPSHOT_END', records: [], heads: [], snapshot}});
  const cp24 = {...cp20, sequence: 4, head: await secureHash(end2)};
  const wrongEnd2 = await createCommit({identity, policy: policy2, checkpoint: cp23,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.structure.end', instanceId: null, commandId: 'w'.repeat(43),
    issuedAt: 6, keyring,
    structure: {v: 1, mode: 'SNAPSHOT_END', records: [], heads: [],
      snapshot: {...snapshot, root: '0'.repeat(64)}}});
  const wrongCp24 = {...cp20, sequence: 4, head: await secureHash(wrongEnd2)};
  for (const [name, final, finalCheckpoint] of [
    ['v2_structured_recovery_snapshot_end', end2, cp24],
    ['v2_structured_recovery_wrong_snapshot_root', wrongEnd2, wrongCp24],
  ]) {
    try {
      const commits = [boot2, bad2, marker2, final];
      const journal = await verifyJournal({workspaceId, policies: [policy2],
        commits, checkpoint: finalCheckpoint, keyring,
        trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
      cases.push({name, policy: policy2, commits, checkpoint: finalCheckpoint,
        keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId},
        ok: true, operations: journal.operations, objects: journal.objects,
        recoveries: journal.recoveries, legacy: journal.legacy,
        structure_state: journal.structure?.state ?? null});
    } catch (error) {
      cases.push({name, policy: policy2, commits: [boot2, bad2, marker2, final],
        checkpoint: finalCheckpoint, keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId},
        ok: false, error: String(error.message)});
    }
  }
  const presetFixture = JSON.parse(await readFile(new URL('./bootstrap-presets.json', import.meta.url), 'utf8'));
  const wiki = presetFixture.entries.find(entry => entry.entrypoint === 'wiki');
  const wikiInstance = 'k'.repeat(43);
  const wikiObjects = [
    {kind:'workspaces',id:workspaceId,revision:1,provenance:'AUTHOR_SIGNED',value:{
      id:workspaceId,name:'Recovery pages',visibility:'PRIVATE',owner:identity.actorId,created:3}},
    {kind:'protocols',id:wiki.digest,revision:1,provenance:'AUTHOR_SIGNED',value:{
      workspace_id:workspaceId,digest:wiki.digest,manifest:wiki.manifest,resolved_manifest:wiki.manifest}},
    {kind:'instances',id:wikiInstance,revision:1,provenance:'AUTHOR_SIGNED',value:{
      id:wikiInstance,workspace_id:workspaceId,protocol_digest:wiki.digest,
      origin_entrypoint:'wiki',semantics:'peerwork.kernel.v1',state:wiki.manifest.initial_state,
      revision:0,event_revision:0,created:3}},
  ];
  const wikiStructure = structurePolicyFromObjects(wikiObjects);
  const wikiPolicy = await createPolicy(identity,{v:2,workspace_id:workspaceId,
    owner_id:identity.actorId,signing_key:identity.keyId,version:1,previous_policy:null,
    effective_sequence:1,visibility:'PRIVATE',epoch:1,issued_at:2,structure:wikiStructure,
    members:[{actor_id:identity.actorId,certificate,role:'OWNER',scopes:[{
      instance_id:wikiInstance,actions:['wiki.create'],protocol_roles:['EDITOR'],
      capabilities:['EDIT'],expires_at:null}]}]});
  const wikiCp0 = {...checkpoint0,policy_hash:await secureHash(wikiPolicy)};
  const wikiBoot = await createCommit({identity,policy:wikiPolicy,checkpoint:wikiCp0,
    operation:{v:1,kind:'BOOTSTRAP',input:{},objects:wikiObjects},actionId:'secure.bootstrap',
    instanceId:null,commandId:'p'.repeat(43),issuedAt:3,keyring});
  const wikiCp1 = {...wikiCp0,sequence:1,head:await secureHash(wikiBoot)};
  const actionInput = {v:1,kind:'ACTION',input:{},objects:[]};
  const wikiContext = await createCommitContext({identity,policy:wikiPolicy,checkpoint:wikiCp1,
    operation:actionInput,actionId:'wiki.create',instanceId:wikiInstance,
    commandId:'q'.repeat(43),issuedAt:4});
  const wikiAction = await prepareSecureAction({objects:wikiObjects,context:wikiContext,
    policy:wikiPolicy,body:{title:'One',body:'Snapshot page'},
    allocations:[{record_id:'s'.repeat(43),entity_id:'t'.repeat(43)}]});
  const wikiActionCommit = await createCommit({identity,policy:wikiPolicy,checkpoint:wikiCp1,
    operation:wikiAction,actionId:'wiki.create',instanceId:wikiInstance,
    commandId:'q'.repeat(43),issuedAt:4,keyring});
  const wikiCp2 = {...wikiCp0,sequence:2,head:await secureHash(wikiActionCommit)};
  const wikiBad = await createCommit({identity,policy:wikiPolicy,checkpoint:wikiCp2,
    operation:{v:1,kind:'ADMIN',input:{},objects:[{kind:'forbidden',id:'u'.repeat(43),
      revision:1,provenance:'AUTHOR_SIGNED',value:{}}]},actionId:'secure.invalid',
    instanceId:null,commandId:'v'.repeat(43),issuedAt:5,keyring});
  const wikiCp3 = {...wikiCp0,sequence:3,head:await secureHash(wikiBad)};
  const wikiPrepared = await prepareJournalRecovery({workspaceId,policies:[wikiPolicy],
    commits:[wikiBoot,wikiActionCommit,wikiBad],checkpoint:wikiCp3,keyring,
    trustedOwner:{actorId:identity.actorId,key:identity.keyId}});
  const wikiPriorObjects = [...wikiObjects,...wikiAction.objects];
  const wikiRecords = projectStructureRecords(wikiPriorObjects,wikiStructure)
    .sort((a,b)=>a.record_id<b.record_id?-1:a.record_id>b.record_id?1:0);
  const wikiHeads = projectStructureHeads(wikiPriorObjects)
    .sort((a,b)=>a.entity_id<b.entity_id?-1:a.entity_id>b.entity_id?1:0);
  const wikiSnapshot = {source:wikiPrepared.recovery.base,
    root:await secureHash({records:wikiRecords,heads:wikiHeads}),
    records:wikiRecords.length,heads:wikiHeads.length,offset:0};
  let wikiCursor = wikiCp3;
  const wikiPages = [];
  for (const [actionId,mode,records,heads,offset,recovery] of [
    ['secure.recover','SNAPSHOT_BEGIN',[],[],0,wikiPrepared.recovery],
    ['secure.structure.page','SNAPSHOT_PAGE',wikiRecords,[],0,undefined],
    ['secure.structure.page','SNAPSHOT_PAGE',[],wikiHeads,wikiRecords.length,undefined],
    ['secure.structure.end','SNAPSHOT_END',[],[],wikiRecords.length+wikiHeads.length,undefined],
  ]) {
    const commit = await createCommit({identity,policy:wikiPolicy,checkpoint:wikiCursor,
      operation:{v:1,kind:'ADMIN',input:{},objects:[]},actionId,instanceId:null,
      commandId:String(wikiPages.length).repeat(43),issuedAt:6+wikiPages.length,keyring,
      structure:{v:1,mode,records,heads,snapshot:{...wikiSnapshot,offset}},
      ...(recovery?{recovery}:{})});
    wikiPages.push(commit);
    wikiCursor = {...wikiCp0,sequence:wikiCursor.sequence+1,head:await secureHash(commit)};
  }
  const wikiCommits = [wikiBoot,wikiActionCommit,wikiBad,...wikiPages];
  try {
    const journal = await verifyJournal({workspaceId,policies:[wikiPolicy],
      commits:wikiCommits,checkpoint:wikiCursor,keyring,
      trustedOwner:{actorId:identity.actorId,key:identity.keyId}});
    cases.push({name:'v2_recovery_nonempty_record_and_head_pages',policy:wikiPolicy,
      commits:wikiCommits,checkpoint:wikiCursor,keyring,workspace_id:workspaceId,
      owner:{actor_id:identity.actorId,key:identity.keyId},ok:true,
      operations:journal.operations,objects:journal.objects,recoveries:journal.recoveries,
      legacy:journal.legacy,structure_state:journal.structure?.state??null,
      structure_records:journal.structure?.records??null,
      structure_heads:journal.structure?.heads??null});
  } catch (error) {
    cases.push({name:'v2_recovery_nonempty_record_and_head_pages',policy:wikiPolicy,
      commits:wikiCommits,checkpoint:wikiCursor,keyring,workspace_id:workspaceId,
      owner:{actor_id:identity.actorId,key:identity.keyId},ok:false,error:String(error.message)});
  }
  const wikiCp4 = {...wikiCp0,sequence:4,head:await secureHash(wikiPages[0])};
  const headFirst = await createCommit({identity,policy:wikiPolicy,checkpoint:wikiCp4,
    operation:{v:1,kind:'ADMIN',input:{},objects:[]},
    actionId:'secure.structure.page',instanceId:null,commandId:'z'.repeat(43),
    issuedAt:7,keyring,structure:{v:1,mode:'SNAPSHOT_PAGE',records:[],heads:wikiHeads,
      snapshot:{...wikiSnapshot,offset:0}}});
  const headFirstCp = {...wikiCp0,sequence:5,head:await secureHash(headFirst)};
  const headFirstCommits = [wikiBoot,wikiActionCommit,wikiBad,wikiPages[0],headFirst];
  try {
    const journal = await verifyJournal({workspaceId,policies:[wikiPolicy],
      commits:headFirstCommits,checkpoint:headFirstCp,keyring,
      trustedOwner:{actorId:identity.actorId,key:identity.keyId}});
    cases.push({name:'v2_recovery_head_page_before_record_denied',policy:wikiPolicy,
      commits:headFirstCommits,checkpoint:headFirstCp,keyring,workspace_id:workspaceId,
      owner:{actor_id:identity.actorId,key:identity.keyId},ok:true,
      operations:journal.operations,objects:journal.objects,recoveries:journal.recoveries,
      legacy:journal.legacy,structure_state:journal.structure?.state??null});
  } catch (error) {
    cases.push({name:'v2_recovery_head_page_before_record_denied',policy:wikiPolicy,
      commits:headFirstCommits,checkpoint:headFirstCp,keyring,workspace_id:workspaceId,
      owner:{actor_id:identity.actorId,key:identity.keyId},ok:false,error:String(error.message)});
  }
  await writeFile(new URL('./signed-recovery-vectors.json', import.meta.url),
    `${JSON.stringify({prepared: {recovery: prepared.recovery,
      failure_code: prepared.failure_code}, cases}, null, 2)}\n`);
} finally {
  await rm(directory, {recursive: true, force: true});
}
