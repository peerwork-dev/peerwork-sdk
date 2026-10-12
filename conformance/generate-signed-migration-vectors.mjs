// Signed v1 migration journal oracle from the pinned TS verifier. PRIVATE
// conversion uses a fixed synthetic test key, never a production credential.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const directory = await mkdtemp(join(tmpdir(), 'peerwork-signed-migration-'));
try {
  const source = resolve(fileURLToPath(new URL('reference/src/', import.meta.url)));
  const output = join(directory, 'oracle.mjs');
  await build({stdin: {contents: `export {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,encodeCanonicalJson} from '${source}/workspace-secure-crypto.ts';
    export {createPolicy,createCommit,secureHash,verifyJournal} from '${source}/workspace-secure-client.ts';`,
    resolveDir: source, sourcefile: 'oracle.ts'}, outfile: output, bundle: true, platform: 'node', format: 'esm', logLevel: 'silent'});
  const {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,encodeCanonicalJson,createPolicy,createCommit,secureHash,verifyJournal} = await import(pathToFileURL(output));
  const identity = await createSigningIdentity();
  const encryption = await createEncryptionIdentity();
  const certificate = await certifyEncryptionKey(identity, encryption, 1, 100000);
  const workspaceId = 'w'.repeat(43);
  const policy = await createPolicy(identity, {v: 1, workspace_id: workspaceId,
    owner_id: identity.actorId, signing_key: identity.keyId, version: 1, previous_policy: null,
    effective_sequence: 1, visibility: 'PUBLIC', epoch: 0,
    members: [{actor_id: identity.actorId, certificate, role: 'OWNER', scopes: []}], issued_at: 2});
  const policyHash = await secureHash(policy);
  const checkpoint0 = {v: 1, workspace_id: workspaceId, owner_id: identity.actorId,
    owner_key: identity.keyId, sequence: 0, head: null, policy_hash: policyHash};
  const imported = {kind: 'workspaces', id: workspaceId, revision: 1,
    provenance: 'AUTHOR_SIGNED', value: {id: workspaceId, workspace_id: workspaceId}};
  const descriptor = {kind: imported.kind, id: imported.id, revision: imported.revision};
  const migration = {source_checkpoint: null, source_root: await secureHash([descriptor]), source_items: [descriptor]};
  const page = await createCommit({identity, policy, checkpoint: checkpoint0,
    operation: {v: 1, kind: 'MIGRATE', input: {}, objects: [imported]},
    actionId: 'secure.migrate', instanceId: null, commandId: 'm'.repeat(43), issuedAt: 3, migration});
  const checkpoint1 = {...checkpoint0, sequence: 1, head: await secureHash(page)};
  const finish = await createCommit({identity, policy, checkpoint: checkpoint1,
    operation: {v: 1, kind: 'ADMIN', input: {}, objects: []},
    actionId: 'secure.finish', instanceId: null, commandId: 'f'.repeat(43), issuedAt: 4});
  const checkpoint2 = {...checkpoint0, sequence: 2, head: await secureHash(finish)};
  const wrongRootPage = await createCommit({identity, policy, checkpoint: checkpoint0,
    operation: {v: 1, kind: 'MIGRATE', input: {}, objects: [imported]},
    actionId: 'secure.migrate', instanceId: null, commandId: 'r'.repeat(43), issuedAt: 3,
    migration: {...migration, source_root: '0'.repeat(64)}});
  const wrongRootCheckpoint = {...checkpoint0, sequence: 1, head: await secureHash(wrongRootPage)};
  const cases = [];
  for (const [name, commits, checkpoint] of [
    ['genesis_migrate_then_finish', [page, finish], checkpoint2],
    ['genesis_migrate_at_eof', [page], checkpoint1],
    ['signed_wrong_source_root', [wrongRootPage], wrongRootCheckpoint],
  ]) {
    try {
      const journal = await verifyJournal({workspaceId, policies: [policy], commits, checkpoint,
        trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
      cases.push({name, policy, commits, checkpoint, workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId}, ok: true, objects: journal.objects});
    } catch (error) {
      cases.push({name, policy, commits, checkpoint, workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId}, ok: false, error: String(error.message)});
    }
  }
  const second = {kind: 'workspace_config', id: 'x'.repeat(43), revision: 1,
    provenance: 'AUTHOR_SIGNED', value: {workspace_id: workspaceId}};
  const secondDescriptor = {kind: second.kind, id: second.id, revision: second.revision};
  const completeItems = [descriptor, secondDescriptor];
  const sortedItems = [...completeItems].sort((left, right) => {
    const a = new TextDecoder().decode(encodeCanonicalJson(left));
    const b = new TextDecoder().decode(encodeCanonicalJson(right));
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const completeRoot = await secureHash(sortedItems);
  const firstPage = await createCommit({identity, policy, checkpoint: checkpoint0,
    operation: {v: 1, kind: 'MIGRATE', input: {}, objects: [imported]},
    actionId: 'secure.migrate', instanceId: null, commandId: '1'.repeat(43), issuedAt: 3,
    migration: {source_checkpoint: null, source_root: completeRoot, source_items: [descriptor]}});
  const firstCheckpoint = {...checkpoint0, sequence: 1, head: await secureHash(firstPage)};
  const secondPage = await createCommit({identity, policy, checkpoint: firstCheckpoint,
    operation: {v: 1, kind: 'MIGRATE', input: {}, objects: [second]},
    actionId: 'secure.migrate', instanceId: null, commandId: '2'.repeat(43), issuedAt: 4,
    migration: {source_checkpoint: null, source_root: completeRoot, source_items: [secondDescriptor]}});
  const secondCheckpoint = {...checkpoint0, sequence: 2, head: await secureHash(secondPage)};
  const twoPageCases = [
    ['two_page_migration', [firstPage, secondPage], secondCheckpoint],
    ['missing_second_page', [firstPage], firstCheckpoint],
  ];
  for (const [name, commits, checkpoint] of twoPageCases) {
    try {
      const journal = await verifyJournal({workspaceId, policies: [policy], commits, checkpoint,
        trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
      cases.push({name, policy, commits, checkpoint, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: true, objects: journal.objects});
    } catch (error) {
      cases.push({name, policy, commits, checkpoint, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: false, error: String(error.message)});
    }
  }
  const bootstrap = await createCommit({identity, policy, checkpoint: checkpoint0,
    operation: {v: 1, kind: 'BOOTSTRAP', input: {}, objects: []}, actionId: 'secure.bootstrap',
    instanceId: null, commandId: 'b'.repeat(43), issuedAt: 3});
  const publicCheckpoint = {...checkpoint0, sequence: 1, head: await secureHash(bootstrap)};
  const privatePolicy = await createPolicy(identity, {v: 1, workspace_id: workspaceId,
    owner_id: identity.actorId, signing_key: identity.keyId, version: 2,
    previous_policy: policyHash, effective_sequence: 2, visibility: 'PRIVATE', epoch: 1,
    members: [{actor_id: identity.actorId, certificate, role: 'OWNER', scopes: []}], issued_at: 4});
  const privateHash = await secureHash(privatePolicy);
  const keyring = {v: 1, workspace_id: workspaceId,
    keys: [{epoch: 1, key: Buffer.alloc(32, 121).toString('base64url')}]};
  const conversion = await createCommit({identity, policy: privatePolicy, checkpoint: publicCheckpoint,
    operation: {v: 1, kind: 'MIGRATE', input: {}, objects: [imported]},
    actionId: 'secure.migrate', instanceId: null, commandId: 'c'.repeat(43), issuedAt: 5,
    keyring, migration: {...migration, source_checkpoint: publicCheckpoint}});
  const privateCheckpoint = {...publicCheckpoint, sequence: 2, head: await secureHash(conversion), policy_hash: privateHash};
  try {
    const journal = await verifyJournal({workspaceId, policies: [policy, privatePolicy],
      commits: [bootstrap, conversion], checkpoint: privateCheckpoint, keyring,
      trustedOwner: {actorId: identity.actorId, key: identity.keyId}});
    cases.push({name: 'public_to_private_conversion', policies: [policy, privatePolicy],
      commits: [bootstrap, conversion], checkpoint: privateCheckpoint, keyring,
      workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
      ok: true, objects: journal.objects});
  } catch (error) {
    cases.push({name: 'public_to_private_conversion', policies: [policy, privatePolicy],
      commits: [bootstrap, conversion], checkpoint: privateCheckpoint, keyring,
      workspace_id: workspaceId, owner: {actor_id: identity.actorId, key: identity.keyId},
      ok: false, error: String(error.message)});
  }
  await writeFile(new URL('./signed-migration-vectors.json', import.meta.url), `${JSON.stringify(cases, null, 2)}\n`);
} finally {
  await rm(directory, {recursive: true, force: true});
}
