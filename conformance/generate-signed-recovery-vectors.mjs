// Direct signed recovery outcomes from the pinned TypeScript journal verifier.
// All keys are freshly generated test identities or fixed synthetic epoch bytes.
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const directory = await mkdtemp(join(tmpdir(), 'peerwork-signed-recovery-'));
try {
  const source = resolve(fileURLToPath(new URL('reference/src/', import.meta.url)));
  const output = join(directory, 'oracle.mjs');
  await build({stdin: {contents: `export {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey} from '${source}/workspace-secure-crypto.ts';
    export {createPolicy,createCommit,secureHash,verifyJournal,prepareJournalRecovery} from '${source}/workspace-secure-client.ts';`,
    resolveDir: source, sourcefile: 'oracle.ts'}, outfile: output, bundle: true,
    platform: 'node', format: 'esm', logLevel: 'silent'});
  const {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey,createPolicy,
    createCommit,secureHash,verifyJournal,prepareJournalRecovery} = await import(pathToFileURL(output));
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
  const cases = [];
  for (const [name, commits, checkpoint] of [
    ['unrecovered_invalid_encrypted_commit', [bootstrap, bad], checkpoint2],
    ['recovered_invalid_encrypted_commit', [bootstrap, bad, marker], checkpoint3],
    ['signed_wrong_excluded_root', [bootstrap, bad, wrongRoot], wrongRootCheckpoint],
    ['invented_failure_over_valid_content', [bootstrap, valid, inventedMarker], inventedCheckpoint3],
  ]) {
    try {
      const journal = await verifyJournal({...baseInput, commits, checkpoint});
      cases.push({name, policy, commits, checkpoint, keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: true,
        operations: journal.operations, objects: journal.objects,
        recoveries: journal.recoveries, legacy: journal.legacy});
    } catch (error) {
      cases.push({name, policy, commits, checkpoint, keyring, workspace_id: workspaceId,
        owner: {actor_id: identity.actorId, key: identity.keyId}, ok: false,
        error: String(error.message)});
    }
  }
  await writeFile(new URL('./signed-recovery-vectors.json', import.meta.url),
    `${JSON.stringify({prepared: {recovery: prepared.recovery,
      failure_code: prepared.failure_code}, cases}, null, 2)}\n`);
} finally {
  await rm(directory, {recursive: true, force: true});
}
