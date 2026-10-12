// Test-only generator: actual tracked TypeScript WorkspaceClient writes a
// fresh v1 store with accepted and pending commands for two Ed25519 actors.
import {randomBytes, createPrivateKey} from 'node:crypto';
import {writeFileSync, chmodSync} from 'node:fs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

const [origin, state, reference] = process.argv.slice(2);
if (!origin || !state || !reference) throw new Error('origin, private state, and reference checkout required');
const {WorkspaceClient} = await import(pathToFileURL(join(reference, 'dist-workspace/src/workspace-client.js')).href);
const dbPath = join(state, 'legacy-client.sqlite');
const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const ids = [];
for (const label of ['A', 'B']) {
  const seed = randomBytes(32);
  const seedFile = join(state, `legacy-${label}.seed`);
  writeFileSync(seedFile, seed, {mode: 0o600, flag: 'wx'});
  const privateKey = createPrivateKey({key: Buffer.concat([prefix, seed]), format: 'der', type: 'pkcs8'});
  seed.fill(0);
  const client = await WorkspaceClient.open({baseUrl: origin, privateKey, intentDbPath: dbPath});
  const input = (commandId, status) => ({
    commandId, workspace_id: null, instance_id: null, protocol_digest: null,
    action_id: 'workspace.create', expected_workspace_revision: null,
    expected_instance_revision: null, exact_input_refs: [],
    body: {name: `Legacy ${label} ${status}`, visibility: 'PUBLIC'},
  });
  const acceptedId = randomBytes(32).toString('base64url');
  const pendingId = randomBytes(32).toString('base64url');
  await client.submit(input(acceptedId, 'accepted'));
  client.prepare(input(pendingId, 'pending'));
  ids.push({label, actor_id: client.actorId, key_id: client.kid,
            seed_file: seedFile, accepted_id: acceptedId, pending_id: pendingId});
  client.close();
}
chmodSync(dbPath, 0o600);
console.log(JSON.stringify({db_path: dbPath, actors: ids}));
