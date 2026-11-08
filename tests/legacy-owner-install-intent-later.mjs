// Closed f828 completed-map source, copied before one further public signed
// operation. Native import selects the protected pre-mutation copy.
import { createPrivateKey } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot
  || !['complete-action', 'complete-rotate'].includes(mode)) {
  throw new Error('COMPLETED_INSTALL_LATER_INPUT');
}
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const initialRun = spawnSync(process.execPath, [
  join(import.meta.dirname, 'legacy-owner-install-intent.mjs'), origin,
  join(sourceDir, 'writer'), referenceRoot, 'direct-completed-end',
], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
if (initialRun.status !== 0) throw new Error('COMPLETED_INSTALL_INITIAL_SETUP');
const initial = JSON.parse(initialRun.stdout);
if (initial.pending_count !== 0 || initial.latest_structure_state !== 'ACTIVE'
  || initial.latest_sequence !== 3) throw new Error('COMPLETED_INSTALL_INITIAL_SHAPE');
const snapshotDir = join(sourceDir, 'selected-snapshot');
mkdirSync(snapshotDir, { mode: 0o700 });
const selected = {
  state_path: join(snapshotDir, 'agent.state'),
  pem_path: join(snapshotDir, 'owner.pem'),
  intent_db_path: join(snapshotDir, 'workspace-intents.sqlite'),
};
for (const [key, target] of Object.entries(selected)) {
  copyFileSync(initial[key], target);
  chmodSync(target, 0o600);
  if ((statSync(target).mode & 0o077) !== 0) throw new Error('COMPLETED_INSTALL_SNAPSHOT_MODE');
}
const moduleUrl = name => pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href;
const { SecureAgentClient } = await import(moduleUrl('workspace-secure-agent'));
const agent = await SecureAgentClient.open({
  baseUrl: new URL(origin).origin,
  privateKey: createPrivateKey(readFileSync(initial.pem_path)),
  statePath: initial.state_path,
  intentDbPath: initial.intent_db_path,
});
try {
  const before = await agent.journal(initial.workspace_id);
  if (before.checkpoint.sequence !== initial.latest_sequence
    || agent.state.protocol_install_intents?.[initial.intent_key] !== initial.intent_hash) {
    throw new Error('COMPLETED_INSTALL_SELECTED_CHANGED');
  }
  let latest;
  if (mode === 'complete-action') {
    const wiki = before.objects.find(row => row.kind === 'instances'
      && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('COMPLETED_INSTALL_WIKI_MISSING');
    latest = await agent.action(initial.workspace_id, wiki.id, 'wiki.create', {
      title: 'Historical install later action', body: 'Signed after completed END',
    });
  } else {
    latest = await agent.rotate(initial.workspace_id);
  }
  if (latest.checkpoint.sequence !== initial.latest_sequence + 1
    || latest.policy.payload.visibility !== 'PRIVATE'
    || latest.structure?.state !== 'ACTIVE'
    || !latest.objects.some(row => row.kind === 'instances'
      && row.id === initial.instance_id
      && row.value.protocol_digest === initial.protocol_digest
      && row.value.origin_entrypoint === initial.entrypoint)) {
    throw new Error('COMPLETED_INSTALL_LATER_HISTORY');
  }
  process.stdout.write(JSON.stringify({
    ...initial, ...selected, mode,
    selected_sequence: initial.latest_sequence,
    latest_sequence: latest.checkpoint.sequence,
    latest_epoch: latest.policy.payload.epoch,
    selected_epoch: before.policy.payload.epoch,
  }) + '\n');
} finally {
  await agent.close();
}
