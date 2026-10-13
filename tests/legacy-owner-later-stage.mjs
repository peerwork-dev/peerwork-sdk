// Genuine f828 pending source snapshot followed by later signed history.
// The original client is closed before copying its protected local files;
// the immutable copy is selected for native import after the writer stops.
import { createPrivateKey } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot || !['complete-action', 'complete-ceiling2', 'incomplete-stale'].includes(mode)) {
  throw new Error('LATER_STAGE_TEST_INPUT');
}
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const initialRun = spawnSync(process.execPath, [
  join(import.meta.dirname, 'legacy-owner-source.mjs'), origin,
  join(sourceDir, 'writer'), referenceRoot,
  'stage-marker-multipart-pending-applied-index1',
], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
if (initialRun.status !== 0) throw new Error(`LATER_STAGE_INITIAL_SOURCE: ${initialRun.stderr}`);
const initial = JSON.parse(initialRun.stdout);
if (initial.pending_count !== 1 || initial.stage_marker?.part_index !== 1
  || initial.stage_part_count < 3 || initial.sequence !== 3) {
  throw new Error('LATER_STAGE_INITIAL_SHAPE');
}
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
  if ((statSync(target).mode & 0o077) !== 0) throw new Error('LATER_STAGE_SNAPSHOT_MODE');
}
const { SecureAgentClient } = await import(pathToFileURL(join(referenceRoot, 'dist-workspace/src/workspace-secure-agent.js')).href);
const { secureHash } = await import(pathToFileURL(join(referenceRoot, 'dist-workspace/src/workspace-secure-client.js')).href);
const privateKey = createPrivateKey(readFileSync(initial.pem_path));
const agent = await SecureAgentClient.open({
  baseUrl: new URL(origin).origin, privateKey,
  statePath: initial.state_path, intentDbPath: initial.intent_db_path,
});
try {
  const originalPacket = agent.state.pending[initial.pending_command_id];
  if (!originalPacket || await secureHash(originalPacket.body.commit) !== initial.pending_commit_hash) {
    throw new Error('LATER_STAGE_ORIGINAL_PACKET_CHANGED');
  }
  const retried = await agent.retryPending();
  if (retried.length !== 1 || Object.keys(agent.state.pending).length !== 0) {
    throw new Error('LATER_STAGE_EXACT_RETRY_MISSING');
  }
  let journal = await agent.journal(initial.workspace_id);
  if (journal.checkpoint.sequence !== 3) throw new Error('LATER_STAGE_ORIGINAL_NOT_SIGNED');
  let completedSequence = null;
  if (mode !== 'incomplete-stale') {
    const material = JSON.parse(initial.pending_stage_material_json);
    const staged = await agent.stagePackageMaterial(initial.workspace_id, material, initial.stage_marker.source);
    journal = staged.journal;
    completedSequence = initial.stage_marker.source.sequence + initial.stage_part_count;
    if (journal.checkpoint.sequence !== completedSequence || staged.proof.source_id !== initial.stage_marker.source_id) {
      throw new Error('LATER_STAGE_COMPLETION_MISMATCH');
    }
  }
  if (mode === 'complete-ceiling2') {
    journal = await agent.enableFormatTwo(initial.workspace_id);
    if (journal.policy.payload.protocol_format_ceiling !== 2 || journal.checkpoint.sequence !== completedSequence + 1) {
      throw new Error('LATER_STAGE_CEILING_MISSING');
    }
  } else {
    const wiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('LATER_STAGE_WIKI_MISSING');
    journal = await agent.action(initial.workspace_id, wiki.id, 'wiki.create', {
      title: mode === 'incomplete-stale' ? 'Incomplete stage later action' : 'Completed stage later action',
      body: 'Authenticated later history after exact old packet',
    });
    if (journal.checkpoint.sequence !== (completedSequence ?? 3) + 1) {
      throw new Error('LATER_STAGE_ACTION_MISSING');
    }
  }
  if (journal.policy.payload.owner_id !== initial.owner_actor_id
    || journal.policy.payload.signing_key !== initial.owner_key_id
    || journal.policy.payload.visibility !== 'PRIVATE'
    || Object.keys(agent.state.pending).length !== 0) {
    throw new Error('LATER_STAGE_CURRENT_AUTHORITY_MISMATCH');
  }
  process.stdout.write(JSON.stringify({
    ...initial, ...selected, mode,
    selected_sequence: initial.sequence,
    selected_policy_hash: initial.stage_marker.source.policy_hash,
    completed_sequence: completedSequence,
    latest_sequence: journal.checkpoint.sequence,
    latest_policy_hash: await secureHash(journal.policy),
    latest_ceiling: journal.policy.payload.protocol_format_ceiling,
    later_history_signed: true,
  }) + '\n');
} finally {
  agent.close();
}
