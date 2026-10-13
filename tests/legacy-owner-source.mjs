// Test-created exportable legacy Owner source. Pinned pre-v3 Agent code signs
// a genuine PRIVATE wire-v1 workspace on the current service's PREPARE path.
// Public IDs only leave this process; PEM/state/SQLite remain mode-protected.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, legacyRoot, mode = 'clean'] = process.argv.slice(2);
if (!origin || !sourceDir || !legacyRoot) throw new Error('LEGACY_TEST_INPUT_REQUIRED');
if (!['clean', 'completed', 'legacy-record', 'pending', 'unknown-store', 'malformed-store', 'legacy-structured', 'legacy-public', 'legacy-public-structured', 'legacy-public-record', 'legacy-public-structured-record', 'private-missing-ring'].includes(mode)) throw new Error('LEGACY_TEST_MODE_INVALID');
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const { privateKey } = generateKeyPairSync('ed25519');
const pemPath = join(sourceDir, 'owner.pem');
const statePath = join(sourceDir, 'agent.state');
const intentDbPath = join(sourceDir, 'workspace-intents.sqlite');
writeFileSync(pemPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const modulePath = join(legacyRoot, 'dist-workspace/src/workspace-secure-agent.js');
const { SecureAgentClient } = await import(pathToFileURL(modulePath).href);
const { secureHash } = await import(pathToFileURL(join(legacyRoot, 'dist-workspace/src/workspace-secure-client.js')).href);
const agent = await SecureAgentClient.open({ baseUrl: new URL(origin).origin, privateKey, statePath, intentDbPath });
try {
  const visibility = mode.startsWith('legacy-public') ? 'PUBLIC' : 'PRIVATE';
  const structured = mode === 'legacy-structured' || mode === 'legacy-public-structured' || mode === 'legacy-public-structured-record';
  const created = await agent.create('Legacy native attach proof', visibility, { structure: structured });
  const journal = await agent.journal(created.workspaceId);
  if (journal.policy.payload.v !== (structured ? 2 : 1) || journal.policy.payload.visibility !== visibility) {
    throw new Error('LEGACY_EXPECTED_WIRE_NOT_CREATED');
  }
  if (mode === 'pending') {
    const wiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('LEGACY_WIKI_MISSING');
    const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
    if (!hook.ok) throw new Error('LEGACY_DROP_HOOK_FAILED');
    try {
      await agent.action(created.workspaceId, wiki.id, 'wiki.create', {
        title: 'Pending legacy Owner action', body: 'Exact signed packet remains local',
      });
    } catch { /* Expected response loss; the Agent's protected pending map is the evidence. */ }
    if (Object.keys(agent.state.pending).length !== 1) throw new Error('LEGACY_PENDING_NOT_SAVED');
  }
  if (mode === 'unknown-store') {
    agent.state.future_signed_intents = { probe: { path: '/test-only', body: {} } };
    agent.save();
  }
  if (mode === 'malformed-store') {
    agent.state.admission_browser_approvals = null;
    agent.save();
  }
  if (mode === 'private-missing-ring') {
    delete agent.state.workspaces[created.workspaceId].keyring;
    agent.save();
  }
  if (mode === 'completed') {
    const update = await agent.updateIdentityKey(randomBytes(32).toString('base64url'), {
      mode: 'ROTATE', expected_certificate_hash: await secureHash(agent.state.certificate),
    });
    if (update.state !== 'PUBLISHED') throw new Error('LEGACY_COMPLETED_UPDATE_MISSING');
  }
  let priorRecordId = null;
  let priorRecordTitle = null;
  let priorRecordBody = null;
  if (mode === 'legacy-record' || mode === 'legacy-structured' || mode === 'legacy-public-record' || mode === 'legacy-public-structured-record') {
    const wiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('LEGACY_WIKI_MISSING');
    priorRecordTitle = visibility === 'PUBLIC' ? 'Legacy public record' : 'Legacy encrypted record';
    priorRecordBody = visibility === 'PUBLIC' ? 'Old PUBLIC wire content' : 'Old wire-v1 encrypted body';
    const advanced = await agent.action(created.workspaceId, wiki.id, 'wiki.create', {
      title: priorRecordTitle, body: priorRecordBody,
    });
    const record = advanced.objects.find(row => row.kind === 'records' && row.value?.payload?.title === priorRecordTitle);
    if (!record) throw new Error('LEGACY_RECORD_MISSING');
    priorRecordId = record.id;
  }
  process.stdout.write(JSON.stringify({
    workspace_id: created.workspaceId,
    owner_actor_id: agent.identity.actorId,
    owner_key_id: agent.identity.keyId,
    policy_v: journal.policy.payload.v,
    sequence: journal.checkpoint.sequence,
    state_path: statePath,
    pem_path: pemPath,
    intent_db_path: intentDbPath,
    pending_count: Object.keys(agent.state.pending).length,
    completed_identity_updates: Object.values(agent.state.identity_key_intents ?? {}).filter(row => row.state === 'PUBLISHED').length,
    prior_record_id: priorRecordId,
    prior_record_title: priorRecordTitle,
    prior_record_body: priorRecordBody,
  }) + '\n');
} finally {
  agent.close();
}
