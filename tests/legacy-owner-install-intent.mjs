// Genuine f828 public-client install-intent snapshots. The hooks interrupt
// supported client boundaries; they never edit the saved state or service DB.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot
  || !['begin-applied-loss', 'begin-before-post', 'completed-end'].includes(mode)) {
  throw new Error('INSTALL_INTENT_TEST_INPUT');
}
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const { privateKey } = generateKeyPairSync('ed25519');
const pemPath = join(sourceDir, 'owner.pem');
const statePath = join(sourceDir, 'agent.state');
const intentDbPath = join(sourceDir, 'workspace-intents.sqlite');
const optionsPath = join(sourceDir, 'install-options.json');
writeFileSync(pemPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const moduleUrl = name => pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href;
const { SecureAgentClient } = await import(moduleUrl('workspace-secure-agent'));
const { discussionPreset } = await import(moduleUrl('workspace-presets'));
const { secureHash } = await import(moduleUrl('workspace-secure-client'));
const { resolveProtocolInstall } = await import(moduleUrl('workspace-protocol-install-plan'));
const agent = await SecureAgentClient.open({
  baseUrl: new URL(origin).origin, privateKey, statePath, intentDbPath,
});
try {
  const created = await agent.create('Legacy install intent proof', 'PRIVATE', { structure: true });
  const workspaceId = created.workspaceId;
  const initial = await agent.journal(workspaceId);
  if (initial.policy.payload.v !== 3 || initial.policy.payload.visibility !== 'PRIVATE'
    || initial.structure?.state !== 'ACTIVE') throw new Error('INSTALL_INTENT_INITIAL_POLICY');
  const manifest = discussionPreset();
  manifest.name = 'example.native-install-intent.v1';
  const instanceId = randomBytes(32).toString('base64url');
  const options = {
    instance_id: instanceId, entrypoint: 'migrated_discussion', manifest,
    grants: [{ actor_id: agent.identity.actorId, actions: ['discussion.post'],
      protocol_roles: ['CONTRIBUTOR'], capabilities: ['POST'] }],
  };
  const resolved = await resolveProtocolInstall(initial, options, []);
  writeFileSync(optionsPath, JSON.stringify(options), { mode: 0o600, flag: 'wx' });
  const key = `${workspaceId}.${instanceId}`;
  const originalPost = agent.post.bind(agent);
  const originalRequest = agent.request.bind(agent);
  let stopped = false;
  let observedAction = null;
  if (mode === 'begin-applied-loss') {
    const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
    if (!hook.ok) throw new Error('INSTALL_INTENT_DROP_HOOK');
  }
  if (mode === 'begin-before-post') {
    agent.request = async (path, requestOptions) => {
      if (!stopped && requestOptions?.method === 'POST'
        && path === `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`) {
        stopped = true;
        throw new Error('TEST_STOP_BEFORE_INSTALL_BEGIN_POST');
      }
      return originalRequest(path, requestOptions);
    };
  }
  if (mode === 'completed-end') {
    agent.post = async (...args) => {
      const action = args[1]?.commit?.payload?.action_id;
      const result = await originalPost(...args);
      if (!stopped && action === 'secure.structure.end') {
        stopped = true;
        observedAction = action;
        throw new Error('TEST_STOP_AFTER_INSTALL_END_POST');
      }
      return result;
    };
  }
  try {
    await agent.installProtocol(workspaceId, options);
    throw new Error('TEST_INSTALL_NOT_INTERRUPTED');
  } catch (error) {
    if (mode === 'begin-before-post' || mode === 'completed-end') {
      const expected = mode === 'begin-before-post'
        ? 'TEST_STOP_BEFORE_INSTALL_BEGIN_POST' : 'TEST_STOP_AFTER_INSTALL_END_POST';
      if (error?.message !== expected) throw error;
    } else if (error?.message === 'TEST_INSTALL_NOT_INTERRUPTED') {
      throw error;
    }
  } finally {
    agent.post = originalPost;
    agent.request = originalRequest;
  }
  const retainedHash = agent.state.protocol_install_intents?.[key];
  if (retainedHash !== resolved.intentHash) {
    throw new Error('INSTALL_INTENT_MAP_MISSING');
  }
  const pending = Object.entries(agent.state.pending);
  const expectedPending = mode === 'completed-end' ? 0 : 1;
  if (pending.length !== expectedPending) throw new Error('INSTALL_INTENT_PENDING_COUNT');
  const selected = pending[0];
  if (selected && (selected[1].path !== `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`
    || selected[1].body?.commit?.payload?.action_id !== 'secure.structure.begin')) {
    throw new Error('INSTALL_INTENT_PENDING_BEGIN_MISMATCH');
  }
  const journal = await agent.journal(workspaceId);
  if (mode === 'completed-end') {
    if (!stopped || observedAction !== 'secure.structure.end'
      || journal.structure?.state !== 'ACTIVE'
      || !journal.objects.some(row => row.kind === 'instances' && row.id === instanceId
        && row.value.protocol_digest === resolved.digest
        && row.value.origin_entrypoint === options.entrypoint)
      || !journal.installations?.some(row => row.instance_id === instanceId
        && row.protocol_digest === resolved.digest && row.entrypoint === options.entrypoint)) {
      throw new Error('INSTALL_INTENT_SIGNED_COMPLETION_MISSING');
    }
  } else if ((mode === 'begin-before-post' && (!stopped || journal.checkpoint.sequence !== initial.checkpoint.sequence))
    || (mode === 'begin-applied-loss' && journal.checkpoint.sequence !== initial.checkpoint.sequence + 1)) {
    throw new Error('INSTALL_INTENT_BEGIN_STATE_MISMATCH');
  }
  process.stdout.write(JSON.stringify({
    mode, workspace_id: workspaceId, owner_actor_id: agent.identity.actorId,
    owner_key_id: agent.identity.keyId, state_path: statePath,
    pem_path: pemPath, intent_db_path: intentDbPath, options_path: optionsPath,
    instance_id: instanceId, intent_key: key, intent_hash: retainedHash,
    protocol_digest: resolved.digest, entrypoint: options.entrypoint,
    initial_sequence: initial.checkpoint.sequence, latest_sequence: journal.checkpoint.sequence,
    latest_structure_state: journal.structure?.state ?? null,
    pending_count: pending.length, pending_command_id: selected?.[0] ?? null,
    pending_commit_hash: selected ? await secureHash(selected[1].body.commit) : null,
  }) + '\n');
} finally {
  agent.close();
}
