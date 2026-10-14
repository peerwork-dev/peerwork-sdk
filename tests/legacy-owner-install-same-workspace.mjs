// Genuine same-workspace source: completed A map plus unsent B BEGIN.
// Reopens the public client after the existing completed-END boundary;
// never edits saved state, pending maps or the service database.
import { execFileSync } from 'node:child_process';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot) throw new Error('SAME_WORKSPACE_INPUT');
const first = JSON.parse(execFileSync(process.execPath, [
  join(dirname(fileURLToPath(import.meta.url)), 'legacy-owner-install-intent.mjs'),
  origin, sourceDir, referenceRoot, 'direct-completed-end',
], { encoding: 'utf8', maxBuffer: 65536 }));
const moduleUrl = name => pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href;
const { SecureAgentClient } = await import(moduleUrl('workspace-secure-agent'));
const { resolveProtocolInstall } = await import(moduleUrl('workspace-protocol-install-plan'));
const { secureHash } = await import(moduleUrl('workspace-secure-client'));
const privateKey = createPrivateKey(readFileSync(first.pem_path));
const agent = await SecureAgentClient.open({ baseUrl: new URL(origin).origin,
  privateKey, statePath: first.state_path, intentDbPath: first.intent_db_path });
try {
  if (agent.identity.actorId !== first.owner_actor_id || agent.identity.keyId !== first.owner_key_id) {
    throw new Error('SAME_WORKSPACE_IDENTITY_CHANGED');
  }
  const workspaceId = first.workspace_id;
  const initial = await agent.journal(workspaceId);
  if (initial.structure?.state !== 'ACTIVE' || initial.checkpoint.sequence !== first.latest_sequence
    || Object.keys(agent.state.pending).length !== 0
    || agent.state.protocol_install_intents?.[first.intent_key] !== first.intent_hash
    || !initial.objects.some(row => row.kind === 'instances' && row.id === first.instance_id
      && row.value.protocol_digest === first.protocol_digest)) {
    throw new Error('SAME_WORKSPACE_FIRST_COMPLETION');
  }
  const options = { ...JSON.parse(readFileSync(first.options_path, 'utf8')),
    instance_id: randomBytes(32).toString('base64url'), entrypoint: 'migrated_selected_discussion' };
  const resolved = await resolveProtocolInstall(initial, options, []);
  const optionsPath = join(sourceDir, 'selected-install-options.json');
  writeFileSync(optionsPath, JSON.stringify(options), { mode: 0o600, flag: 'wx' });
  let stopped = false;
  const request = agent.request.bind(agent);
  agent.request = async (path, requestOptions) => {
    if (!stopped && requestOptions?.method === 'POST'
      && path === `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`
      && JSON.parse(requestOptions.body).commit.payload.action_id === 'secure.structure.begin') {
      stopped = true;
      throw new Error('SAME_WORKSPACE_STOP_BEFORE_B_BEGIN');
    }
    return request(path, requestOptions);
  };
  try {
    await agent.installProtocol(workspaceId, options);
    throw new Error('SAME_WORKSPACE_NOT_INTERRUPTED');
  } catch (error) {
    if (error?.message !== 'SAME_WORKSPACE_STOP_BEFORE_B_BEGIN') throw error;
  } finally { agent.request = request; }
  const map = agent.state.protocol_install_intents ?? {};
  const pending = Object.entries(agent.state.pending);
  const selectedKey = `${workspaceId}.${options.instance_id}`;
  if (!stopped || Object.keys(map).length !== 2 || pending.length !== 1
    || map[first.intent_key] !== first.intent_hash || map[selectedKey] !== resolved.intentHash
    || pending[0][0] !== pending[0][1].body?.commit?.payload?.command_id
    || pending[0][1].path !== `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`
    || pending[0][1].body?.commit?.payload?.action_id !== 'secure.structure.begin') {
    throw new Error('SAME_WORKSPACE_FINAL_SOURCE_SHAPE');
  }
  const latest = await agent.journal(workspaceId);
  if (latest.checkpoint.sequence !== initial.checkpoint.sequence || latest.structure?.state !== 'ACTIVE'
    || latest.objects.some(row => row.kind === 'instances' && row.id === options.instance_id)) {
    throw new Error('SAME_WORKSPACE_B_APPLIED');
  }
  process.stdout.write(JSON.stringify({
    mode: 'direct-same-workspace-before-post', workspace_id: workspaceId,
    owner_actor_id: first.owner_actor_id, owner_key_id: first.owner_key_id,
    state_path: first.state_path, pem_path: first.pem_path, intent_db_path: first.intent_db_path,
    options_path: optionsPath, material_path: first.material_path,
    instance_id: options.instance_id, intent_key: selectedKey, intent_hash: resolved.intentHash,
    protocol_digest: resolved.digest, entrypoint: options.entrypoint,
    initial_sequence: initial.checkpoint.sequence, latest_sequence: latest.checkpoint.sequence,
    latest_structure_state: latest.structure?.state, pending_count: pending.length,
    pending_command_id: pending[0][0], pending_commit_hash: await secureHash(pending[0][1].body.commit),
    retained_instance_id: first.instance_id, retained_intent_key: first.intent_key,
    retained_intent_hash: first.intent_hash, retained_protocol_digest: first.protocol_digest,
    retained_entrypoint: first.entrypoint,
  }) + '\n');
} finally { agent.close(); }
