// Test-created current-client Owner source for a kernel JWS left pending across
// the official PUBLIC secure conversion. No service database is edited.
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot || !['applied-loss', 'pre-send'].includes(mode)) {
  throw new Error('KERNEL_PENDING_SOURCE_INPUT_INVALID');
}
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const { privateKey } = generateKeyPairSync('ed25519');
const pemPath = join(sourceDir, 'owner.pem');
const statePath = join(sourceDir, 'agent.state');
const intentDbPath = join(sourceDir, 'workspace-intents.sqlite');
writeFileSync(pemPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const { SecureAgentClient } = await import(pathToFileURL(join(referenceRoot, 'dist-workspace/src/workspace-secure-agent.js')).href);
const trustedOrigin = new URL(origin).origin;
let dropAppliedResponse = false;
let droppedResponses = 0;
const observedFetch = async (input, init) => {
  const response = await fetch(input, init);
  if (dropAppliedResponse && new URL(input).pathname === '/api/workspace/v1/commands' && init?.method === 'POST') {
    dropAppliedResponse = false;
    if (!response.ok) throw new Error('KERNEL_SOURCE_COMMAND_NOT_APPLIED');
    droppedResponses++;
    throw new Error('TEST_DROP_APPLIED_KERNEL_RESPONSE');
  }
  return response;
};
const agent = await SecureAgentClient.open({ baseUrl: trustedOrigin, privateKey, statePath, intentDbPath, fetch: observedFetch });
const command = (workspaceId, actionId, body) => ({
  workspace_id: workspaceId, instance_id: null, protocol_digest: null, action_id: actionId,
  expected_workspace_revision: null, expected_instance_revision: null, exact_input_refs: [], body,
});
try {
  await agent.register();
  const target = await agent.transport.submit(command(null, 'workspace.create', { name: 'Kernel conversion target', visibility: 'PUBLIC' }));
  const unrelated = await agent.transport.submit(command(null, 'workspace.create', { name: 'Unrelated pending scope', visibility: 'PUBLIC' }));
  const workspaceId = target.result.workspace_id;
  const unrelatedWorkspaceId = unrelated.result.workspace_id;
  if (typeof workspaceId !== 'string' || typeof unrelatedWorkspaceId !== 'string' || workspaceId === unrelatedWorkspaceId) throw new Error('KERNEL_SOURCE_WORKSPACE_INVALID');
  const selected = agent.transport.prepare(command(workspaceId, 'admin.view.set', {
    expected_config_revision: 0, layout_version: 1, blocks: ['document'], output_collections: [],
  }));
  const other = agent.transport.prepare(command(unrelatedWorkspaceId, 'admin.view.set', {
    expected_config_revision: 0, layout_version: 1, blocks: ['history'], output_collections: [],
  }));
  if (mode === 'applied-loss') {
    dropAppliedResponse = true;
    try { await agent.transport.submitPrepared(selected); throw new Error('KERNEL_SOURCE_LOSS_NOT_REACHED'); }
    catch (error) { if (error?.code !== 'SUBMIT_UNCERTAIN') throw error; }
    if (droppedResponses !== 1) throw new Error('KERNEL_SOURCE_LOSS_COUNT_INVALID');
  }
  const before = agent.transport.pending();
  if (before.length !== 2 || !before.includes(selected.commandId) || !before.includes(other.commandId)) throw new Error('KERNEL_SOURCE_PENDING_INVALID');
  const converted = await agent.convert(workspaceId, 'PUBLIC');
  const after = agent.transport.pending();
  if (after.length !== 2 || !after.includes(selected.commandId) || !after.includes(other.commandId)) throw new Error('KERNEL_SOURCE_PENDING_CHANGED');
  if (converted.policy.payload.visibility !== 'PUBLIC' || converted.checkpoint.workspace_id !== workspaceId) throw new Error('KERNEL_SOURCE_CONVERSION_INVALID');
  process.stdout.write(JSON.stringify({
    mode, workspace_id: workspaceId, unrelated_workspace_id: unrelatedWorkspaceId,
    owner_actor_id: agent.identity.actorId, owner_key_id: agent.identity.keyId,
    audience: agent.transport.discovery.audience,
    pem_path: pemPath, state_path: statePath, intent_db_path: intentDbPath,
    selected_command_id: selected.commandId, selected_intent_digest: selected.intentDigest,
    unrelated_command_id: other.commandId, unrelated_intent_digest: other.intentDigest,
    pending_count: after.length, dropped_responses: droppedResponses,
    policy_v: converted.policy.payload.v, policy_visibility: converted.policy.payload.visibility,
    secure_sequence: converted.checkpoint.sequence,
  }) + '\n');
} finally {
  agent.close();
}
