// Genuine public-client partial object staging; no source/DB edits.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createLegacyComposedInstallMaterial } from './legacy-owner-install-composition-material.mjs';
import { createLegacyObjectInstallMaterial } from './legacy-owner-install-object-material.mjs';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot
  || !['first-part0-before-post', 'first-part0-applied-loss'].includes(mode)) throw new Error('PARTIAL_OBJECT_INPUT');
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const load = name => import(pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href);
const { SecureAgentClient } = await load('workspace-secure-agent');
const { secureHash, secureEqual, verifySecure, commitContext, verifiedJournalCheckpoint } = await load('workspace-secure-client');
const { decodeBase64Url, unsealContent, encodeCanonicalJson } = await load('workspace-secure-crypto');
const { SECURE_DOMAINS } = await load('workspace-secure-contract');
const { resolveProtocolInstall } = await load('workspace-protocol-install-plan');
const { compilePackageMaterial } = await load('workspace-protocol-package-source');
const { normalizeProtocolObjectSourceProof, readProtocolObjectSource } = await load('workspace-protocol-object-source');
const { verifyStagedProtocolObjectCheckpoint, validateProtocolObjectStageOperation, PROTOCOL_OBJECT_STAGE_ACTION } = await load('workspace-protocol-object-stage');
const { privateKey } = generateKeyPairSync('ed25519');
const paths = { state_path: join(sourceDir, 'agent.state'), pem_path: join(sourceDir, 'owner.pem'),
  intent_db_path: join(sourceDir, 'workspace-intents.sqlite'), options_path: join(sourceDir, 'install-options.json'),
  material_path: join(sourceDir, 'install-material.json') };
writeFileSync(paths.pem_path, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const agent = await SecureAgentClient.open({ baseUrl: new URL(origin).origin, privateKey,
  statePath: paths.state_path, intentDbPath: paths.intent_db_path });
try {
  const workspace = (await agent.create('Partial object stage source', 'PRIVATE', { structure: true })).workspaceId;
  const initial = await agent.journal(workspace);
  if (initial.policy.payload.v !== 3 || initial.policy.payload.visibility !== 'PRIVATE'
    || initial.structure?.state !== 'ACTIVE') throw new Error('PARTIAL_OBJECT_INITIAL');
  const middle = true; // Same public four-part author as the accepted T005 witness.
  const composed = middle ? await createLegacyComposedInstallMaterial(referenceRoot, true) : undefined;
  const material = composed?.material ?? await createLegacyObjectInstallMaterial(referenceRoot), compiled = compilePackageMaterial(material);
  const instance = randomBytes(32).toString('base64url'), key = `${workspace}.${instance}`;
  const options = { instance_id: instance, entrypoint: 'migrated_discussion', manifest: composed?.sourceManifest ?? compiled.manifest,
    ...(composed ? {dependencies:composed.dependencies} : {}),
    grants: [{ actor_id: agent.identity.actorId, actions: ['discussion.post'],
      protocol_roles: ['CONTRIBUTOR'], capabilities: ['POST'] }], expected_checkpoint: initial.checkpoint };
  const resolved = await resolveProtocolInstall(initial, options, agent.transport.discovery.protocol_features ?? []);
  if (resolved.digest !== compiled.protocolDigest || !secureEqual(resolved.manifest, compiled.manifest)) {
    throw new Error('PARTIAL_OBJECT_COMPILER');
  }
  for (const [path, value] of [[paths.options_path, options], [paths.material_path, material]]) {
    writeFileSync(path, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
  }
  const path = `/api/workspace/v1/secure/workspaces/${workspace}/commits`, index = 0;
  const originalPost = agent.post.bind(agent), originalRequest = agent.request.bind(agent);
  let stopped = false;
  const selected = commit => commit?.payload?.action_id === PROTOCOL_OBJECT_STAGE_ACTION
    && commit.payload.sequence === initial.checkpoint.sequence + index + 1;
  if (mode.endsWith('before-post')) {
    agent.request = async (target, request) => {
      if (!stopped && target === path && request?.method === 'POST' && selected(JSON.parse(request.body).commit)) {
        stopped = true;
        throw new Error('TEST_STOP_BEFORE_OBJECT_PART_POST');
      }
      return originalRequest(target, request);
    };
  } else {
    agent.post = async (...args) => {
      if (!stopped && args[0] === path && selected(args[1]?.commit)) {
        stopped = true;
        const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
        if (!hook.ok) throw new Error('PARTIAL_OBJECT_DROP_HOOK');
      }
      return originalPost(...args);
    };
  }
  try {
    await agent.installProtocol(workspace, options);
    throw new Error('PARTIAL_OBJECT_NOT_INTERRUPTED');
  } catch (error) {
    if (!stopped || mode.endsWith('before-post') && error?.message !== 'TEST_STOP_BEFORE_OBJECT_PART_POST'
      || mode.endsWith('applied-loss') && !Object.keys(agent.state.pending).length
      || error?.message === 'PARTIAL_OBJECT_NOT_INTERRUPTED') throw error;
  } finally { agent.post = originalPost; agent.request = originalRequest; }

  const markers = agent.state.protocol_object_stage_intents, marker = markers?.[key];
  const pending = Object.entries(agent.state.pending), journal = await agent.journal(workspace);
  const applied = mode.endsWith('applied-loss'), expectedAccepted = index + Number(applied);
  if (Object.keys(markers ?? {}).length !== 1 || !marker
    || Object.keys(marker).sort().join(',') !== 'command_id,parts,proof,request_hash'
    || marker.request_hash !== await secureHash(options) || pending.length !== 1
    || pending[0][0] !== marker.command_id || pending[0][1].path !== path
    || pending[0][1].body.commit?.payload?.command_id !== marker.command_id
    || !selected(pending[0][1].body.commit)
    || Object.keys(agent.state.protocol_install_intents ?? {}).length !== 0
    || journal.installations?.some(row => row.instance_id === instance)
    || journal.objects.some(row => row.kind === 'instances' && row.id === instance)
    || journal.structure?.state !== 'ACTIVE'
    || journal.checkpoint.sequence !== initial.checkpoint.sequence + expectedAccepted) {
    throw new Error('PARTIAL_OBJECT_GENUINE_SHAPE');
  }
  const proof = normalizeProtocolObjectSourceProof(marker.proof);
  if (proof.parts.length !== (middle ? 4 : 2) || marker.parts.length !== proof.parts.length
    || !secureEqual(proof.source, initial.checkpoint) || proof.protocol_digest !== compiled.protocolDigest
    || !secureEqual(readProtocolObjectSource(proof, marker.parts), { workspace_id: workspace,
      digest: compiled.protocolDigest, manifest: compiled.manifest, resolved_manifest: compiled.manifest, ...(composed ? {composition:composed.composition} : {}) })) {
    throw new Error('PARTIAL_OBJECT_FULL_MATERIAL');
  }
  verifyStagedProtocolObjectCheckpoint(journal, proof);
  const actualParts = journal.objects.filter(row => row.kind === 'protocol_object_part'
    && row.value.source_id === proof.source_id).sort((a, b) => a.value.index - b.value.index);
  if (!secureEqual(actualParts, marker.parts.slice(0, expectedAccepted))) throw new Error('PARTIAL_OBJECT_SIGNED_PREFIX');
  const commit = pending[0][1].body.commit, prior = verifiedJournalCheckpoint(journal, commit.payload.sequence - 1);
  if (commit.payload.previous !== prior.head || commit.payload.policy_hash !== prior.policy_hash
    || prior.policy_hash !== initial.checkpoint.policy_hash) throw new Error('PARTIAL_OBJECT_PACKET_PREDECESSOR');
  await verifySecure(commit, SECURE_DOMAINS.commit, agent.identity.keyId);
  const epoch = agent.state.workspaces[workspace].keyring.keys.find(row => row.epoch === commit.payload.epoch);
  if (!epoch) throw new Error('PARTIAL_OBJECT_EPOCH');
  const keyObject = await crypto.subtle.importKey('raw', decodeBase64Url(epoch.key), { name: 'AES-GCM' }, false, ['decrypt']);
  const raw = await unsealContent(keyObject, commit.payload.body, commitContext(commit));
  const operation = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  if (!Buffer.from(raw).equals(Buffer.from(encodeCanonicalJson(operation)))
    || !secureEqual(operation, { v: 1, kind: 'ADMIN', input: { protocol_object_stage: { proof, part_index: index } },
      objects: [marker.parts[index]] })) throw new Error('PARTIAL_OBJECT_EXACT_OPERATION');
  await validateProtocolObjectStageOperation(operation, commitContext(commit), initial.policy,
    journal.objects.filter(row => row.kind !== 'protocol_object_part' || row.value.source_id !== proof.source_id || row.value.index < index));
  process.stdout.write(JSON.stringify({ mode, ...paths, workspace_id: workspace,
    owner_actor_id: agent.identity.actorId, owner_key_id: agent.identity.keyId, instance_id: instance,
    entrypoint: options.entrypoint, protocol_digest: compiled.protocolDigest, material_root_digest: material.closure.root_package_digest,
    pending_transport_body_sha256: createHash('sha256').update(JSON.stringify(pending[0][1].body)).digest('hex'),
    pending_command_id: marker.command_id, pending_commit_hash: await secureHash(commit),
    pending_action_id: commit.payload.action_id, pending_sequence: commit.payload.sequence,
    part_index: index, part_count: proof.parts.length, accepted_part_count: expectedAccepted,
    initial_sequence: initial.checkpoint.sequence, latest_sequence: journal.checkpoint.sequence,
    latest_structure_state: journal.structure.state, install_intent_count: 0, selected_installation_exists: false,
    compiler_equality: true, request_hash: marker.request_hash, intent_hash: resolved.intentHash,
    original_checkpoint: initial.checkpoint, selected_predecessor: prior, object_source: proof,
    exact_operation_verified: true }) + '\n');
} finally { await agent.close(); }
