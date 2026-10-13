// Test-created exportable legacy Owner source. Pinned pre-v3 Agent code signs
// a genuine PRIVATE wire-v1 workspace on the current service's PREPARE path.
// Public IDs only leave this process; PEM/state/SQLite remain mode-protected.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, legacyRoot, mode = 'clean'] = process.argv.slice(2);
if (!origin || !sourceDir || !legacyRoot) throw new Error('LEGACY_TEST_INPUT_REQUIRED');
if (!['clean', 'completed', 'legacy-record', 'pending', 'pending-before-post', 'pending-private-structured', 'pending-private-structured-before-post', 'pending-public', 'pending-public-before-post', 'pending-public-structured', 'pending-public-structured-before-post', 'pending-current-private', 'pending-current-private-before-post', 'pending-current-private-structured', 'pending-current-private-structured-before-post', 'pending-current-private-structured-ceiling2', 'pending-current-private-structured-ceiling2-before-post', 'pending-current-public', 'pending-current-public-before-post', 'pending-current-public-structured', 'pending-current-public-structured-before-post', 'stage-marker-completed', 'stage-marker-pending', 'stage-marker-mismatch', 'stage-marker-command-mismatch', 'kernel-jws-source', 'unknown-store', 'malformed-store', 'legacy-structured', 'legacy-public', 'legacy-public-structured', 'legacy-public-record', 'legacy-public-structured-record', 'private-missing-ring'].includes(mode)) throw new Error('LEGACY_TEST_MODE_INVALID');
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
  const visibility = mode.includes('public') ? 'PUBLIC' : 'PRIVATE';
  const structured = mode.includes('structured') || mode.startsWith('stage-marker-');
  const currentClient = mode.startsWith('pending-current') || mode.startsWith('stage-marker-') || mode === 'kernel-jws-source';
  const created = await agent.create('Legacy native attach proof', visibility, { structure: structured });
  let journal = await agent.journal(created.workspaceId);
  if (mode.includes('ceiling2')) journal = await agent.enableFormatTwo(created.workspaceId);
  if (journal.policy.payload.v !== (currentClient ? 3 : structured ? 2 : 1) || journal.policy.payload.visibility !== visibility) {
    throw new Error('LEGACY_EXPECTED_WIRE_NOT_CREATED');
  }
  if (mode.startsWith('pending')) {
    const wiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('LEGACY_WIKI_MISSING');
    let stopped = false;
    const originalRequest = agent.request.bind(agent);
    const beforePost = mode.endsWith('before-post');
    if (!beforePost) {
      const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
      if (!hook.ok) throw new Error('LEGACY_DROP_HOOK_FAILED');
    } else {
      agent.request = async (path, options) => {
        if (!stopped && path === `/api/workspace/v1/secure/workspaces/${created.workspaceId}/commits` && options?.method === 'POST') {
          stopped = true;
          throw new Error('TEST_STOP_BEFORE_ACTION_POST');
        }
        return originalRequest(path, options);
      };
    }
    try {
      await agent.action(created.workspaceId, wiki.id, 'wiki.create', {
        title: 'Pending legacy Owner action', body: 'Exact signed packet remains local',
      });
    } catch (error) {
      if (beforePost && error?.message !== 'TEST_STOP_BEFORE_ACTION_POST') throw error;
      /* The Agent's protected pending map is the durable evidence. */
    } finally { agent.request = originalRequest; }
    if (beforePost && !stopped) throw new Error('LEGACY_PRE_POST_STOP_NOT_REACHED');
    if (Object.keys(agent.state.pending).length !== 1) throw new Error('LEGACY_PENDING_NOT_SAVED');
  }
  let stageMarker = null;
  let stagePartCount = null;
  let stagePartId = null;
  let stagePartSha = null;
  let stageSignedCommandId = null;
  if (mode.startsWith('stage-marker-')) {
    const { parseProtocolPackage, PROTOCOL_PACKAGE_FORMAT } = await import(pathToFileURL(join(legacyRoot, 'dist-workspace/src/protocol-package.js')).href);
    const { createProtocolPackageClosure } = await import(pathToFileURL(join(legacyRoot, 'dist-workspace/src/protocol-package-closure.js')).href);
    const { createProtocolPackageSource, verifyStagedPackageCheckpoint } = await import(pathToFileURL(join(legacyRoot, 'dist-workspace/src/workspace-protocol-package-source.js')).href);
    const directory = join(legacyRoot, 'protocols/discussion');
    const files = {};
    const walk = at => {
      for (const entry of readdirSync(at, { withFileTypes: true })) {
        const path = join(at, entry.name);
        if (entry.isDirectory()) walk(path);
        else files[relative(directory, path).split(sep).join('/')] = readFileSync(path, 'utf8');
      }
    };
    walk(directory);
    const bundle = parseProtocolPackage({ format: PROTOCOL_PACKAGE_FORMAT, files });
    const material = { v: 1, closure: createProtocolPackageClosure(bundle, []), bindings: {} };
    const staged = createProtocolPackageSource(material, journal.checkpoint);
    if (staged.parts.length !== 1) throw new Error('TEST_STAGE_PART_COUNT_UNEXPECTED');
    stagePartCount = staged.parts.length;
    stagePartId = staged.proof.parts[0].id;
    stagePartSha = staged.proof.parts[0].sha256;
    const originalPost = agent.post.bind(agent);
    let stopped = false;
    let submittedCommand = null;
    agent.post = async (...args) => {
      if (!submittedCommand) submittedCommand = {
        command_id: args[2], action_id: args[1]?.commit?.payload?.action_id,
      };
      const result = await originalPost(...args);
      if ((mode === 'stage-marker-completed' || mode === 'stage-marker-mismatch' || mode === 'stage-marker-command-mismatch') && !stopped) {
        stopped = true;
        throw new Error('TEST_STOP_AFTER_STAGE_POST');
      }
      return result;
    };
    if (mode === 'stage-marker-pending') {
      const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
      if (!hook.ok) throw new Error('TEST_STAGE_DROP_HOOK_FAILED');
    }
    try {
      await agent.stagePackageMaterial(created.workspaceId, material, journal.checkpoint);
      throw new Error('TEST_STAGE_DID_NOT_INTERRUPT');
    } catch (error) {
      if ((mode === 'stage-marker-completed' || mode === 'stage-marker-mismatch' || mode === 'stage-marker-command-mismatch') && error?.message !== 'TEST_STOP_AFTER_STAGE_POST') throw error;
      if (mode === 'stage-marker-pending' && error?.message === 'TEST_STAGE_DID_NOT_INTERRUPT') throw error;
    } finally { agent.post = originalPost; }
    if ((mode === 'stage-marker-completed' || mode === 'stage-marker-mismatch' || mode === 'stage-marker-command-mismatch') && !stopped) throw new Error('TEST_STAGE_COMPLETED_STOP_NOT_REACHED');
    const markers = Object.values(agent.state.package_stage_intents ?? {});
    if (markers.length !== 1) throw new Error('TEST_STAGE_MARKER_MISSING');
    stageMarker = markers[0];
    if (submittedCommand?.command_id !== stageMarker.command_id
      || submittedCommand.action_id !== 'secure.protocol-package.stage') throw new Error('TEST_STAGE_COMMAND_BINDING_MISSING');
    stageSignedCommandId = submittedCommand.command_id;
    const expectedPending = mode === 'stage-marker-pending' ? 1 : 0;
    if (Object.keys(agent.state.pending).length !== expectedPending) throw new Error('TEST_STAGE_PENDING_CLASS_MISMATCH');
    journal = await agent.journal(created.workspaceId);
    if (journal.checkpoint.sequence !== staged.proof.source.sequence + 1) throw new Error('TEST_STAGE_SIGNED_COMMIT_MISSING');
    const stageOperation = journal.operations.at(-1);
    if (stageOperation?.input?.package_stage?.source_id !== stageMarker.source_id
      || stageOperation.input.package_stage.part_index !== stageMarker.part_index
      || await secureHash(stageOperation.input.package_stage.source) !== await secureHash(stageMarker.source)) {
      throw new Error('TEST_STAGE_SIGNED_OPERATION_MISMATCH');
    }
    const stagedPart = stageOperation.objects?.[0];
    if (stageOperation.objects?.length !== 1
      || stagedPart?.kind !== 'protocol_package_part'
      || stagedPart.id !== staged.proof.parts[0].id
      || stagedPart.value?.index !== 0
      || stagedPart.value?.source_id !== stageMarker.source_id
      || stagedPart.value?.sha256 !== staged.proof.parts[0].sha256) throw new Error('TEST_STAGE_SIGNED_PART_MISMATCH');
    verifyStagedPackageCheckpoint(journal, staged.proof);
    if (mode === 'stage-marker-mismatch') {
      // Test-created local marker tamper only; the signed stage stays intact.
      stageMarker.source_sha256 = '0'.repeat(64);
      agent.save();
    }
    if (mode === 'stage-marker-command-mismatch') {
      // A syntactically valid local marker selects a different signed command.
      stageMarker.command_id = randomBytes(32).toString('base64url');
      agent.save();
    }
  }
  let kernelSource = null;
  if (mode === 'kernel-jws-source') {
    const unrelated = await agent.create('Unrelated signed-command scope', 'PRIVATE');
    const targetWiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    const unrelatedJournal = await agent.journal(unrelated.workspaceId);
    const unrelatedWiki = unrelatedJournal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!targetWiki || !unrelatedWiki) throw new Error('KERNEL_WIKI_MISSING');
    const accepted = await agent.transport.submit({
      workspace_id: null, instance_id: null, protocol_digest: null, action_id: 'workspace.create',
      expected_workspace_revision: null, expected_instance_revision: null, exact_input_refs: [],
      body: { name: 'Accepted kernel source row', visibility: 'PUBLIC' },
    });
    const prepareWiki = (workspaceId, wiki, title) => agent.transport.prepare({
      workspace_id: workspaceId, instance_id: wiki.id, protocol_digest: wiki.value.protocol_digest,
      action_id: 'wiki.create', expected_workspace_revision: null, expected_instance_revision: null,
      exact_input_refs: [], body: { title, body: 'Signed but not submitted' },
    });
    const selected = prepareWiki(created.workspaceId, targetWiki, 'Selected Owner kernel intent');
    const other = prepareWiki(unrelated.workspaceId, unrelatedWiki, 'Unrelated Owner kernel intent');
    kernelSource = {
      audience: agent.transport.discovery.audience,
      accepted_command_id: accepted.command_id,
      accepted_intent_digest: accepted.verifiedReceipt.intent_digest,
      accepted_workspace_id: accepted.result.workspace_id,
      selected_command_id: selected.commandId,
      selected_intent_digest: selected.intentDigest,
      unrelated_workspace_id: unrelated.workspaceId,
      unrelated_command_id: other.commandId,
      unrelated_intent_digest: other.intentDigest,
      pending_ids: agent.transport.pending(),
    };
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
    protocol_format_ceiling: journal.policy.payload.protocol_format_ceiling ?? null,
    structure_mode: journal.policy.payload.structure_mode ?? null,
    visibility,
    structured,
    sequence: journal.checkpoint.sequence,
    state_path: statePath,
    pem_path: pemPath,
    intent_db_path: intentDbPath,
    pending_count: Object.keys(agent.state.pending).length,
    pending_command_id: Object.keys(agent.state.pending)[0] ?? null,
    pending_commit_hash: Object.values(agent.state.pending)[0]?.body?.commit
      ? await secureHash(Object.values(agent.state.pending)[0].body.commit) : null,
    stage_marker: stageMarker ? {
      command_id: stageMarker.command_id,
      workspace_id: stageMarker.workspace_id,
      source_id: stageMarker.source_id,
      source_sha256: stageMarker.source_sha256,
      part_index: stageMarker.part_index,
      source: stageMarker.source,
      part_id: stagePartId,
      part_sha256: stagePartSha,
    } : null,
    stage_part_count: stagePartCount,
    stage_signed_command_id: stageSignedCommandId,
    kernel_source: kernelSource,
    completed_identity_updates: Object.values(agent.state.identity_key_intents ?? {}).filter(row => row.state === 'PUBLISHED').length,
    prior_record_id: priorRecordId,
    prior_record_title: priorRecordTitle,
    prior_record_body: priorRecordBody,
  }) + '\n');
} finally {
  agent.close();
}
