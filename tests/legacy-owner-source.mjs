// Test-created exportable legacy Owner source. Pinned pre-v3 Agent code signs
// a genuine PRIVATE wire-v1 workspace on the current service's PREPARE path.
// Public IDs only leave this process; PEM/state/SQLite remain mode-protected.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, legacyRoot, mode = 'clean'] = process.argv.slice(2);
if (!origin || !sourceDir || !legacyRoot) throw new Error('LEGACY_TEST_INPUT_REQUIRED');
if (!['clean', 'completed', 'legacy-record', 'pending', 'pending-before-post', 'pending-private-structured', 'pending-private-structured-before-post', 'pending-public', 'pending-public-before-post', 'pending-public-structured', 'pending-public-structured-before-post', 'pending-current-private', 'pending-current-private-before-post', 'pending-current-private-structured', 'pending-current-private-structured-before-post', 'pending-current-private-structured-ceiling2', 'pending-current-private-structured-ceiling2-before-post', 'pending-current-public', 'pending-current-public-before-post', 'pending-current-public-structured', 'pending-current-public-structured-before-post', 'stage-marker-completed', 'stage-marker-pending', 'stage-marker-mismatch', 'stage-marker-command-mismatch', 'stage-marker-before-post', 'stage-marker-orphan', 'stage-marker-multipart-final', 'stage-marker-multipart-intermediate', 'stage-marker-multipart-final-later', 'stage-marker-multipart-pending-applied-index1', 'stage-marker-multipart-pending-before-post-index1', 'stage-marker-multipart-orphan-index1', 'kernel-jws-source', 'unknown-store', 'malformed-store', 'legacy-structured', 'legacy-public', 'legacy-public-structured', 'legacy-public-record', 'legacy-public-structured-record', 'private-missing-ring'].includes(mode)) throw new Error('LEGACY_TEST_MODE_INVALID');
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
  let stageParts = null;
  let stagePartId = null;
  let stagePartSha = null;
  let stageSignedCommandId = null;
  let orphanStageMaterialJson = null;
  let pendingStageMaterialJson = null;
  let wrongPendingStageMaterialJson = null;
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
    const multipart = mode.startsWith('stage-marker-multipart-');
    const pendingMultipart = mode.startsWith('stage-marker-multipart-pending-');
    const orphanMultipart = mode === 'stage-marker-multipart-orphan-index1';
    // Documentation is package material but not a protocol behavior change.
    // This remains within the pinned package file budget. The selected
    // pending/orphan index-1 modes make at least three real source parts;
    // other multipart modes make two under the f828 64 KiB per-part limit.
    if (multipart) files['README.md'] += '\n' + 'A'.repeat(pendingMultipart || orphanMultipart ? 150000 : 70000);
    const bundle = parseProtocolPackage({ format: PROTOCOL_PACKAGE_FORMAT, files });
    const material = { v: 1, closure: createProtocolPackageClosure(bundle, []), bindings: {} };
    if (mode === 'stage-marker-orphan' || orphanMultipart) orphanStageMaterialJson = JSON.stringify(material);
    if (pendingMultipart) {
      pendingStageMaterialJson = JSON.stringify(material);
      const wrongBundle = parseProtocolPackage({
        format: PROTOCOL_PACKAGE_FORMAT,
        files: { ...files, 'README.md': files['README.md'] + '\nDifferent source material' },
      });
      wrongPendingStageMaterialJson = JSON.stringify({
        v: 1, closure: createProtocolPackageClosure(wrongBundle, []), bindings: {},
      });
    }
    const staged = createProtocolPackageSource(material, journal.checkpoint);
    if (pendingMultipart) {
      const wrongStaged = createProtocolPackageSource(JSON.parse(wrongPendingStageMaterialJson), journal.checkpoint);
      if (wrongStaged.parts.length !== staged.parts.length || wrongStaged.proof.source_id === staged.proof.source_id) {
        throw new Error('TEST_ALTERNATE_STAGE_MATERIAL_NOT_DISTINCT');
      }
    }
    if (pendingMultipart || orphanMultipart ? staged.parts.length < 3 : staged.parts.length !== (multipart ? 2 : 1)) throw new Error('TEST_STAGE_PART_COUNT_UNEXPECTED');
    stagePartCount = staged.parts.length;
    stageParts = staged.proof.parts;
    const originalPost = agent.post.bind(agent);
    const originalRequest = agent.request.bind(agent);
    const beforePost = mode === 'stage-marker-before-post' || mode === 'stage-marker-multipart-pending-before-post-index1';
    const orphan = mode === 'stage-marker-orphan' || orphanMultipart;
    const applied = !beforePost && !orphan;
    const stopAt = multipart && mode !== 'stage-marker-multipart-intermediate' ? 2 : 1;
    let stopped = false;
    let dropArmed = false;
    let stagePosts = 0;
    let submittedCommand = null;
    agent.post = async (...args) => {
      stagePosts++;
      submittedCommand = {
        command_id: args[2], action_id: args[1]?.commit?.payload?.action_id,
      };
      if (orphan && !stopped && (!orphanMultipart || stagePosts === 2)) {
        stopped = true;
        throw new Error('TEST_STOP_AFTER_STAGE_MARKER_SAVE');
      }
      if (mode === 'stage-marker-multipart-pending-applied-index1' && stagePosts === 2) {
        const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
        if (!hook.ok) throw new Error('TEST_STAGE_DROP_HOOK_FAILED');
        dropArmed = true;
      }
      const result = await originalPost(...args);
      if ((mode === 'stage-marker-completed' || mode === 'stage-marker-mismatch' || mode === 'stage-marker-command-mismatch' || multipart) && !stopped && stagePosts === stopAt) {
        stopped = true;
        throw new Error('TEST_STOP_AFTER_STAGE_POST');
      }
      return result;
    };
    if (mode === 'stage-marker-pending') {
      const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
      if (!hook.ok) throw new Error('TEST_STAGE_DROP_HOOK_FAILED');
    }
    if (beforePost) {
      agent.request = async (path, options) => {
        if (!stopped && (!pendingMultipart || stagePosts === 2) && path === `/api/workspace/v1/secure/workspaces/${created.workspaceId}/commits` && options?.method === 'POST') {
          stopped = true;
          throw new Error('TEST_STOP_BEFORE_STAGE_POST');
        }
        return originalRequest(path, options);
      };
    }
    try {
      await agent.stagePackageMaterial(created.workspaceId, material, journal.checkpoint);
      throw new Error('TEST_STAGE_DID_NOT_INTERRUPT');
    } catch (error) {
      const expected = orphan ? 'TEST_STOP_AFTER_STAGE_MARKER_SAVE'
        : beforePost ? 'TEST_STOP_BEFORE_STAGE_POST'
        : mode === 'stage-marker-pending' || pendingMultipart ? null : 'TEST_STOP_AFTER_STAGE_POST';
      if (expected ? error?.message !== expected : error?.message === 'TEST_STAGE_DID_NOT_INTERRUPT') throw error;
    } finally { agent.post = originalPost; agent.request = originalRequest; }
    if ((beforePost || orphan || (mode !== 'stage-marker-pending' && !pendingMultipart)) && !stopped) throw new Error('TEST_STAGE_STOP_NOT_REACHED');
    const markers = Object.values(agent.state.package_stage_intents ?? {});
    if (markers.length !== 1) throw new Error('TEST_STAGE_MARKER_MISSING');
    stageMarker = markers[0];
    if ((pendingMultipart || orphanMultipart) && (stagePosts !== 2 || stageMarker.part_index !== 1 || (mode.endsWith('applied-index1') && !dropArmed))) {
      throw new Error('TEST_STAGE_PENDING_INDEX1_NOT_REACHED');
    }
    stagePartId = staged.proof.parts[stageMarker.part_index]?.id;
    stagePartSha = staged.proof.parts[stageMarker.part_index]?.sha256;
    if (submittedCommand?.command_id !== stageMarker.command_id
      || submittedCommand.action_id !== 'secure.protocol-package.stage') throw new Error('TEST_STAGE_COMMAND_BINDING_MISSING');
    stageSignedCommandId = applied ? submittedCommand.command_id : null;
    const expectedPending = mode === 'stage-marker-pending' || beforePost || pendingMultipart ? 1 : 0;
    if (Object.keys(agent.state.pending).length !== expectedPending) throw new Error('TEST_STAGE_PENDING_CLASS_MISMATCH');
    if (expectedPending && Object.keys(agent.state.pending)[0] !== stageMarker.command_id) throw new Error('TEST_STAGE_SAVED_ID_MISMATCH');
    journal = await agent.journal(created.workspaceId);
    const expectedAppliedParts = pendingMultipart ? (beforePost ? 1 : 2) : orphanMultipart ? 1 : (applied ? stopAt : 0);
    if (journal.checkpoint.sequence !== staged.proof.source.sequence + expectedAppliedParts) throw new Error('TEST_STAGE_SIGNED_COMMIT_CLASS_MISMATCH');
    if (pendingMultipart || orphanMultipart) {
      verifyStagedPackageCheckpoint(journal, staged.proof);
      const signedPrefix = journal.operations.slice(-expectedAppliedParts);
      for (let index = 0; index < expectedAppliedParts; index++) {
        const operation = signedPrefix[index];
        const part = operation?.objects?.[0];
        if (operation?.kind !== 'ADMIN' || operation.input?.package_stage?.source_id !== staged.proof.source_id
          || operation.input.package_stage.part_index !== index || operation.objects?.length !== 1
          || part?.id !== staged.proof.parts[index]?.id || part.value?.sha256 !== staged.proof.parts[index]?.sha256) {
          throw new Error('TEST_STAGE_SIGNED_PREFIX_MISMATCH');
        }
      }
    }
    if (applied) {
      const stageOperation = journal.operations.at(-1);
      if (stageOperation?.input?.package_stage?.source_id !== stageMarker.source_id
        || stageOperation.input.package_stage.part_index !== stageMarker.part_index
        || await secureHash(stageOperation.input.package_stage.source) !== await secureHash(stageMarker.source)) {
        throw new Error('TEST_STAGE_SIGNED_OPERATION_MISMATCH');
      }
      const stagedPart = stageOperation.objects?.[0];
      if (stageOperation.objects?.length !== 1
        || stagedPart?.kind !== 'protocol_package_part'
        || stagedPart.id !== stagePartId
        || stagedPart.value?.index !== stageMarker.part_index
        || stagedPart.value?.source_id !== stageMarker.source_id
        || stagedPart.value?.sha256 !== stagePartSha) throw new Error('TEST_STAGE_SIGNED_PART_MISMATCH');
      verifyStagedPackageCheckpoint(journal, staged.proof);
    }
    if (mode === 'stage-marker-multipart-final-later') {
      const wiki = journal.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
      if (!wiki) throw new Error('TEST_STAGE_LATER_WIKI_MISSING');
      await agent.action(created.workspaceId, wiki.id, 'wiki.create', {
        title: 'After completed multipart stage', body: 'Authenticated later history',
      });
      journal = await agent.journal(created.workspaceId);
      if (journal.checkpoint.sequence !== staged.proof.source.sequence + 3) throw new Error('TEST_STAGE_LATER_HISTORY_MISSING');
    }
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
    stage_parts: stageParts,
    stage_applied: mode.startsWith('stage-marker-') ? !['stage-marker-before-post', 'stage-marker-orphan', 'stage-marker-multipart-orphan-index1', 'stage-marker-multipart-pending-before-post-index1'].includes(mode) : null,
    stage_signed_command_id: stageSignedCommandId,
    orphan_stage_material_json: orphanStageMaterialJson,
    pending_stage_material_json: pendingStageMaterialJson,
    wrong_pending_stage_material_json: wrongPendingStageMaterialJson,
    kernel_source: kernelSource,
    completed_identity_updates: Object.values(agent.state.identity_key_intents ?? {}).filter(row => row.state === 'PUBLISHED').length,
    prior_record_id: priorRecordId,
    prior_record_title: priorRecordTitle,
    prior_record_body: priorRecordBody,
  }) + '\n');
} finally {
  agent.close();
}
