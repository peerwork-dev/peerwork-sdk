// Fixture-only service gate. It proves that the public f828 client naturally
// creates three distinct install-intent states; it does not import them.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, openSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { DatabaseSync } from 'node:sqlite';

const [referenceRoot, sdkRoot, testRoot] = process.argv.slice(2);
if (!referenceRoot || !sdkRoot || !testRoot) throw new Error('INSTALL_SETUP_INPUT');
mkdirSync(testRoot, { recursive: true, mode: 0o700 });
const stderrFile = openSync(join(testRoot, 'service.stderr'), 'w', 0o600);
const server = spawn(process.execPath, [join(sdkRoot, 'tests/reference-kernel-server.mjs')], {
  env: { ...process.env, PEERWORK_REFERENCE_ROOT: referenceRoot,
    PEERWORK_TEST_STATE: testRoot, PEERWORK_TEST_FIRST_POST_MODE: 'normal' },
  stdio: ['ignore', 'pipe', stderrFile],
});
try {
  const lines = createInterface({ input: server.stdout });
  const ready = await Promise.race([
    (async () => { for await (const line of lines) return JSON.parse(line); throw new Error('SERVICE_EOF'); })(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('SERVICE_READINESS_TIMEOUT')), 30000)),
  ]);
  if (typeof ready.origin !== 'string') throw new Error('SERVICE_ORIGIN_MISSING');
  const db = new DatabaseSync(join(testRoot, 'control.sqlite'), { readOnly: true });
  try {
    // The original three modes have a separate frozen setup result. Exercise
    // only the newly added closure-backed direct subset in this successor.
    const selected = process.env.PEERWORK_INSTALL_SETUP_MODE;
    if (selected && !['direct-completed-end', 'complete-action', 'complete-rotate',
      'direct-page-before-post', 'direct-page-applied-loss',
      'direct-end-before-post', 'direct-end-applied-loss',
      'direct-checkpoint-begin-before-post', 'direct-checkpoint-end-applied-loss',
      'direct-checkpoint-completed-end', 'direct-disclosure-begin-before-post',
      'direct-disclosure-end-applied-loss', 'direct-no-grants-begin-before-post',
      'direct-empty-disclosure-begin-before-post', 'direct-composition-begin-before-post',
      'direct-composition-end-applied-loss', 'direct-staged-package-begin-before-post',
      'direct-staged-package-end-applied-loss', 'direct-staged-package-page-before-post',
    'direct-staged-package-page-applied-loss', 'direct-staged-package-completed-end'].includes(selected)) {
      throw new Error('INSTALL_SETUP_MODE_INVALID');
    }
    for (const mode of selected ? [selected]
      : ['direct-begin-applied-loss', 'direct-begin-before-post']) {
      const sourceDir = join(testRoot, mode);
      mkdirSync(sourceDir, { mode: 0o700 });
      const later = mode.startsWith('complete-');
      const child = spawn(process.execPath, [join(sdkRoot, later
        ? 'tests/legacy-owner-install-intent-later.mjs'
        : 'tests/legacy-owner-install-intent.mjs'),
        ready.origin, sourceDir, referenceRoot, mode], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 65536) child.kill(); });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) child.kill(); });
      const code = await new Promise(resolve => child.once('exit', resolve));
      if (code !== 0) {
        writeFileSync(join(sourceDir, 'helper.stderr'), stderr, { mode: 0o600, flag: 'wx' });
        throw new Error(`INSTALL_SETUP_${mode}_FAILED: rc=${code} stderr_sha256=${createHash('sha256').update(stderr).digest('hex')}`);
      }
      const source = JSON.parse(stdout);
      const completed = mode.endsWith('completed-end') || later;
      const checkpointOption = mode.startsWith('direct-checkpoint-');
      const normalizedOptions = /^(direct-disclosure-|direct-no-grants-|direct-empty-disclosure-)/.test(mode);
      const retainedStep = /^direct-(page|end)-/.exec(mode.replace(
        /^direct-(checkpoint|disclosure|empty-disclosure|no-grants|composition|staged-package)-/, 'direct-'))?.[1];
      if (source.mode !== mode || source.pending_count !== (completed ? 0 : 1)
        || source.latest_structure_state !== (retainedStep
          ? retainedStep === 'end' && mode.endsWith('applied-loss') ? 'ACTIVE' : 'SEEDING'
          : mode.endsWith('applied-loss') ? 'SEEDING' : 'ACTIVE')
        || ((mode.startsWith('direct-') || later) && !source.material_path)
        || (later && (source.selected_sequence !== 3 || source.latest_sequence !== 4))) {
        throw new Error(`INSTALL_SETUP_${mode}_SHAPE`);
      }
      const count = db.prepare('SELECT count(*) AS count FROM secure_commits WHERE workspace_id=?').get(source.workspace_id).count;
      if (count !== source.latest_sequence) throw new Error(`INSTALL_SETUP_${mode}_REPLAY_COUNT`);
      if (checkpointOption && (source.expected_checkpoint?.v !== 1
        || source.expected_checkpoint.workspace_id !== source.workspace_id
        || source.expected_checkpoint.owner_id !== source.owner_actor_id
        || source.expected_checkpoint.owner_key !== source.owner_key_id
        || source.expected_checkpoint.sequence !== source.initial_sequence
        || source.canonical_options_hash !== source.intent_hash)) {
        throw new Error(`INSTALL_SETUP_${mode}_REVIEWED_CHECKPOINT`);
      }
      if (normalizedOptions && (source.canonical_options_hash === source.intent_hash
        || !Array.isArray(source.normalized_grants)
        || mode.startsWith('direct-no-grants-') && (source.original_grants_omitted !== true
          || source.normalized_grants.length !== 0)
        || !mode.startsWith('direct-no-grants-') && (!Array.isArray(source.normalized_disclosure)
          || source.normalized_disclosure.length !== 1
          || source.normalized_disclosure[0].protocol_digest !== source.protocol_digest))) {
        throw new Error(`INSTALL_SETUP_${mode}_NORMALIZED_OPTIONS`);
      }
      if (mode.startsWith('direct-composition-') && (source.compiler_equality !== true
        || source.explicit_dependency_count !== 1 || source.composition?.v !== 1
        || source.composition.source_digest !== source.source_digest
        || source.canonical_options_hash === source.intent_hash)) {
        throw new Error(`INSTALL_SETUP_${mode}_COMPOSITION`);
      }
      if (mode.startsWith('direct-staged-package-') && (source.compiler_equality !== true
        || !Number.isSafeInteger(source.source_parts) || source.source_parts < 1
        || source.stage_markers_cleared !== true || source.package_source?.v !== 1
        || source.package_source.source.sequence !== source.initial_sequence
        || source.begin_predecessor.sequence !== source.initial_sequence + source.source_parts
        || source.begin_predecessor.policy_hash !== source.expected_checkpoint.policy_hash
        || source.expected_checkpoint.sequence !== source.initial_sequence)) {
        throw new Error(`INSTALL_SETUP_${mode}_STAGED_SOURCE`);
      }
      if (!completed) {
        const accepted = db.prepare('SELECT count(*) AS count FROM secure_commits WHERE workspace_id=? AND command_id=?')
          .get(source.workspace_id, source.pending_command_id).count;
        if (accepted !== (mode.endsWith('applied-loss') ? 1 : 0)) throw new Error(`INSTALL_SETUP_${mode}_ACCEPTANCE`);
      }
      process.stdout.write(JSON.stringify({ mode, pending_count: source.pending_count,
        pending_action_id: source.pending_action_id ?? null,
        pending_sequence: source.pending_sequence ?? null,
        initial_sequence: source.initial_sequence, latest_sequence: source.latest_sequence,
        structure_state: source.latest_structure_state, commit_count: count,
        intent_hash_bound: true,
        ...(mode.startsWith('direct-staged-package-') ? { compiler_equality: true,
          source_parts: source.source_parts, reviewed_sequence: source.expected_checkpoint.sequence,
          begin_predecessor_sequence: source.begin_predecessor.sequence,
          stage_markers_cleared: true } : {}),
        ...(mode.startsWith('direct-composition-') ? { compiler_equality: true,
          explicit_dependency_count: source.explicit_dependency_count,
          original_options_hash_distinct: true, source_digest: source.source_digest,
          protocol_digest: source.protocol_digest } : {}),
        selected_epoch: source.selected_epoch ?? null,
        latest_epoch: source.latest_epoch ?? null,
        ...(checkpointOption ? { reviewed_checkpoint_sequence: source.expected_checkpoint.sequence,
          original_options_hash_bound: true } : {}),
        ...(normalizedOptions ? { original_options_hash_distinct: true,
          original_grants_omitted: source.original_grants_omitted,
          normalized_disclosure: source.normalized_disclosure,
          normalized_grants_count: source.normalized_grants.length,
          reviewed_checkpoint_sequence: source.expected_checkpoint?.sequence ?? null } : {}) }) + '\n');
    }
  } finally { db.close(); }
} finally {
  if (server.exitCode === null && server.signalCode === null) {
    server.kill();
    await new Promise(resolve => server.once('exit', resolve));
  }
}
