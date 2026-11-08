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
    // This runner exercises only the new same-workspace source shape.
    // The original three modes have a separate frozen setup result. Exercise
    // only the newly added closure-backed direct subset in this successor.
    for (const mode of ['direct-same-workspace-before-post']) {
      const sourceDir = join(testRoot, mode);
      mkdirSync(sourceDir, { mode: 0o700 });
      const child = spawn(process.execPath, [join(sdkRoot,
        'tests/legacy-owner-install-same-workspace.mjs'),
        ready.origin, sourceDir, referenceRoot], { stdio: ['ignore', 'pipe', 'pipe'] });
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
      if (source.mode !== mode || source.pending_count !== 1
        || source.latest_structure_state !== 'ACTIVE'
        || source.initial_sequence !== 3 || source.latest_sequence !== 3
        || source.instance_id === source.retained_instance_id
        || !source.material_path || !source.retained_intent_hash) {
        throw new Error('SAME_WORKSPACE_SETUP_SHAPE');
      }
      const count = db.prepare('SELECT count(*) AS count FROM secure_commits WHERE workspace_id=?').get(source.workspace_id).count;
      if (count !== source.latest_sequence) throw new Error(`INSTALL_SETUP_${mode}_REPLAY_COUNT`);
      const accepted = db.prepare('SELECT count(*) AS count FROM secure_commits WHERE workspace_id=? AND command_id=?')
        .get(source.workspace_id, source.pending_command_id).count;
      if (accepted !== 0) throw new Error('SAME_WORKSPACE_SETUP_B_ACCEPTED');
      process.stdout.write(JSON.stringify({ mode, pending_count: source.pending_count,
        initial_sequence: source.initial_sequence, latest_sequence: source.latest_sequence,
        structure_state: source.latest_structure_state, commit_count: count,
        same_workspace_map_count: 2, selected_begin_accepted: false,
        selected_and_retained_hashes_bound: true }) + '\n');
    }
  } finally { db.close(); }
} finally {
  if (server.exitCode === null && server.signalCode === null) {
    server.kill();
    await new Promise(resolve => server.once('exit', resolve));
  }
}
