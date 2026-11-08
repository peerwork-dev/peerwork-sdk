// Local HTTP fixture gate; this does not import or recover anything natively.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, openSync, closeSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { DatabaseSync } from 'node:sqlite';
const [referenceRoot, sdkRoot, testRoot, mode] = process.argv.slice(2);
if (!referenceRoot || !sdkRoot || !testRoot || !['part1-before-post', 'part1-applied-loss'].includes(mode)) {
  throw new Error('PARTIAL_OBJECT_SETUP_INPUT');
}
mkdirSync(testRoot, { recursive: true, mode: 0o700 });
const stderr = openSync(join(testRoot, 'service.stderr'), 'wx', 0o600);
const server = spawn(process.execPath, [join(sdkRoot, 'tests/reference-kernel-server.mjs')], {
  env: { ...process.env, PEERWORK_REFERENCE_ROOT: referenceRoot,
    PEERWORK_TEST_STATE: testRoot, PEERWORK_TEST_FIRST_POST_MODE: 'normal' },
  stdio: ['ignore', 'pipe', stderr],
});
try {
  const lines = createInterface({ input: server.stdout });
  let timer;
  const ready = await Promise.race([
    (async () => { for await (const line of lines) return JSON.parse(line); throw new Error('PARTIAL_OBJECT_SERVICE_EOF'); })(),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('PARTIAL_OBJECT_SERVICE_TIMEOUT')), 30000); }),
  ]).finally(() => clearTimeout(timer));
  if (typeof ready.origin !== 'string') throw new Error('PARTIAL_OBJECT_ORIGIN');
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(sdkRoot, 'tests/legacy-owner-partial-object-stage.mjs'),
      ready.origin, join(testRoot, 'source'), referenceRoot, mode], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 65536) child.kill(); });
    child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 65536) child.kill(); });
    child.once('error', reject); child.once('close', code => resolve({ code, stdout, stderr }));
  });
  for (const [name, value] of Object.entries(output)) {
    writeFileSync(join(testRoot, `helper.${name}`), String(value), { mode: 0o600, flag: 'wx' });
  }
  if (output.code !== 0) throw new Error(`PARTIAL_OBJECT_HELPER_FAILED rc=${output.code} stderr_sha256=${createHash('sha256').update(output.stderr).digest('hex')}`);
  const fixture = JSON.parse(output.stdout), applied = mode.endsWith('applied-loss');
  if (fixture.mode !== mode || fixture.part_index !== 1 || fixture.part_count !== 2
    || fixture.initial_sequence !== 1 || fixture.pending_sequence !== 3
    || fixture.latest_sequence !== (applied ? 3 : 2) || fixture.accepted_part_count !== (applied ? 2 : 1)
    || fixture.latest_structure_state !== 'ACTIVE' || fixture.install_intent_count !== 0
    || fixture.selected_installation_exists !== false || !fixture.compiler_equality || !fixture.exact_operation_verified
    || fixture.pending_action_id !== 'secure.protocol-object.stage'
    || fixture.selected_predecessor.sequence !== 2 || fixture.original_checkpoint.sequence !== 1) {
    throw new Error('PARTIAL_OBJECT_FIXTURE_SHAPE');
  }
  const db = new DatabaseSync(join(testRoot, 'control.sqlite'), { readOnly: true });
  try {
    const rows = db.prepare('SELECT sequence,command_id,action_id,commit_hash FROM secure_commits WHERE workspace_id=? ORDER BY sequence').all(fixture.workspace_id);
    const selected = rows.filter(row => row.command_id === fixture.pending_command_id);
    if (rows.length !== fixture.latest_sequence || selected.length !== Number(applied)
      || selected.some(row => row.sequence !== 3 || row.commit_hash !== fixture.pending_commit_hash)
      || rows.filter(row => row.action_id === 'secure.protocol-object.stage').length !== fixture.accepted_part_count
      || rows.some(row => row.action_id.startsWith('secure.structure.'))) throw new Error('PARTIAL_OBJECT_SIGNED_COUNTS');
  } finally { db.close(); }
  process.stdout.write(JSON.stringify({ mode, result: 'PASS', part_index: 1, part_count: 2,
    source_sequence: 1, selected_predecessor_sequence: 2, pending_sequence: 3,
    current_sequence: fixture.latest_sequence, accepted_parts: fixture.accepted_part_count,
    current_state: 'ACTIVE', pending_action_id: fixture.pending_action_id, original_request_hash_bound: true,
    compiler_full_value_equal: true, exact_selected_operation_verified: true,
    install_intents: 0, begin_commits: 0, selected_instance_installed: false }) + '\n');
} finally {
  if (server.exitCode === null && server.signalCode === null) {
    server.kill(); await new Promise(resolve => server.once('exit', resolve));
  }
  closeSync(stderr);
}
