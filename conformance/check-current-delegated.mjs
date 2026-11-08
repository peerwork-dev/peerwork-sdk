// Optional comparison against an explicitly supplied tracked service checkout.
// The portable frozen/corrected SDK oracles live in this repository instead.
import {build} from 'esbuild';
import {createHash} from 'node:crypto';
import {readFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const checkout = process.argv[2];
if (!checkout) throw Error('usage: node conformance/check-current-delegated.mjs <tracked-source-checkout>');
const source = resolve(checkout, 'src');
const expectedClientHash = '35d33c4cbe271af7f27a886c33daadc2f6e28a70d11a8e917bfc9c1a4a1bc5ce';
const clientSource = await readFile(join(source, 'workspace-secure-client.ts'));
if (createHash('sha256').update(clientSource).digest('hex') !== expectedClientHash) {
  throw Error('tracked client source differs from pinned f828b6c');
}
const directory = await mkdtemp(join(tmpdir(), 'peerwork-current-delegated-'));
try {
  const output = join(directory, 'oracle.mjs');
  await build({stdin: {contents: `export {verifyJournal} from '${source}/workspace-secure-client.ts'`,
    resolveDir: source, sourcefile: 'oracle.ts'}, outfile: output, bundle: true,
    platform: 'node', format: 'esm', logLevel: 'silent'});
  const {verifyJournal} = await import(pathToFileURL(output));
  const data = JSON.parse(await readFile(new URL('./signed-recovery-vectors.json', import.meta.url), 'utf8'));
  for (const name of ['signed_delegated_wiki_action_corrected', 'signed_delegated_zero_record_action']) {
    const row = data.cases.find(caseRow => caseRow.name === name);
    if (!row) throw Error(`missing case: ${name}`);
    const journal = await verifyJournal({workspaceId: row.workspace_id,
      policies: [row.policy], commits: row.commits, checkpoint: row.checkpoint,
      keyring: row.keyring, trustedOwner: {actorId: row.owner.actor_id, key: row.owner.key}});
    console.log(JSON.stringify({name, accepted: true, operations: journal.operations.length,
      objects: journal.objects.length}));
  }
} finally {
  await rm(directory, {recursive: true, force: true});
}
