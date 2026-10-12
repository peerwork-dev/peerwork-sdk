// Exact tracked f828b6c collaboration presets; development-time fixture only.
// Rust embeds the output and needs no Node runtime to create a workspace.
import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const source = resolve('reference/src/workspace-presets.ts');
const bytes = await readFile(source);
const sourceHash = createHash('sha256').update(bytes).digest('hex');
if (sourceHash !== '2e85ed64b4ff63737cfe5fc2fd47f270dc8bb488533a5a287a0270d5702223bd')
  throw new Error('tracked workspace-presets source differs from f828b6c');
const dir = await mkdtemp(join(tmpdir(), 'peerwork-bootstrap-presets-'));
try {
  const output = join(dir, 'presets.mjs');
  await build({entryPoints:[source], outfile:output, bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {COLLABORATION_PRESETS} = await import(pathToFileURL(output));
  const manifestOutput = join(dir, 'manifest.mjs');
  await build({entryPoints:[resolve('reference/src/workspace-manifest.ts')], outfile:manifestOutput,
    bundle:true, platform:'node', format:'esm', logLevel:'silent'});
  const {manifestCanonical} = await import(pathToFileURL(manifestOutput));
  const entries = [];
  for (const [entrypoint, factory] of Object.entries(COLLABORATION_PRESETS)) {
    const manifest = factory();
    const canonical = manifestCanonical(manifest).canonical;
    const digest = createHash('sha256').update(canonical).digest('hex');
    entries.push({entrypoint, digest, manifest});
  }
  if (entries.length !== 6) throw new Error('collaboration preset count changed');
  await writeFile('bootstrap-presets.json', JSON.stringify({source_sha256:sourceHash, entries})+'\n');
} finally {
  await rm(dir, {recursive:true,force:true});
}
