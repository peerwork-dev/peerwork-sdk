// Differential vectors from the pinned, tracked TypeScript implementation.
// Usage: PEERWORK_TS_SOURCE=/path/to/clients/secure-workspace/source/src \
//        PEERWORK_REFERENCE_NODE_MODULES=/path/to/node_modules node generate-ts-vectors.mjs
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const source = process.env.PEERWORK_TS_SOURCE;
if (!source) throw new Error('PEERWORK_TS_SOURCE must pin the accepted tracked source');
const modules = process.env.PEERWORK_REFERENCE_NODE_MODULES;
const { build } = modules
  ? await import(pathToFileURL(resolve(modules, 'esbuild/lib/main.js')))
  : await import('esbuild');
const dir = await mkdtemp(join(tmpdir(), 'peerwork-ts-vectors-'));
try {
  const entries = [
    ['kernel', 'workspace-manifest.ts'],
    ['secure', 'workspace-secure-crypto.ts'],
  ];
  for (const [name, file] of entries) {
    await build({ entryPoints: [resolve(source, file)], outfile: join(dir, `${name}.mjs`),
      bundle: true, platform: 'node', format: 'esm', nodePaths: modules ? [modules] : [], logLevel: 'silent' });
  }
  const kernel = await import(pathToFileURL(join(dir, 'kernel.mjs')));
  const secure = await import(pathToFileURL(join(dir, 'secure.mjs')));
  const cases = [
    ['plain', { z: null, a: [true, -0, 9007199254740991] }],
    ['numeric_keys', { '10': 'ten', '2': 'two', '01': 'leading', a: 1 }],
    ['utf16_keys', { '\uE000': 1, '\u{10000}': 2, '\u2028': 3 }],
    ['escaping', { a: '\u0000\n\b\u2028\u2029', 'slash/quote"': 'x\\y' }],
    ['nested', { b: { z: 0, a: [null, { y: false, x: 'λ' }] }, a: 4 }],
    ['integer_spellings', JSON.parse('{"decimal":1.0,"exponent":1e0}')],
  ];
  const out = cases.map(([name, value]) => ({ name, input: value,
    kernel: kernel.canonical(value), secure: secure.canonicalJsonText(value) }));
  const surrogate = JSON.parse('{"value":"\\ud800"}');
  const b64 = value => Buffer.from(value, 'utf8').toString('base64url');
  out.push({ name: 'lone_surrogate', input_wire_base64: b64(JSON.stringify(surrogate)),
    kernel_base64: b64(kernel.canonical(surrogate)), secure_base64: b64(secure.canonicalJsonText(surrogate)) });
  const negatives = [
    ['unsafe_integer', { a: 9007199254740992 }],
    ['fraction', { a: 1.5 }],
    ['prototype_key', JSON.parse('{"__proto__":1}')],
    ['empty_key', { '': 1 }],
    ['list_129', Array.from({ length: 129 }, (_, i) => i)],
  ];
  for (const [name, value] of negatives) {
    const row = { name };
    for (const [path, fn] of [['kernel', kernel.canonical], ['secure', secure.canonicalJsonText]]) {
      try { row[path] = fn(value); } catch (error) { row[path] = { error: String(error.message) }; }
    }
    out.push(row);
  }
  await writeFile(new URL('./ts-differential-vectors.json', import.meta.url), JSON.stringify({
    source_commit: 'dd8a9d2', evidence_commit: '4065739', cases: out,
  }, null, 2) + '\n');
} finally { await rm(dir, { recursive: true, force: true }); }
