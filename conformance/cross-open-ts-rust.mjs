// Run from repository root with the same PEERWORK_TS_SOURCE and
// PEERWORK_REFERENCE_NODE_MODULES variables as generate-ts-vectors.mjs.
// Ephemeral test keys move only over the bridge process's stdin.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const source = process.env.PEERWORK_TS_SOURCE;
if (!source) throw new Error('PEERWORK_TS_SOURCE is required');
const modules = process.env.PEERWORK_REFERENCE_NODE_MODULES;
const { build: esbuild } = modules
  ? await import(pathToFileURL(resolve(modules, 'esbuild/lib/main.js')))
  : await import('esbuild');
const dir = await mkdtemp(join(tmpdir(), 'peerwork-e2ee-cross-'));
try {
  const output = join(dir, 'secure.mjs');
  await esbuild({ entryPoints: [resolve(source, 'workspace-secure-crypto.ts')], outfile: output,
    bundle: true, platform: 'node', format: 'esm', nodePaths: modules ? [modules] : [], logLevel: 'silent' });
  const ts = await import(pathToFileURL(output));
  console.error('compiled tracked TS secure module');
  const b64 = bytes => Buffer.from(bytes).toString('base64url');
  const bridge = request => new Promise((resolveResult, rejectResult) => {
    const binary = process.env.PEERWORK_E2EE_BRIDGE ?? resolve('target/debug/examples/e2ee_bridge');
    const child = spawn(binary, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', rejectResult);
    child.on('close', code => { clearTimeout(timer); if (code === 0) {
      try { resolveResult(JSON.parse(stdout)); } catch (error) { rejectResult(error); }
    } else rejectResult(new Error(`Rust bridge failed (${code}): ${stderr}`)); });
    child.stdin.end(JSON.stringify(request));
  });
  const context = { workspace_id: 'cross-open-test', epoch: 1 };
  const plaintext = { epoch: 1, content: 'cross-language' };
  const recipient = await ts.createEncryptionIdentity(true);
  console.error('generated ephemeral recipient');
  const recipientPrivate = await ts.exportRecipientPrivateKey(recipient.privateKey);
  const boxFromTs = await ts.hpkeSeal(recipient.publicKeyJwk, plaintext, context);
  console.error('TS sealed HPKE box');
  assert.deepEqual(await bridge({ op: 'open_key_box', private_key: b64(recipientPrivate), sealed: boxFromTs, context }), plaintext);
  const boxFromRust = await bridge({ op: 'seal_key_box', recipient: recipient.publicKeyJwk, plaintext, context });
  assert.deepEqual(await ts.hpkeOpen(recipient.privateKey, boxFromRust, context), plaintext);
  await assert.rejects(() => ts.hpkeOpen(recipient.privateKey, boxFromRust, { ...context, epoch: 2 }));
  const keyBytes = new Uint8Array(32).fill(23);
  const aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const bytes = new TextEncoder().encode('cross-language content');
  const sealedFromTs = await ts.sealContentBytes(aesKey, bytes, context);
  assert.equal(Buffer.from((await bridge({ op: 'open_content', key: b64(keyBytes), sealed: sealedFromTs, context })).plaintext, 'base64url').toString(), 'cross-language content');
  const sealedFromRust = await bridge({ op: 'seal_content', key: b64(keyBytes), plaintext: b64(bytes), context });
  assert.equal(new TextDecoder().decode(await ts.openContentBytes(aesKey, sealedFromRust, context)), 'cross-language content');
  await assert.rejects(() => ts.openContentBytes(aesKey, sealedFromRust, { ...context, epoch: 2 }));
  console.log('TS/Rust HPKE and AES-GCM cross-open: 4 directions passed; context tampering rejected');
} finally { await rm(dir, { recursive: true, force: true }); }
