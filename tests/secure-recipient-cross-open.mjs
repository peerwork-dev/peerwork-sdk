// Opt-in native P-256 recipient/certificate compatibility with pinned TS.
// All private bytes are synthetic, mode-0600 and removed after this run.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root = resolve(import.meta.dirname, '..');
const {build} = await import(pathToFileURL(join(root, 'conformance/node_modules/esbuild/lib/main.js')).href);
const directory = await mkdtemp(join(tmpdir(), 'peerwork-native-recipient-'));
try {
  const vectorPath = join(directory, 'synthetic-recipient.json');
  const cargo = process.env.PEERWORK_CARGO_BIN ?? 'cargo';
  const test = spawnSync(cargo, [
    'test','-p','peerwork-core','tracked_ts_recipient_certificate_vector',
    '--offline','--locked',
  ], {cwd:root,env:{...process.env,PEERWORK_RECIPIENT_VECTOR_OUT:vectorPath},encoding:'utf8'});
  if (test.status !== 0) throw new Error(`native recipient test failed: ${test.stderr.slice(-3000)}`);
  const output = join(directory, 'tracked-secure-crypto.mjs');
  await build({
    entryPoints:[join(root,'conformance/reference/src/workspace-secure-crypto.ts')],
    outfile:output,bundle:true,platform:'node',format:'esm',
    nodePaths:[join(root,'conformance/node_modules')],logLevel:'silent',
  });
  const ts = await import(pathToFileURL(output).href);
  const vector = JSON.parse(await readFile(vectorPath,'utf8'));
  assert.ok(await ts.verifyEncryptionKeyCertificate(vector.certificate,{
    actorId:vector.actor_id,signingKeyId:vector.signing_key,now:vector.issued_at+1,
  }));
  assert.equal(vector.certificate.payload.encryption_key_id,vector.encryption_key_id);
  const privateBytes = Buffer.from(vector.recipient_private,'base64url');
  const privateKey = await ts.importRecipientPrivateKey(privateBytes);
  privateBytes.fill(0);
  const context = {v:1,workspace_id:Buffer.alloc(32,17).toString('base64url')};
  const box = await ts.hpkeSeal(vector.recipient_public,{v:1,ping:'native-key'},context);
  assert.deepEqual(await ts.hpkeOpen(privateKey,box,context),{v:1,ping:'native-key'});
  const changed = structuredClone(vector.certificate);
  changed.payload.encryption_key_id = Buffer.alloc(32,99).toString('base64url');
  assert.equal(await ts.verifyEncryptionKeyCertificate(changed,{
    actorId:vector.actor_id,signingKeyId:vector.signing_key,now:vector.issued_at+1,
  }),null);
  console.log('native recipient certificate and private serialization verified by tracked TypeScript; changed certificate refused');
} finally {
  await rm(directory,{recursive:true,force:true});
}
