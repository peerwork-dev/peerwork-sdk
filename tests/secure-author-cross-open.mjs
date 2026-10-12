// Opt-in native-author → pinned TypeScript verifier/decryptor differential.
// All keys and ciphertext here are synthetic and remain in a disposable file.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root = resolve(import.meta.dirname, '..');
const {build} = await import(pathToFileURL(join(root, 'conformance/node_modules/esbuild/lib/main.js')).href);
const directory = await mkdtemp(join(tmpdir(), 'peerwork-native-secure-author-'));
try {
  const vectorPath = join(directory, 'synthetic-vector.json');
  const cargo = process.env.PEERWORK_CARGO_BIN ?? 'cargo';
  const test = spawnSync(cargo, [
    'test','-p','peerwork-core',
    'prepared_secure_author::tests::native_private_author_signs_and_seals_exact_saved_request',
    '--offline','--locked',
  ], {cwd:root,env:{...process.env,PEERWORK_AUTHOR_VECTOR_OUT:vectorPath},encoding:'utf8'});
  if (test.status !== 0) throw new Error(`native author test failed: ${test.stderr.slice(-3000)}`);
  const output = join(directory, 'tracked-secure-crypto.mjs');
  await build({
    entryPoints:[join(root,'conformance/reference/src/workspace-secure-crypto.ts')],
    outfile:output,bundle:true,platform:'node',format:'esm',
    nodePaths:[join(root,'conformance/node_modules')],logLevel:'silent',
  });
  const ts = await import(pathToFileURL(output).href);
  const vector = JSON.parse(await readFile(vectorPath,'utf8'));
  const request = JSON.parse(vector.request);
  assert.equal(await ts.verifyCanonical(
    'peerwork.secure.commit.v3',request.commit.payload,
    request.commit.signature,vector.signing_key,
  ),true);
  const key = await crypto.subtle.importKey(
    'raw',Buffer.from(vector.epoch_key,'base64url'),
    {name:'AES-GCM'},false,['decrypt'],
  );
  const opened = await ts.openContentBytes(key,request.commit.payload.body,vector.context);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(opened)),vector.operation);
  await assert.rejects(() => ts.openContentBytes(key,request.commit.payload.body,{
    ...vector.context,sequence:vector.context.sequence+1,
  }));
  console.log('native v3 PRIVATE commit: tracked TypeScript signature and AES-GCM open passed; context tamper rejected');
} finally {
  await rm(directory,{recursive:true,force:true});
}
