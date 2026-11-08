// Opt-in fresh synthetic keyring differential against the pinned TS source.
// No fixture key material leaves the disposable protected directory.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root = resolve(import.meta.dirname, '..');
const {build} = await import(pathToFileURL(join(root, 'conformance/node_modules/esbuild/lib/main.js')).href);
const directory = await mkdtemp(join(tmpdir(), 'peerwork-native-keyring-'));
try {
  const source = join(root, 'conformance/reference/src');
  const cryptoModule = join(directory, 'crypto.mjs');
  const clientModule = join(directory, 'client.mjs');
  for (const [entry, outfile] of [
    ['workspace-secure-crypto.ts', cryptoModule],
    ['workspace-secure-client.ts', clientModule],
  ]) await build({
    entryPoints:[join(source, entry)], outfile, bundle:true, platform:'node',
    format:'esm', nodePaths:[join(root,'conformance/node_modules')], logLevel:'silent',
  });
  const tsCrypto = await import(pathToFileURL(cryptoModule).href);
  const tsClient = await import(pathToFileURL(clientModule).href);
  const workspace = Buffer.alloc(32, 19).toString('base64url');
  const recipient = await tsCrypto.createEncryptionIdentity(true);
  const privateBytes = await tsCrypto.exportRecipientPrivateKey(recipient.privateKey);
  const keyring = tsClient.rotateSecureKeyring(tsClient.newSecureKeyring(workspace), 3);
  const context = {v:1, workspace_id:workspace, grant_id:Buffer.alloc(32, 29).toString('base64url')};
  const tsBox = await tsCrypto.hpkeSeal(recipient.publicKeyJwk, keyring, context);
  const inputPath = join(directory,'input.json'), outputPath = join(directory,'output.json');
  await writeFile(inputPath, JSON.stringify({
    workspace_id:workspace, recipient_public:recipient.publicKeyJwk,
    recipient_private:Buffer.from(privateBytes).toString('base64url'),
    keyring, context, ts_box:tsBox,
  }), {flag:'wx',mode:0o600});
  privateBytes.fill(0);
  const cargo = process.env.PEERWORK_CARGO_BIN ?? 'cargo';
  const result = spawnSync(cargo, [
    'test','-p','peerwork-core','tracked_ts_keyring_hpke_cross_open','--offline','--locked',
  ], {cwd:root, env:{
    ...process.env,
    PEERWORK_KEYRING_VECTOR_IN:inputPath,
    PEERWORK_KEYRING_VECTOR_OUT:outputPath,
  },encoding:'utf8'});
  if (result.status !== 0) throw new Error(`native keyring check failed: ${result.stderr.slice(-3000)}`);
  const {native_box:nativeBox} = JSON.parse(await readFile(outputPath,'utf8'));
  assert.deepEqual(await tsCrypto.hpkeOpen(recipient.privateKey,nativeBox,context),keyring);
  await assert.rejects(() => tsCrypto.hpkeOpen(recipient.privateKey,nativeBox,{
    ...context,grant_id:Buffer.alloc(32,30).toString('base64url'),
  }));
  console.log('native↔tracked TS keyring HPKE cross-open passed in both directions; altered context rejected');
} finally {
  await rm(directory,{recursive:true,force:true});
}
