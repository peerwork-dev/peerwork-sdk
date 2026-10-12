// Dynamic synthetic direct TypeScript owner-grant oracle for the native core.
// Recipient private material exists only in a mode-0600 temp fixture and is
// removed on exit; no service state or operator key is read.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root = resolve(import.meta.dirname, '..');
const {build} = await import(pathToFileURL(join(root, 'conformance/node_modules/esbuild/lib/main.js')).href);
const directory = await mkdtemp(join(tmpdir(), 'peerwork-grant-oracle-'));
try {
  const clientOutput = join(directory, 'secure-client.mjs');
  const cryptoOutput = join(directory, 'secure-crypto.mjs');
  for (const [source, output] of [
    ['workspace-secure-client.ts', clientOutput],
    ['workspace-secure-crypto.ts', cryptoOutput],
  ]) await build({entryPoints:[join(root,'conformance/reference/src',source)],outfile:output,
    bundle:true,platform:'node',format:'esm',nodePaths:[join(root,'conformance/node_modules')],logLevel:'silent'});
  const client = await import(pathToFileURL(clientOutput).href);
  const crypto = await import(pathToFileURL(cryptoOutput).href);
  const owner = await crypto.createSigningIdentity();
  const recipient = await crypto.createEncryptionIdentity(true);
  const now = 1_700_000_000_000;
  const certificate = await crypto.certifyEncryptionKey(owner, recipient, now);
  const workspace = client.secureToken();
  const policy = await client.createPolicy(owner, {
    v:1,workspace_id:workspace,owner_id:owner.actorId,signing_key:owner.keyId,
    version:1,previous_policy:null,effective_sequence:1,visibility:'PRIVATE',
    epoch:1,members:[{actor_id:owner.actorId,certificate,role:'OWNER',scopes:[]}],
    issued_at:now,
  });
  await client.verifyPolicyChain([policy],workspace);
  const keyring = client.newSecureKeyring(workspace);
  const grant = await client.createKeyGrant({identity:owner,recipient:certificate,policy,keyring,issuedAt:now+1});
  assert.deepEqual(await client.openKeyGrant({grant,recipient:certificate,privateKey:recipient.privateKey,
    policy,policies:[policy],owner:{actorId:owner.actorId,key:owner.keyId},now:now+2}),keyring);
  const wrongRecipient = await crypto.certifyEncryptionKey(owner,await crypto.createEncryptionIdentity(true),now);
  await assert.rejects(client.openKeyGrant({grant,recipient:wrongRecipient,privateKey:recipient.privateKey,
    policy,policies:[policy],owner:{actorId:owner.actorId,key:owner.keyId},now:now+2}));
  const changedEpoch = structuredClone(grant);
  changedEpoch.payload.epoch = 2;
  await assert.rejects(client.openKeyGrant({grant:changedEpoch,recipient:certificate,privateKey:recipient.privateKey,
    policy,policies:[policy],owner:{actorId:owner.actorId,key:owner.keyId},now:now+2}));
  const changedPolicy = structuredClone(grant);
  changedPolicy.payload.policy_hash = 'a'.repeat(64);
  await assert.rejects(client.openKeyGrant({grant:changedPolicy,recipient:certificate,privateKey:recipient.privateKey,
    policy,policies:[policy],owner:{actorId:owner.actorId,key:owner.keyId},now:now+2}));
  const privateBytes = Buffer.from(await crypto.exportRecipientPrivateKey(recipient.privateKey));
  const vector = {
    policy,grant,certificate,wrong_recipient:wrongRecipient,workspace,owner_actor:owner.actorId,owner_key:owner.keyId,
    checkpoint:{v:1,workspace_id:workspace,owner_id:owner.actorId,owner_key:owner.keyId,
      sequence:0,head:null,policy_hash:await client.secureHash(policy)},
    recipient_private:privateBytes.toString('base64url'),now:now+2,
  };
  privateBytes.fill(0);
  const vectorPath = join(directory,'synthetic-grant.json');
  await writeFile(vectorPath,JSON.stringify(vector),{mode:0o600,flag:'wx'});
  const cargo = process.env.PEERWORK_CARGO_BIN ?? 'cargo';
  const result = spawnSync(cargo,['test','-p','peerwork-core','direct_ts_owner_grant_vector',
    '--offline','--locked'],{cwd:root,env:{...process.env,PEERWORK_GRANT_VECTOR:vectorPath},encoding:'utf8'});
  if(result.status!==0)throw new Error(`native grant vector failed: ${result.stderr.slice(-3000)}`);
  assert.equal((await readFile(vectorPath,'utf8')).length>0,true);
  console.log('direct TypeScript owner grant and native signed-policy/HPKE/keyring proof agree; tamper, wrong recipient, epoch and policy rejected');
} finally {
  await rm(directory,{recursive:true,force:true});
}
