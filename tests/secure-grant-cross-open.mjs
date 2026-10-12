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
    recipient_actor:owner.actorId,recipient_key:owner.keyId,
    checkpoint:{v:1,workspace_id:workspace,owner_id:owner.actorId,owner_key:owner.keyId,
      sequence:0,head:null,policy_hash:await client.secureHash(policy)},
    recipient_private:privateBytes.toString('base64url'),now:now+2,
  };
  privateBytes.fill(0);
  const member = await crypto.createSigningIdentity();
  const memberEncryption = await crypto.createEncryptionIdentity(true);
  const memberCertificate = await crypto.certifyEncryptionKey(member,memberEncryption,now);
  const invitedWorkspace = client.secureToken();
  const invitationPolicy = await client.createPolicy(owner,{
    v:1,workspace_id:invitedWorkspace,owner_id:owner.actorId,signing_key:owner.keyId,
    version:1,previous_policy:null,effective_sequence:1,visibility:'PRIVATE',epoch:1,
    members:[{actor_id:owner.actorId,certificate,role:'OWNER',scopes:[]}],issued_at:now,
  });
  const offer = await client.createInvitation({identity:owner,policy:invitationPolicy,
    recipient:memberCertificate,scopes:[],message:'synthetic',issuedAt:now,expiresAt:now+86_400_000});
  const decision = await client.createInviteDecision(member,offer,'ACCEPT',
    {actorId:owner.actorId,key:owner.keyId},now+1);
  const invitedPolicy = await client.createPolicy(owner,{
    v:1,workspace_id:invitedWorkspace,owner_id:owner.actorId,signing_key:owner.keyId,
    version:2,previous_policy:await client.secureHash(invitationPolicy),effective_sequence:2,
    visibility:'PRIVATE',epoch:1,members:[
      {actor_id:owner.actorId,certificate,role:'OWNER',scopes:[]},
      {actor_id:member.actorId,certificate:memberCertificate,role:'MEMBER',scopes:[]}],issued_at:now+1,
  });
  await client.verifyPolicyChain([invitationPolicy,invitedPolicy],invitedWorkspace);
  const signedCommit = async (selected,sequence,previous) => client.signSecure(owner,
    'peerwork.secure.commit.v1',{
      v:1,workspace_id:invitedWorkspace,sequence,previous,policy_hash:await client.secureHash(selected),
      epoch:1,actor_id:owner.actorId,signing_key:owner.keyId,command_id:client.secureToken(),
      action_id:'synthetic.header',instance_id:null,issued_at:now+sequence,delegation:null,
      mode:'PRIVATE',body:{v:1,alg:'AES-256-GCM',nonce:client.secureToken(),chunks:[client.secureToken()]},
    });
  const firstCommit = await signedCommit(invitationPolicy,1,null);
  const secondCommit = await signedCommit(invitedPolicy,2,await client.secureHash(firstCommit));
  const invitedCommits = [firstCommit,secondCommit];
  const invitedRing = client.newSecureKeyring(invitedWorkspace);
  const invitedGrant = await client.createKeyGrant({identity:owner,recipient:memberCertificate,
    policy:invitedPolicy,keyring:invitedRing,invite:{offer,decision},issuedAt:now+2});
  assert.deepEqual(await client.openKeyGrant({grant:invitedGrant,recipient:memberCertificate,
    privateKey:memberEncryption.privateKey,policy:invitedPolicy,policies:[invitationPolicy,invitedPolicy],
    owner:{actorId:owner.actorId,key:owner.keyId},expectedInvite:{offer,decision},now:now+3}),invitedRing);
  await assert.rejects(client.openKeyGrant({grant:invitedGrant,recipient:memberCertificate,
    privateKey:memberEncryption.privateKey,policy:invitedPolicy,policies:[invitationPolicy,invitedPolicy],
    owner:{actorId:owner.actorId,key:owner.keyId},now:now+3}));
  const device = await crypto.createSigningIdentity();
  const deviceEncryption = await crypto.createEncryptionIdentity(true);
  const deviceCertificate = await crypto.certifyEncryptionKey(device,deviceEncryption,now);
  const delegation = await client.signSecure(owner,'peerwork.secure.device-delegation.v1',{
    v:1,workspace_id:workspace,actor_id:owner.actorId,signing_key:owner.keyId,
    device:deviceCertificate,request_id:client.secureToken(),scope:[],read:true,
    origin:'https://synthetic.invalid',audience:'synthetic',issued_at:now,expires_at:now+86_400_000,
  });
  const delegatedGrant = await client.createKeyGrant({identity:owner,recipient:deviceCertificate,
    policy,keyring,delegation,issuedAt:now+2});
  assert.deepEqual(await client.openKeyGrant({grant:delegatedGrant,recipient:deviceCertificate,
    privateKey:deviceEncryption.privateKey,policy,policies:[policy],
    owner:{actorId:owner.actorId,key:owner.keyId},expectedDelegation:delegation,now:now+3}),keyring);
  await assert.rejects(client.openKeyGrant({grant:delegatedGrant,recipient:deviceCertificate,
    privateKey:deviceEncryption.privateKey,policy,policies:[policy],
    owner:{actorId:owner.actorId,key:owner.keyId},now:now+3}));
  await assert.rejects(client.openKeyGrant({grant:delegatedGrant,recipient:deviceCertificate,
    privateKey:deviceEncryption.privateKey,policy,policies:[policy],
    owner:{actorId:owner.actorId,key:owner.keyId},expectedDelegation:delegation,
    now:now+86_400_000}));
  const invitePrivate = Buffer.from(await crypto.exportRecipientPrivateKey(memberEncryption.privateKey));
  const devicePrivate = Buffer.from(await crypto.exportRecipientPrivateKey(deviceEncryption.privateKey));
  const vectors = [vector,{
    policy:invitedPolicy,policies:[invitationPolicy,invitedPolicy],commits:invitedCommits,
    grant:invitedGrant,certificate:memberCertificate,wrong_recipient:wrongRecipient,
    workspace:invitedWorkspace,owner_actor:owner.actorId,owner_key:owner.keyId,
    recipient_actor:member.actorId,recipient_key:member.keyId,
    checkpoint:{v:1,workspace_id:invitedWorkspace,owner_id:owner.actorId,owner_key:owner.keyId,
      sequence:2,head:await client.secureHash(secondCommit),policy_hash:await client.secureHash(invitedPolicy)},
    recipient_private:invitePrivate.toString('base64url'),offer,decision,now:now+3,
  },{
    policy,grant:delegatedGrant,certificate:deviceCertificate,wrong_recipient:wrongRecipient,
    workspace,owner_actor:owner.actorId,owner_key:owner.keyId,
    recipient_actor:device.actorId,recipient_key:device.keyId,
    checkpoint:vector.checkpoint,recipient_private:devicePrivate.toString('base64url'),delegation,
    now:now+3,delegation_expired_now:now+86_400_000,
  }];
  invitePrivate.fill(0);devicePrivate.fill(0);
  const cargo = process.env.PEERWORK_CARGO_BIN ?? 'cargo';
  for (const [index,item] of vectors.entries()) {
    const vectorPath = join(directory,`synthetic-grant-${index}.json`);
    await writeFile(vectorPath,JSON.stringify(item),{mode:0o600,flag:'wx'});
    const result = spawnSync(cargo,['test','-p','peerwork-core','direct_ts_owner_grant_vector',
      '--offline','--locked'],{cwd:root,env:{...process.env,PEERWORK_GRANT_VECTOR:vectorPath},encoding:'utf8'});
    if(result.status!==0)throw new Error(`native grant vector ${index} failed: ${result.stderr.slice(-3000)}`);
    assert.equal((await readFile(vectorPath,'utf8')).length>0,true);
  }
  console.log('direct, accepted-invitation and delegated TypeScript grants cross-open in native proof; missing related proofs and altered grants refused');
} finally {
  await rm(directory,{recursive:true,force:true});
}
