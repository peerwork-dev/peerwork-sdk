// Development-only bridge to the pinned tracked Peerwork TypeScript kernel.
// PEERWORK_REFERENCE_ROOT names a built checkout; PEERWORK_TEST_STATE is a
// fresh private test directory. This script is never part of an SDK package.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {readFileSync, readdirSync, statSync, writeFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';

const root = process.env.PEERWORK_REFERENCE_ROOT;
const state = process.env.PEERWORK_TEST_STATE;
if (!root || !state) throw new Error('reference root and fresh state are required');
const expectedHead = 'f828b6c50a0a58d1e718af90f653b214adcc3328';
const actualHead = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
if (actualHead !== expectedHead) throw new Error('reference checkout commit differs from tested pin');
try {
  execFileSync('git', ['-C', root, 'diff', '--quiet', 'HEAD', '--', 'src', 'tests', 'scripts', 'tsconfig.json', 'tsconfig.workspace.json', 'package.json', 'package-lock.json']);
} catch {
  throw new Error('tracked reference build input differs from tested commit');
}
const untrackedInputs = execFileSync('git', ['-C', root, 'ls-files', '--others', '--exclude-standard', '--', 'src', 'tests', 'scripts'], {encoding: 'utf8'}).trim().split('\n').filter(path => /\.(?:ts|tsx|mts|cts|js|mjs|cjs|json)$/.test(path));
if (untrackedInputs.length) throw new Error('untracked reference build input is present');
for (const [relative, expected] of Object.entries({
  'src/workspace-kernel.ts': '586ac5b6a689abd2782d5d3e093bdf2ebc3eaaa688b526908b0402fb7783b4e2',
  'src/workspace-http.ts': '4e8ab5d5484120395f28e39d2a703804328563efacfe90dfe9b761f923236355',
  'package-lock.json': '80d6ed0f40c4dbfa180289aad67054a35b25843754291ae7a34780c81f77a51f',
})) {
  const sourcePath = join(root, relative);
  const actual = createHash('sha256').update(readFileSync(sourcePath)).digest('hex');
  if (actual !== expected) throw new Error(`reference source hash mismatch: ${relative}`);
  if (relative.endsWith('.ts')) {
    const builtPath = join(root, 'dist-workspace', relative.replace(/\.ts$/, '.js'));
    if (statSync(builtPath).mtimeMs < statSync(sourcePath).mtimeMs)
      throw new Error(`reference TypeScript source is newer than build: ${relative}`);
  }
}
const requireFromReference = createRequire(join(root, 'package.json'));
if (JSON.parse(readFileSync(join(root, 'node_modules/typescript/package.json'), 'utf8')).version !== '7.0.2')
  throw new Error('reference TypeScript compiler version differs from lock');
const compiledRoot = join(root, 'dist-workspace/src');
const compiledFiles = [];
function scanCompiled(directory) {
  for (const entry of readdirSync(directory, {withFileTypes: true})) {
    const full = join(directory, entry.name);
    if (entry.isDirectory()) scanCompiled(full);
    else if (entry.isFile() && full.endsWith('.js')) compiledFiles.push(full);
  }
}
scanCompiled(compiledRoot);
compiledFiles.sort();
const compiledDigest = createHash('sha256');
for (const file of compiledFiles) {
  compiledDigest.update(file.slice(compiledRoot.length + 1));
  compiledDigest.update('\0');
  compiledDigest.update(createHash('sha256').update(readFileSync(file)).digest('hex'));
  compiledDigest.update('\n');
}
if (compiledFiles.length !== 204 || compiledDigest.digest('hex') !== '6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc')
  throw new Error('compiled reference source closure differs from tested build');
const {serve} = await import(pathToFileURL(requireFromReference.resolve('@hono/node-server')).href);
const {openKernel, WorkspaceKernel} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-kernel.js')).href);
const {createWorkspaceControlApp} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-http.js')).href);
const {canonical, hash, RECEIPT_TYPE} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-contract.js')).href);
const {signKernelJws} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-jws.js')).href);
let catalogAdapter;
if (process.env.PEERWORK_TEST_CATALOG === '1') {
  const packageModule = await import(pathToFileURL(join(root, 'dist-workspace/src/protocol-package.js')).href);
  const compiler = await import(pathToFileURL(join(root, 'dist-workspace/src/protocol-compiler.js')).href);
  catalogAdapter = {
    parseBytes: packageModule.parseProtocolPackageBytes,
    canonicalBytes: packageModule.canonicalProtocolPackageBytes,
    digest: packageModule.digestProtocolPackage,
    inspect: pkg => packageModule.inspectProtocolPackage(pkg.bundle),
    compile: compiler.compileProtocolPackage,
  };
}
const db = openKernel(join(state, 'control.sqlite'), 'reference-kernel');
const kernel = new WorkspaceKernel(db, 'reference-kernel', Buffer.alloc(32, 71), Date.now, {}, catalogAdapter);
const real = serve({fetch: createWorkspaceControlApp(kernel).fetch, hostname: '127.0.0.1', port: 0});
await new Promise(resolve => real.once('listening', resolve));
const realOrigin = `http://127.0.0.1:${real.address().port}`;
let secureFixture;
if (process.env.PEERWORK_TEST_SECURE === '1') {
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const {createActionContext, createCommit, secureHash, secureToken} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-client.js')).href);
  const {prepareSecureAction} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-engine.js')).href);
  const privateKey = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state, 'synthetic-agent-ed25519.pem'), privateKey.export({format:'pem',type:'pkcs8'}), {mode:0o600,flag:'wx'});
  const agent = await SecureAgentClient.open({
    baseUrl: realOrigin,
    privateKey,
    statePath: join(state, 'synthetic-secure-agent.json'),
    intentDbPath: join(state, 'synthetic-secure-agent-intents.sqlite'),
  });
  try {
    const created = await agent.create('Synthetic private workspace', 'PRIVATE');
    const journal = await agent.journal(created.workspaceId);
    const discussion = journal.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'discussion');
    if (!discussion || journal.policy.payload.v !== 3 || journal.policy.payload.structure_mode !== 'NONE')
      throw new Error('secure test fixture is not an unstructured v3 private workspace');
    const input = {
      identity: agent.identity, policy: journal.policy, checkpoint: journal.checkpoint,
      actionId: 'discussion.post', instanceId: discussion.id,
      commandId: secureToken(), issuedAt: Date.now(),
    };
    const context = await createActionContext(input);
    const operation = await prepareSecureAction({
      objects: journal.objects, context, policy: journal.policy,
      body: {message:'synthetic native secure exact retry'}, exactRefs: [],
    });
    // Fresh synthetic fixture inputs for a native-authored packet. These
    // private bytes remain in the temporary protected test directory and are
    // never emitted on stdout or returned through an SDK language DTO.
    writeFileSync(join(state, 'synthetic-secure-context.json'), JSON.stringify(context), {mode:0o600,flag:'wx'});
    writeFileSync(join(state, 'synthetic-secure-operation.json'), JSON.stringify(operation), {mode:0o600,flag:'wx'});
    writeFileSync(join(state, 'synthetic-secure-keyring.json'), JSON.stringify(agent.state.workspaces[created.workspaceId].keyring), {mode:0o600,flag:'wx'});
    const commit = await createCommit({...input, operation, keyring:agent.state.workspaces[created.workspaceId].keyring});
    const request = Buffer.from(JSON.stringify({commit}));
    writeFileSync(join(state, 'synthetic-secure-request.json'), request, {mode:0o600,flag:'wx'});
    secureFixture = {
      workspace_id: created.workspaceId,
      actor_id: agent.identity.actorId,
      signing_key: agent.identity.keyId,
      authority: agent.transport.authority,
      owner_key: journal.policy.payload.signing_key,
      policy_hash: await secureHash(journal.policy),
      sequence: commit.payload.sequence,
      previous: commit.payload.previous,
      epoch: commit.payload.epoch,
      version: commit.payload.v,
      mode: commit.payload.mode,
      protocol_format_ceiling: commit.payload.protocol_format_ceiling,
      command_id: commit.payload.command_id,
      action_id: commit.payload.action_id,
      commit_digest: await secureHash(commit),
    };
  } finally {
    agent.close();
  }
}
let bootstrapFixture;
let publicReadFixture;
if (process.env.PEERWORK_TEST_RESTART_PUBLIC_FIXTURE) publicReadFixture = JSON.parse(readFileSync(process.env.PEERWORK_TEST_RESTART_PUBLIC_FIXTURE, 'utf8')).public;
let publicAdmissionFixture;
let privateGrantFixture;
let privateNativeAdmissionFixture;
let publicReadInstance;
let publicReadAppended = false;
let publicReadFirstPage;
let serveStalePublicPage = false;
if (process.env.PEERWORK_TEST_PUBLIC_READ === '1') {
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const privateKey = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state, 'synthetic-public-read-owner.pem'), privateKey.export({format:'pem',type:'pkcs8'}), {mode:0o600,flag:'wx'});
  const agent = await SecureAgentClient.open({baseUrl:realOrigin,privateKey,
    statePath:join(state,'synthetic-public-read-agent.json'),
    intentDbPath:join(state,'synthetic-public-read-agent-intents.sqlite')});
  try {
    const created = await agent.create('Synthetic public read workspace', 'PUBLIC');
    let journal = await agent.journal(created.workspaceId);
    if (journal.checkpoint.sequence !== 1) throw new Error('public read fixture did not create a one-commit journal');
    const discussion = journal.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'discussion');
    if (!discussion) throw new Error('public read fixture lacks discussion instance');
    if (process.env.PEERWORK_TEST_PUBLIC_INSTALL_PAGES === '1') {
      const wiki = journal.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'wiki');
      if (!wiki) throw new Error('public install page fixture lacks wiki instance');
      for (let index = 0; index < 51; index++) {
        journal = await agent.action(created.workspaceId, wiki.id, 'wiki.create',
          {title:`Seed ${index}`,body:`Page boundary ${index}`});
      }
      if (journal.objects.filter(object => object.kind === 'records').length !== 51 ||
          journal.objects.filter(object => object.kind === 'entity_heads').length !== 51)
        throw new Error('public install page fixture did not write 51 record/head pairs');
    }
    publicReadInstance = discussion.id;
    publicReadFixture = {workspace_id:created.workspaceId, instance_id:publicReadInstance,
      actor_id:agent.identity.actorId,
      signing_key:agent.identity.keyId, authority:agent.transport.authority,
      head:journal.checkpoint.head,
      ...(process.env.PEERWORK_TEST_PUBLIC_INSTALL_PAGES === '1' ? {seeded_records:51,seeded_heads:51} : {})};
  } finally { agent.close(); }
}
if (process.env.PEERWORK_TEST_ADMISSION === '1') {
  if (!publicReadFixture) throw new Error('PUBLIC admission requires the verified public workspace fixture');
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const privateKey = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state,'synthetic-admission-recipient.pem'),privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  const agent = await SecureAgentClient.open({baseUrl:realOrigin,privateKey,
    statePath:join(state,'synthetic-admission-recipient.json'),
    intentDbPath:join(state,'synthetic-admission-recipient-intents.sqlite')});
  try {
    await agent.publishIdentity();
    const certificate = agent.state.certificate;
    writeFileSync(join(state,'synthetic-admission-recipient-certificate.json'),JSON.stringify(certificate),{mode:0o600,flag:'wx'});
    publicAdmissionFixture={recipient_actor_id:agent.identity.actorId,recipient_key_id:agent.identity.keyId};
  } finally { agent.close(); }
}
if (process.env.PEERWORK_TEST_PRIVATE_GRANT === '1' || process.env.PEERWORK_TEST_PRIVATE_INVITATION === '1' ||
    process.env.PEERWORK_TEST_PRIVATE_HISTORICAL_INVITATION === '1' || process.env.PEERWORK_TEST_PRIVATE_ACTION === '1') {
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const ownerPrivate = generateKeyPairSync('ed25519').privateKey;
  const recipientPrivate = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state,'private-grant-owner.pem'),ownerPrivate.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  writeFileSync(join(state,'private-grant-recipient.pem'),recipientPrivate.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  const owner = await SecureAgentClient.open({baseUrl:realOrigin,privateKey:ownerPrivate,
    statePath:join(state,'private-grant-owner.json'),intentDbPath:join(state,'private-grant-owner-intents.sqlite')});
  const recipient = await SecureAgentClient.open({baseUrl:realOrigin,privateKey:recipientPrivate,
    statePath:join(state,'private-grant-recipient.json'),intentDbPath:join(state,'private-grant-recipient-intents.sqlite')});
  try {
    const created = await owner.create('Native recipient private grant fixture','PRIVATE');
    await recipient.publishIdentity();
    const privateAction = process.env.PEERWORK_TEST_PRIVATE_ACTION === '1';
    const actionScopes = privateAction ? [{instance_id:null,actions:['wiki.create'],protocol_roles:['EDITOR'],capabilities:['EDIT'],expires_at:null}] : [];
    const offer = await owner.invite(created.workspaceId,recipient.state.certificate,actionScopes,'Native private grant retrieval');
    const decision = await recipient.decide(offer,{actorId:owner.identity.actorId,key:owner.identity.keyId},'ACCEPT');
    await owner.deliver(offer,decision);
    // The newly joined member's first grant is invitation-bound. The
    // authenticated direct-grant retrieval branch starts after an owner epoch
    // rotation, which writes a separate direct grant for this member.
    const directEpoch = process.env.PEERWORK_TEST_PRIVATE_GRANT === '1';
    const historicalInvitation = process.env.PEERWORK_TEST_PRIVATE_HISTORICAL_INVITATION === '1';
    if (historicalInvitation) {
      const before = await owner.journal(created.workspaceId);
      const beforeWiki = before.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'wiki');
      if (!beforeWiki) throw new Error('private historical fixture lacks wiki instance');
      await owner.action(created.workspaceId,beforeWiki.id,'wiki.create',
        {title:'Private before epoch advance',body:'Encrypted record from invitation epoch'});
    }
    if (directEpoch || historicalInvitation) await owner.rotate(created.workspaceId);
    let journal = await owner.journal(created.workspaceId);
    const wiki = journal.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('private grant fixture lacks wiki action instance');
    journal = await owner.action(created.workspaceId,wiki.id,'wiki.create',
      {title:'Private native grant readback',body:'Encrypted record recovered through grant'});
    if (journal.policy.payload.visibility !== 'PRIVATE' || journal.policy.payload.epoch !== (directEpoch || historicalInvitation ? 2 : 1) ||
        journal.checkpoint.sequence !== (historicalInvitation ? 5 : directEpoch ? 4 : 3) ||
        (historicalInvitation && !journal.objects.some(object => object.kind === 'records' &&
          object.value?.payload?.title === 'Private before epoch advance' &&
          object.value?.payload?.body === 'Encrypted record from invitation epoch')) ||
        !journal.objects.some(object => object.kind === 'records' &&
          object.value?.payload?.title === 'Private native grant readback' &&
          object.value?.payload?.body === 'Encrypted record recovered through grant'))
      throw new Error('private grant fixture did not reach signed encrypted record');
    privateGrantFixture = {workspace_id:created.workspaceId,owner_actor_id:owner.identity.actorId,
      owner_key_id:owner.identity.keyId,recipient_actor_id:recipient.identity.actorId,
      recipient_key_id:recipient.identity.keyId,recipient_authority:recipient.transport.authority,
      sequence:journal.checkpoint.sequence,head:journal.checkpoint.head,
      invite_id:offer.payload.invite_id,historical_invitation:historicalInvitation,
      instance_id:wiki.id};
  } finally { owner.close(); recipient.close(); }
}
if (process.env.PEERWORK_TEST_PRIVATE_NATIVE_ADMISSION === '1') {
  // Only the owner is provisioned by the tracked TypeScript fixture. The
  // recipient must create and publish its own identity, sign ACCEPT, and
  // receive the actual signed grant through the native installed interface.
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const ownerPrivate = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state,'private-native-admission-owner.pem'),ownerPrivate.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  const owner = await SecureAgentClient.open({baseUrl:realOrigin,privateKey:ownerPrivate,
    statePath:join(state,'private-native-admission-owner.json'),
    intentDbPath:join(state,'private-native-admission-owner-intents.sqlite')});
  try {
    const created = await owner.create('Native recipient admission fixture','PRIVATE');
    const journal = await owner.journal(created.workspaceId);
    if (journal.policy.payload.visibility !== 'PRIVATE' || journal.checkpoint.sequence !== 1)
      throw new Error('private native admission owner bootstrap did not verify');
    privateNativeAdmissionFixture = {workspace_id:created.workspaceId,
      owner_actor_id:owner.identity.actorId,owner_key_id:owner.identity.keyId,
      owner_authority:owner.transport.authority,sequence:journal.checkpoint.sequence,
      head:journal.checkpoint.head};
  } finally { owner.close(); }
}
if (process.env.PEERWORK_TEST_BOOTSTRAP === '1') {
  const {generateKeyPairSync} = await import('node:crypto');
  const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
  const privateKey = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state, 'synthetic-bootstrap-owner.pem'), privateKey.export({format:'pem',type:'pkcs8'}), {mode:0o600,flag:'wx'});
  const agent = await SecureAgentClient.open({baseUrl:realOrigin,privateKey,
    statePath:join(state,'synthetic-bootstrap-agent.json'),
    intentDbPath:join(state,'synthetic-bootstrap-agent-intents.sqlite')});
  try {
    await agent.register();
    bootstrapFixture = {actor_id:agent.identity.actorId,
      signing_key:agent.identity.keyId,authority:agent.transport.authority,
      real_origin:realOrigin};
  } finally { agent.close(); }
}
let dropFirstPost = true;
let forceDropNextPost = false;
let dropNextIdentityDirectory = false;
let serveStaleIdentityDirectory = false;
let tamperNextIdentityDirectory = false;
let tamperNextPrivateGrant = false;
let tamperNextPrivateInvitation = false;
let delayNextIdentityDirectoryPost = false;
let delayedIdentityDirectoryApplied = false;
let rejectNextPostBeforeApply = false;
let delayNextPostAfterApply = false;
let delayedPostStarted = false;
let alterFirstChunk = process.env.PEERWORK_TEST_WRONG_CHUNK_STATE === '1';
const firstPostMode = process.env.PEERWORK_TEST_FIRST_POST_MODE || 'drop';
const firstPostDelayMs = Number(process.env.PEERWORK_TEST_FIRST_POST_DELAY_MS || 0);
let firstJournalDelayMs = Number(process.env.PEERWORK_TEST_FIRST_JOURNAL_DELAY_MS || 0);
if (!['drop', 'delay', 'normal'].includes(firstPostMode) || !Number.isSafeInteger(firstPostDelayMs) || firstPostDelayMs < 0 || firstPostDelayMs > 10000)
  throw new Error('invalid first POST fixture mode or delay');
if (!Number.isSafeInteger(firstJournalDelayMs) || firstJournalDelayMs < 0 || firstJournalDelayMs > 10000)
  throw new Error('invalid journal delay fixture');
let delayFirstJournal = firstJournalDelayMs > 0;
let journalDelayStarted = false;
let journalGetCount = 0;
const proxy = createServer(async (request, response) => {
  try {
    if (request.url === '/__test/activate-protocol-cutover' && request.method === 'POST') {
      if (process.env.PEERWORK_TEST_OWNER_FORMAT !== '1') throw new Error('Owner format fixture unavailable');
      const {secureProtocolCutoverPreflightDigest} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-store.js')).href);
      const activationId = Buffer.alloc(32, 83).toString('base64url');
      const result = kernel.secureStore.activateProtocolCutover(activationId, secureProtocolCutoverPreflightDigest(db));
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({phase:result.phase}));
      return;
    }
    if (request.url?.startsWith('/__test/private-owner-') && request.method === 'POST') {
      if (!privateNativeAdmissionFixture) throw new Error('private native admission fixture unavailable');
      const chunks = [];
      let bodyBytes = 0;
      for await (const chunk of request) {
        bodyBytes += chunk.length;
        if (bodyBytes > 65536) throw new Error('private owner test request too large');
        chunks.push(chunk);
      }
      const input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      const {createPrivateKey} = await import('node:crypto');
      const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
      const privateKey = createPrivateKey(readFileSync(join(state,'private-native-admission-owner.pem')));
      const owner = await SecureAgentClient.open({baseUrl:realOrigin,privateKey,
        statePath:join(state,'private-native-admission-owner.json'),
        intentDbPath:join(state,'private-native-admission-owner-intents.sqlite')});
      try {
        let result;
        if (request.url === '/__test/private-owner-invite') {
          if (typeof input.certificate_json !== 'string') throw new Error('native public certificate is required');
          const certificate = JSON.parse(input.certificate_json);
          const actorId = certificate?.payload?.actor_id;
          const signingKey = certificate?.payload?.signing_key;
          if (typeof actorId !== 'string' || typeof signingKey !== 'string')
            throw new Error('native public certificate actor/key is required');
          // Test setup makes an explicit first-contact trust decision from the
          // native recipient's shared public certificate. The tracked client
          // then validates the signed directory and requires the current
          // directory certificate to equal those exact shared bytes.
          const expectedFingerprint = createHash('sha256')
            .update(Buffer.from(signingKey, 'base64url')).digest('hex');
          await owner.confirmIdentity(actorId,expectedFingerprint);
          const currentCertificate = await owner.identityCertificate(actorId);
          if (canonical(currentCertificate) !== canonical(certificate))
            throw new Error('native recipient directory certificate changed');
          const scopes = input.scopes_json === undefined ? [] : JSON.parse(input.scopes_json);
          if (!Array.isArray(scopes)) throw new Error('invitation scopes must be an array');
          const offer = await owner.invite(privateNativeAdmissionFixture.workspace_id,currentCertificate,scopes,
            'Native recipient private invitation');
          result = {invite_id:offer.payload.invite_id,workspace_id:privateNativeAdmissionFixture.workspace_id};
        } else if (request.url === '/__test/private-owner-deliver') {
          if (typeof input.invite_id !== 'string') throw new Error('invite ID is required');
          const grant = await owner.deliverAdmission(input.invite_id);
          result = {grant_id:grant.payload.grant_id,invite_id:input.invite_id};
        } else if (request.url === '/__test/private-owner-rotate') {
          const rotated = await owner.rotate(privateNativeAdmissionFixture.workspace_id);
          const wiki = rotated.objects.find(object => object.kind === 'instances' && object.value?.origin_entrypoint === 'wiki');
          if (!wiki) throw new Error('private owner rotation fixture lacks wiki instance');
          const journal = await owner.action(privateNativeAdmissionFixture.workspace_id,wiki.id,'wiki.create',
            {title:'Native private admission readback',body:'Encrypted record after owner epoch advance'});
          const record = journal.objects.find(object => object.kind === 'records' &&
            object.value?.payload?.title === 'Native private admission readback');
          if (!record || journal.policy.payload.visibility !== 'PRIVATE' ||
              journal.policy.payload.epoch !== rotated.policy.payload.epoch)
            throw new Error('private owner rotation did not produce encrypted record');
          result = {workspace_id:privateNativeAdmissionFixture.workspace_id,
            sequence:journal.checkpoint.sequence,epoch:journal.policy.payload.epoch,
            record_id:record.id};
        } else throw new Error('unknown private owner test endpoint');
        response.writeHead(200, {'content-type':'application/json'});
        response.end(JSON.stringify(result));
      } finally { owner.close(); }
      return;
    }
    if (request.url === '/__test/append-public' && request.method === 'POST') {
      if (!publicReadFixture || publicReadAppended) throw new Error('public append fixture unavailable');
      const {createPrivateKey} = await import('node:crypto');
      const {SecureAgentClient} = await import(pathToFileURL(join(root, 'dist-workspace/src/workspace-secure-agent.js')).href);
      const privateKey = createPrivateKey(readFileSync(join(state, 'synthetic-public-read-owner.pem')));
      const agent = await SecureAgentClient.open({baseUrl:realOrigin,privateKey,
        statePath:join(state,'synthetic-public-read-agent.json'),
        intentDbPath:join(state,'synthetic-public-read-agent-intents.sqlite')});
      try {
        const journal = await agent.action(publicReadFixture.workspace_id, publicReadInstance,
          'discussion.post', {message:'synthetic public refresh'});
        if (journal.checkpoint.sequence !== 53) throw new Error('public append did not advance checkpoint');
        publicReadAppended = true;
        response.writeHead(200, {'content-type':'application/json'});
        response.end(JSON.stringify({sequence:journal.checkpoint.sequence,head:journal.checkpoint.head}));
      } finally { agent.close(); }
      return;
    }
    if (request.url === '/__test/serve-stale-public' && request.method === 'POST') {
      if (!publicReadAppended || !publicReadFirstPage) throw new Error('stale public page fixture unavailable');
      serveStalePublicPage = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/restore-current-public' && request.method === 'POST') {
      if (!publicReadAppended || !publicReadFirstPage) throw new Error('public page fixture unavailable');
      serveStalePublicPage = false;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/delay-next-journal' && request.method === 'POST') {
      if (!(publicReadFixture || process.env.PEERWORK_TEST_HISTORICAL_ATTACH === '1') || firstJournalDelayMs !== 0) throw new Error('journal delay fixture unavailable');
      firstJournalDelayMs = 18000;
      delayFirstJournal = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/drop-next-post' && request.method === 'POST') {
      if (dropFirstPost) throw new Error('dropped-response fixture is already armed');
      dropFirstPost = true;
      forceDropNextPost = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/delay-next-post' && request.method === 'POST') {
      if (delayNextPostAfterApply) throw new Error('POST delay already armed');
      delayNextPostAfterApply = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/post-delay-status' && request.method === 'GET') {
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({started:delayedPostStarted}));
      return;
    }
    if (request.url === '/__test/drop-next-identity-directory' && request.method === 'POST') {
      if (!publicReadFixture || dropNextIdentityDirectory) throw new Error('identity directory drop fixture unavailable');
      dropNextIdentityDirectory = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/serve-stale-identity-directory' && request.method === 'POST') {
      if (!publicReadFixture) throw new Error('identity directory fixture unavailable');
      serveStaleIdentityDirectory = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/tamper-next-identity-directory' && request.method === 'POST') {
      if (!publicReadFixture || tamperNextIdentityDirectory) throw new Error('identity directory tamper fixture unavailable');
      tamperNextIdentityDirectory = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/tamper-next-private-grant' && request.method === 'POST') {
      if ((!privateGrantFixture && !privateNativeAdmissionFixture) || tamperNextPrivateGrant)
        throw new Error('private grant tamper fixture unavailable');
      tamperNextPrivateGrant = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/tamper-next-private-invitation' && request.method === 'POST') {
      if (!privateGrantFixture || tamperNextPrivateInvitation) throw new Error('private invitation tamper fixture unavailable');
      tamperNextPrivateInvitation = true;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/delay-next-identity-directory-post' && request.method === 'POST') {
      if (delayNextIdentityDirectoryPost) throw new Error('identity directory delay already armed');
      delayNextIdentityDirectoryPost = true;
      delayedIdentityDirectoryApplied = false;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/identity-directory-post-delay-status' && request.method === 'GET') {
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({applied:delayedIdentityDirectoryApplied}));
      return;
    }
    if (request.url === '/__test/restore-identity-directory' && request.method === 'POST') {
      serveStaleIdentityDirectory = false;
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/reject-next-post-before-apply' && request.method === 'POST') {
      if (!publicReadFixture || rejectNextPostBeforeApply)
        throw new Error('public rejected-request fixture unavailable');
      rejectNextPostBeforeApply = true;
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify({enabled:true}));
      return;
    }
    if (request.url === '/__test/journal-delay-status' && request.method === 'GET') {
      response.writeHead(200, {'content-type':'application/json'});
      response.end(JSON.stringify({started:journalDelayStarted}));
      return;
    }
    if (request.url === '/__test/counts') {
      const counts = {
        commands: db.prepare('SELECT count(*) n FROM commands').get().n,
        workspaces: db.prepare('SELECT count(*) n FROM workspaces').get().n,
        protocols: db.prepare('SELECT count(*) n FROM protocols').get().n,
        workspace_revision: db.prepare('SELECT revision FROM workspaces LIMIT 1').get()?.revision ?? null,
      };
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(counts));
      return;
    }
    if (request.url === '/__test/catalog-counts') {
      const totals = {
        commands: db.prepare('SELECT count(*) n FROM commands').get().n,
        namespaces: db.prepare('SELECT count(*) n FROM catalog_namespaces').get().n,
        uploads: db.prepare('SELECT count(*) n FROM catalog_uploads').get().n,
        ready_uploads: db.prepare("SELECT count(*) n FROM catalog_uploads WHERE state='READY'").get().n,
        consumed_uploads: db.prepare("SELECT count(*) n FROM catalog_uploads WHERE state='CONSUMED'").get().n,
        chunks: db.prepare('SELECT count(*) n FROM catalog_upload_chunks').get().n,
        packages: db.prepare('SELECT count(*) n FROM catalog_packages').get().n,
        outbox: db.prepare('SELECT count(*) n FROM catalog_outbox').get().n,
      };
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(totals));
      return;
    }
    if (request.url === '/__test/secure-counts') {
      const totals = {
        commits: db.prepare('SELECT count(*) n FROM secure_commits').get().n,
        head_sequence: db.prepare('SELECT head_sequence FROM secure_workspaces LIMIT 1').get()?.head_sequence ?? null,
        head_hash: db.prepare('SELECT head_hash FROM secure_workspaces LIMIT 1').get()?.head_hash ?? null,
        journal_gets: journalGetCount,
      };
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(totals));
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    if (request.method === 'GET' && request.url?.includes('/journal?')) journalGetCount++;
    if (rejectNextPostBeforeApply && request.method === 'POST') {
      rejectNextPostBeforeApply = false;
      response.writeHead(503, {'content-type': 'application/json'});
      response.end(JSON.stringify({code:'TEST_NOT_APPLIED'}));
      return;
    }
    const original = await fetch(realOrigin + request.url, {
      method: request.method,
      headers: {'content-type': request.headers['content-type'] || 'application/json',
        ...(typeof request.headers['x-peerwork-read'] === 'string'
          ? {'X-Peerwork-Read': request.headers['x-peerwork-read']} : {})},
      body: request.method === 'GET' ? undefined : Buffer.concat(chunks),
    });
    let bytes = Buffer.from(await original.arrayBuffer());
    if (request.method === 'GET' && request.url?.startsWith('/api/workspace/v1/secure/identity-keys/')
        && serveStaleIdentityDirectory && original.status === 200) {
      const value = JSON.parse(bytes.toString('utf8'));
      bytes = Buffer.from(JSON.stringify({actor_id:value.actor_id,entries:[]}));
    }
    if (request.method === 'GET' && request.url?.startsWith('/api/workspace/v1/secure/identity-keys/')
        && tamperNextIdentityDirectory && original.status === 200) {
      tamperNextIdentityDirectory = false;
      const value = JSON.parse(bytes.toString('utf8'));
      const entry = value.entries.at(-1);
      if (!entry) throw new Error('identity directory tamper requires an entry');
      entry.signature = `${entry.signature[0] === 'A' ? 'B' : 'A'}${entry.signature.slice(1)}`;
      bytes = Buffer.from(JSON.stringify(value));
    }
    if (request.method === 'GET' && request.url?.endsWith('/key-grants')
        && tamperNextPrivateGrant && original.status === 200) {
      tamperNextPrivateGrant = false;
      const value = JSON.parse(bytes.toString('utf8'));
      const grant = value.grants?.[0];
      if (!grant) throw new Error('private grant tamper requires a grant');
      grant.signature = `${grant.signature[0] === 'A' ? 'B' : 'A'}${grant.signature.slice(1)}`;
      bytes = Buffer.from(JSON.stringify(value));
    }
    if (request.method === 'GET' && request.url === `/api/workspace/v1/secure/invitations/${privateGrantFixture?.invite_id}`
        && tamperNextPrivateInvitation && original.status === 200) {
      tamperNextPrivateInvitation = false;
      const value = JSON.parse(bytes.toString('utf8'));
      if (!value.grant?.signature) throw new Error('private invitation tamper requires signed grant');
      value.grant.signature = `${value.grant.signature[0] === 'A' ? 'B' : 'A'}${value.grant.signature.slice(1)}`;
      bytes = Buffer.from(JSON.stringify(value));
    }
    if (request.method === 'POST' && request.url === '/api/workspace/v1/secure/identity-keys'
        && dropNextIdentityDirectory && original.status === 201) {
      dropNextIdentityDirectory = false;
      response.destroy();
      return;
    }
    if (request.method === 'POST' && request.url === '/api/workspace/v1/secure/identity-keys'
        && delayNextIdentityDirectoryPost && original.status === 201) {
      delayNextIdentityDirectoryPost = false;
      delayedIdentityDirectoryApplied = true;
      await new Promise(resolve => setTimeout(resolve, 3000));
      if (response.destroyed) return;
    }
    if (publicReadFixture && request.method === 'GET' && request.url?.includes('/journal?') && original.status === 200) {
      if (!publicReadFirstPage) publicReadFirstPage = Buffer.from(bytes);
      if (serveStalePublicPage) bytes = Buffer.from(publicReadFirstPage);
    }
    if (alterFirstChunk && request.method === 'POST' && request.url === '/api/workspace/v1/catalog/upload' && original.status === 201) {
      alterFirstChunk = false;
      const value = JSON.parse(bytes.toString('utf8'));
      const receiptPayload = JSON.parse(Buffer.from(value.receipt.split('.')[1], 'base64url').toString('utf8'));
      value.result.state = value.result.state === 'READY' ? 'STAGING' : 'READY';
      receiptPayload.result_digest = hash(canonical(value.result));
      value.receipt = signKernelJws(receiptPayload, RECEIPT_TYPE, kernel.receiptKey);
      bytes = Buffer.from(JSON.stringify(value));
    }
    if (request.method === 'POST' && dropFirstPost) {
      dropFirstPost = false;
      if (forceDropNextPost || firstPostMode === 'drop') {
        forceDropNextPost = false;
        response.destroy(); // Real kernel has already committed and replied.
        return;
      }
      // Hold the committed real response for an in-flight client abort test.
      await new Promise(resolve => setTimeout(resolve, firstPostDelayMs));
      if (response.destroyed) return;
    }
    if (request.method === 'POST' && delayNextPostAfterApply && original.status >= 200 && original.status < 300) {
      delayNextPostAfterApply = false;
      delayedPostStarted = true; // The tracked service has already applied and replied.
      await new Promise(resolve => setTimeout(resolve, 3000));
      delayedPostStarted = false;
      if (response.destroyed) return;
    }
    if (request.method === 'GET' && request.url?.includes('/journal?') && delayFirstJournal) {
      delayFirstJournal = false;
      journalDelayStarted = true;
      await new Promise(resolve => setTimeout(resolve, firstJournalDelayMs));
      journalDelayStarted = false;
      firstJournalDelayMs = 0;
      if (response.destroyed) return;
    }
    response.writeHead(original.status, {'content-type': original.headers.get('content-type') || 'application/json'});
    response.end(bytes);
  } catch (error) {
    if (!response.destroyed) { response.writeHead(500); response.end(); }
    process.stderr.write(`reference proxy error: ${error?.message || error}\n`);
  }
});
await new Promise(resolve => proxy.listen(Number(process.env.PEERWORK_TEST_RESTART_PROXY_PORT || 0), '127.0.0.1', resolve));
process.stdout.write(JSON.stringify({origin: `http://127.0.0.1:${proxy.address().port}/`,
  ...(secureFixture ? {secure:secureFixture} : {}),
  ...(publicReadFixture ? {public_read:publicReadFixture} : {}),
  ...(publicAdmissionFixture ? {public_admission:publicAdmissionFixture} : {}),
  ...(privateGrantFixture ? {private_grant:privateGrantFixture} : {}),
  ...(privateNativeAdmissionFixture ? {private_native_admission:privateNativeAdmissionFixture} : {}),
  ...(bootstrapFixture ? {bootstrap:bootstrapFixture} : {})}) + '\n');
const shutdown = () => {
  proxy.closeAllConnections();
  proxy.close();
  real.closeAllConnections?.();
  real.close();
  db.close();
};
process.stdin.on('end', shutdown);
