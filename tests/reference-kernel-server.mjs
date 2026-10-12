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
    const commit = await createCommit({...input, operation, keyring:agent.state.workspaces[created.workspaceId].keyring});
    const request = Buffer.from(JSON.stringify({commit}));
    writeFileSync(join(state, 'synthetic-secure-request.json'), request, {mode:0o600,flag:'wx'});
    secureFixture = {
      workspace_id: created.workspaceId,
      actor_id: agent.identity.actorId,
      signing_key: agent.identity.keyId,
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
let dropFirstPost = true;
let alterFirstChunk = process.env.PEERWORK_TEST_WRONG_CHUNK_STATE === '1';
const firstPostMode = process.env.PEERWORK_TEST_FIRST_POST_MODE || 'drop';
const firstPostDelayMs = Number(process.env.PEERWORK_TEST_FIRST_POST_DELAY_MS || 0);
if (!['drop', 'delay', 'normal'].includes(firstPostMode) || !Number.isSafeInteger(firstPostDelayMs) || firstPostDelayMs < 0 || firstPostDelayMs > 10000)
  throw new Error('invalid first POST fixture mode or delay');
const proxy = createServer(async (request, response) => {
  try {
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
      };
      response.writeHead(200, {'content-type': 'application/json'});
      response.end(JSON.stringify(totals));
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const original = await fetch(realOrigin + request.url, {
      method: request.method,
      headers: {'content-type': request.headers['content-type'] || 'application/json'},
      body: request.method === 'GET' ? undefined : Buffer.concat(chunks),
    });
    let bytes = Buffer.from(await original.arrayBuffer());
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
      if (firstPostMode === 'drop') {
        response.destroy(); // Real kernel has already committed and replied.
        return;
      }
      // Hold the committed real response for an in-flight client abort test.
      await new Promise(resolve => setTimeout(resolve, firstPostDelayMs));
      if (response.destroyed) return;
    }
    response.writeHead(original.status, {'content-type': original.headers.get('content-type') || 'application/json'});
    response.end(bytes);
  } catch (error) {
    if (!response.destroyed) { response.writeHead(500); response.end(); }
    process.stderr.write(`reference proxy error: ${error?.message || error}\n`);
  }
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
process.stdout.write(JSON.stringify({origin: `http://127.0.0.1:${proxy.address().port}/`, ...(secureFixture ? {secure:secureFixture} : {})}) + '\n');
const shutdown = () => {
  proxy.closeAllConnections();
  proxy.close();
  real.closeAllConnections?.();
  real.close();
  db.close();
};
process.stdin.on('end', shutdown);
