import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';
import { webcrypto } from 'node:crypto';

const reference = '/root/workdir/message/.worktrees/e2ee-main-integration-20261006';
const source = `${reference}/dist-workspace/src`;
Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

const { parseProtocolPackage, PROTOCOL_PACKAGE_FORMAT } = await import(`${source}/protocol-package.js`);
const { compileProtocolPackage } = await import(`${source}/protocol-compiler.js`);
const { createSigningIdentity, createEncryptionIdentity, certifyEncryptionKey, encodeCanonicalJson, decodeBase64Url, unsealContent } = await import(`${source}/workspace-secure-crypto.js`);
const { createPolicy, createCommit, commitContext, secureHash, secureToken, newSecureKeyring } = await import(`${source}/workspace-secure-client.js`);
const { prepareSecureAction, validateSecureOperation } = await import(`${source}/workspace-secure-engine.js`);

function readFiles(directory) {
  const files = {};
  function walk(current) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) walk(path);
      else files[relative(directory, path).split(sep).join('/')] = readFileSync(path, 'utf8');
    }
  }
  walk(directory);
  return files;
}
function depthOf(root) {
  let maximum = 0;
  const stack = [[root, 0]];
  while (stack.length) {
    const [value, depth] = stack.pop();
    if (depth > maximum) maximum = depth;
    if (value && typeof value === 'object') {
      for (const child of Object.values(value)) stack.push([child, depth + 1]);
    }
  }
  return maximum;
}
function unusedChainAtDepth(target) {
  let value = 'unused';
  // Operation -> input -> body -> unused gives depth 3 before this chain.
  for (let i = 0; i < target - 3; i++) value = { next: value };
  return value;
}

const packageDir = `${reference}/protocols/wiki`;
const packageValue = parseProtocolPackage({ format: PROTOCOL_PACKAGE_FORMAT, files: readFiles(packageDir) });
const compiled = compileProtocolPackage(packageValue, { loadExactPackage: () => undefined });
assert.equal(compiled.protocolDigest, '33f799e4b168b28032348a26e8c5d320cb2c43550e3effc60f584dc4561717a3');
assert.equal(compiled.passed, true);
assert.equal(compiled.manifest.actions.find(action => action.id === 'wiki.create')?.inputs, undefined);

const identity = await createSigningIdentity();
const encryption = await createEncryptionIdentity();
const certificate = await certifyEncryptionKey(identity, encryption, 1, 1000000);
const workspaceId = secureToken(), instanceId = secureToken(), keyring = newSecureKeyring(workspaceId, 1);
const policy = await createPolicy(identity, {
  v: 1, workspace_id: workspaceId, owner_id: identity.actorId, signing_key: identity.keyId,
  version: 1, previous_policy: null, effective_sequence: 1, visibility: 'PRIVATE', epoch: 1,
  members: [{ actor_id: identity.actorId, certificate, role: 'OWNER', scopes: [{ instance_id: instanceId, actions: ['wiki.create'], protocol_roles: ['EDITOR'], capabilities: ['EDIT'] }] }],
  issued_at: 10,
});
const context = {
  v: 1, workspace_id: workspaceId, sequence: 1, previous: null, policy_hash: await secureHash(policy), epoch: 1,
  actor_id: identity.actorId, signing_key: identity.keyId, command_id: secureToken(), action_id: 'wiki.create',
  instance_id: instanceId, issued_at: 20, delegation: null,
};
const objects = [
  { kind: 'protocols', id: secureToken(), revision: 1, provenance: 'AUTHOR_SIGNED', value: { workspace_id: workspaceId, digest: compiled.protocolDigest, resolved_manifest: JSON.stringify(compiled.manifest) } },
  { kind: 'instances', id: instanceId, revision: 1, provenance: 'AUTHOR_SIGNED', value: { id: instanceId, workspace_id: workspaceId, protocol_digest: compiled.protocolDigest, state: JSON.stringify(compiled.manifest.initial_state), revision: 1, event_revision: 0 } },
];

async function exercise(body) {
  const result = { prepared: false, operationValidated: false, privateSealed: false, decrypted: false, decryptedCanonicalRoundtrip: false, selectedFieldsMatch: false, unusedExtraPreserved: false, operationDepth: null, plaintextBytes: null, outerCommitBytes: null, failedStage: null, safeErrorName: null };
  let stage = 'prepareSecureAction';
  try {
    const operation = await prepareSecureAction({ objects, context, policy, body });
    result.prepared = true;
    stage = 'validateSecureOperation';
    await validateSecureOperation(operation, context, policy, objects);
    result.operationValidated = true;
    stage = 'createCommit';
    const commit = await createCommit({ identity, policy, checkpoint: { v: 1, workspace_id: workspaceId, sequence: 0, head: null, policy_hash: await secureHash(policy) }, keyring, actionId: 'wiki.create', instanceId, issuedAt: 20, commandId: context.command_id, operation });
    result.privateSealed = commit.payload.mode === 'PRIVATE';
    result.outerCommitBytes = encodeCanonicalJson(commit).byteLength;
    stage = 'decryptContent';
    const key = await crypto.subtle.importKey('raw', decodeBase64Url(keyring.keys[0].key), { name: 'AES-GCM' }, false, ['decrypt']);
    const raw = await unsealContent(key, commit.payload.body, commitContext(commit));
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    const decrypted = JSON.parse(text);
    result.decrypted = true;
    stage = 'plaintextChecks';
    result.decryptedCanonicalRoundtrip = text === new TextDecoder().decode(encodeCanonicalJson(decrypted))
      && Buffer.compare(Buffer.from(raw), Buffer.from(encodeCanonicalJson(operation))) === 0;
    result.selectedFieldsMatch = decrypted.kind === 'ACTION'
      && decrypted.input.body.title === 'ordinary title'
      && decrypted.input.body.body === 'ordinary body';
    result.unusedExtraPreserved = body.unused_extra === undefined
      ? !Object.hasOwn(decrypted.input.body, 'unused_extra')
      : Object.hasOwn(decrypted.input.body, 'unused_extra');
    result.operationDepth = depthOf(decrypted);
    result.plaintextBytes = raw.byteLength;
  } catch (error) {
    result.failedStage = stage;
    result.safeErrorName = error instanceof Error ? error.name : 'UnknownError';
  }
  return result;
}

const control = await exercise({ title: 'ordinary title', body: 'ordinary body' });
const candidate = await exercise({ title: 'ordinary title', body: 'ordinary body', unused_extra: unusedChainAtDepth(2049) });
const summary = {
  node: process.version,
  compiledProtocolDigest: compiled.protocolDigest,
  compilerPassed: compiled.passed,
  actionHasInputContract: false,
  ordinaryControl: control,
  depth2049Candidate: candidate,
  persistedSecretsOrPackets: false,
};
// Persist scalar stage evidence before final acceptance assertions, so a later
// assertion failure cannot erase which public operations actually completed.
console.log(JSON.stringify(summary));
assert.equal(compiled.passed, true);
assert.equal(control.failedStage, null);
assert.equal(control.prepared && control.operationValidated && control.privateSealed && control.decrypted && control.decryptedCanonicalRoundtrip && control.selectedFieldsMatch, true);
assert.equal(control.operationDepth < 64, true);
assert.equal(candidate.failedStage, null);
assert.equal(candidate.prepared && candidate.operationValidated && candidate.privateSealed && candidate.decrypted && candidate.decryptedCanonicalRoundtrip && candidate.selectedFieldsMatch && candidate.unusedExtraPreserved, true);
assert.equal(candidate.operationDepth, 2049);
