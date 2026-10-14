// Source-only public routing and preflight with a stub native boundary.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const realRequire = createRequire(import.meta.url);
const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..',
  'bindings', 'node', 'index.cjs'), 'utf8');
const calls = [];
class KernelCancelHandle { cancel() { this.cancelled = true; } }
const native = {
  KernelCancelHandle,
  secureOwnerCreateJson: async (...args) => {
    calls.push(args);
    return JSON.stringify({ ok: true, value: { status: 'PENDING_UNRESOLVED' } });
  },
};
const mockRequire = name => name === '/stub/native' ? native : realRequire(name);
mockRequire.resolve = () => '/stub/native';
const exports = {};
new Function('require', 'exports', 'process', source)(mockRequire, exports, process);
const owner = exports.openSecureOwnerWorkspaces({ origin: 'https://control.example', stateDir: '/protected/root' });
const input = {
  workspaceId: 'w'.repeat(43), protectedTsStatePath: '/protected/legacy/state',
  protectedTsIntentDbPath: '/protected/legacy/intents.sqlite',
  protectedOwnerPkcs8Path: '/protected/legacy/owner.pem',
  expectedOwnerActorId: 'a'.repeat(43), expectedOwnerKeyId: 'k'.repeat(43),
};
const selected = 'c'.repeat(43);
const digest = 'd'.repeat(64);
const options = '{"visibility":"PRIVATE"}';
const material = '{"v":1}';
await owner.inspectPendingDirectInstallBegin(input, selected, options, material);
assert.equal(calls.at(-1)[0], 'direct_begin_inspect');
assert.deepEqual(JSON.parse(calls.at(-1)[2]), {
  attachment_input: JSON.parse(calls.at(-1)[2]).attachment_input,
  selected_command_id: selected, expected_ts_state_digest: null,
  options_json: options, material_json: material,
});
await owner.attachPendingDirectInstallBegin(input, selected, digest, options, material);
assert.equal(calls.at(-1)[0], 'direct_begin_attach');
assert.equal(JSON.parse(calls.at(-1)[2]).expected_ts_state_digest, digest);
await owner.recoverPendingDirectInstallBegin('t'.repeat(43), selected);
assert.equal(calls.at(-1)[0], 'direct_begin_recover');
assert.equal(calls.at(-1)[3], selected);
assert.equal(calls.at(-1)[4], 't'.repeat(43));
assert.equal(owner.inspectPendingDirectInstallPacket, owner.inspectPendingDirectInstallBegin);
assert.equal(owner.attachPendingDirectInstallPacket, owner.attachPendingDirectInstallBegin);
assert.equal(owner.recoverPendingDirectInstallPacket, owner.recoverPendingDirectInstallBegin);
await owner.inspectPendingDirectInstallPacket(input, selected, options, material);
await owner.attachPendingDirectInstallPacket(input, selected, digest, options, material);
await owner.recoverPendingDirectInstallPacket('t'.repeat(43), selected);
assert.deepEqual(calls.slice(-3).map(row => row[0]), ['direct_begin_inspect', 'direct_begin_attach', 'direct_begin_recover']);
await owner.inspectCompletedDirectInstall(input, selected, options, material);
assert.equal(calls.at(-1)[0], 'direct_completed_inspect');
assert.equal(JSON.parse(calls.at(-1)[2]).selected_instance_id, selected);
assert.equal(JSON.parse(calls.at(-1)[2]).expected_ts_state_digest, null);
assert.ok(!('selected_command_id' in JSON.parse(calls.at(-1)[2])));
await owner.attachCompletedDirectInstall(input, selected, digest, options, material);
assert.equal(calls.at(-1)[0], 'direct_completed_attach');
assert.equal(JSON.parse(calls.at(-1)[2]).expected_ts_state_digest, digest);
const before = calls.length;
for (const invalid of [
  { ...input, unsupported: true },
  { ...input, selectedOrphanPackageStageCommandId: selected, expectedTsStateDigest: digest },
  { ...input, recoverPendingAction: true },
]) assert.throws(() => owner.attachPendingDirectInstallBegin(invalid, selected, digest, options, material), TypeError);
assert.throws(() => owner.attachPendingDirectInstallBegin(input, selected, '', options, material), TypeError);
assert.throws(() => owner.inspectPendingDirectInstallBegin(input, selected, '', material), TypeError);
assert.throws(() => owner.attachCompletedDirectInstall(input, selected, '', options, material), TypeError);
assert.throws(() => owner.inspectCompletedDirectInstall(input, '', options, material), TypeError);
assert.throws(() => owner.inspectCompletedDirectInstall({ ...input, expectedTsStateDigest: digest }, selected, options, material), TypeError);
assert.equal(calls.length, before);
const controller = new AbortController();
controller.abort();
await owner.inspectPendingDirectInstallBegin(input, selected, options, material, { signal: controller.signal });
assert.equal(calls.at(-1)[5].cancelled, true);
await owner.inspectCompletedDirectInstall(input, selected, options, material, { signal: controller.signal });
assert.equal(calls.at(-1)[5].cancelled, true);
console.log('Node direct packet aliases/completed routing, preflight and AbortSignal PASS');
