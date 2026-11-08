// Source-only Node facade routing and preflight with a stub native boundary.
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
    return JSON.stringify({ ok: true, value: { status: 'ORPHAN_NO_PACKET' } });
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
const material = '{"v":1}';
const selected = 'c'.repeat(43);
const digest = 'd'.repeat(64);
assert.equal((await owner.inspectMultipartOrphanPackageStage(input, material)).status, 'ORPHAN_NO_PACKET');
assert.equal(calls.at(-1)[0], 'orphan_multipart_inspect');
assert.equal(JSON.parse(calls.at(-1)[2]).material_json, material);
await owner.attachMultipartOrphanPackageStage({ ...input,
  selectedOrphanPackageStageCommandId: selected, expectedTsStateDigest: digest }, material);
assert.equal(calls.at(-1)[0], 'orphan_multipart_attach');
assert.equal(JSON.parse(calls.at(-1)[2]).attachment_input.selected_orphan_package_stage_command_id, selected);
const before = calls.length;
for (const invalid of [
  { ...input, selectedOrphanPackageStageCommandId: selected },
  { ...input, selectedOrphanPackageStageCommandId: selected,
    selectedPendingPackageStageCommandId: 'p'.repeat(43), expectedTsStateDigest: digest },
  { ...input, selectedOrphanPackageStageCommandId: selected,
    expectedTsStateDigest: digest, unsupported: true },
]) {
  assert.throws(() => owner.attachMultipartOrphanPackageStage(invalid, material), TypeError);
}
assert.throws(() => owner.inspectMultipartOrphanPackageStage(input, ''), TypeError);
assert.equal(calls.length, before);
const controller = new AbortController();
controller.abort();
await owner.inspectMultipartOrphanPackageStage(input, material, { signal: controller.signal });
assert.equal(calls.at(-1)[5].cancelled, true);
console.log('Node orphan multipart facade: routing, preflight and AbortSignal PASS');
