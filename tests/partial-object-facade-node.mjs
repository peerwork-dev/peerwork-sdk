// Public Node marshalling/preflight/AbortSignal; no native/service execution.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const realRequire = createRequire(import.meta.url);
const calls = [];
class KernelCancelHandle { cancel() { this.cancelled = true; } }
const native = { KernelCancelHandle, secureOwnerCreateJson: async (...args) => {
  calls.push(args); return JSON.stringify({ ok: true, value: { status: 'ATTACHED_RESTRICTED' } });
} };
const mockRequire = name => name === '/stub/native' ? native : realRequire(name);
mockRequire.resolve = () => '/stub/native';
const exports = {};
new Function('require', 'exports', 'process', readFileSync(new URL('../bindings/node/index.cjs', import.meta.url), 'utf8'))(mockRequire, exports, process);
const owner = exports.openSecureOwnerWorkspaces({ origin: 'https://control.example', stateDir: '/protected/root' });
const input = { workspaceId: 'w'.repeat(43), protectedTsStatePath: '/protected/source/state',
  protectedTsIntentDbPath: '/protected/source/intents.sqlite', protectedOwnerPkcs8Path: '/protected/source/owner.pem',
  expectedOwnerActorId: 'a'.repeat(43), expectedOwnerKeyId: 'k'.repeat(43) };
const selected = 's'.repeat(43), digest = 'd'.repeat(64), attachId = 't'.repeat(43);
const options = '{ "instance_id": "chosen", "label": "雪" }', material = '{ "closure": {} }';
await owner.inspectPendingObjectStage(input, selected, options, material);
assert.equal(calls.at(-1)[0], 'object_stage_inspect');
const request = JSON.parse(calls.at(-1)[2]);
assert.deepEqual(Object.keys(request).sort(), ['attachment_input', 'expected_ts_state_digest', 'material_json', 'options_json', 'selected_command_id']);
assert.equal(request.selected_command_id, selected);
assert.equal(request.expected_ts_state_digest, null);
assert.equal(request.options_json, options); assert.equal(request.material_json, material);
assert.equal(request.attachment_input.protected_ts_state_path, input.protectedTsStatePath);
await owner.attachPendingObjectStage(input, selected, digest, options, material);
assert.equal(calls.at(-1)[0], 'object_stage_attach');
assert.equal(JSON.parse(calls.at(-1)[2]).expected_ts_state_digest, digest);
await owner.recoverPendingObjectStage(attachId, selected);
assert.equal(calls.at(-1)[0], 'object_stage_recover');
assert.equal(calls.at(-1)[3], selected); assert.equal(calls.at(-1)[4], attachId);
const before = calls.length;
for (const invalid of [{ ...input, unsupported: true }, { ...input, recoverPendingAction: true },
  { ...input, selectedPendingPackageStageCommandId: selected, expectedTsStateDigest: digest },
  { ...input, expectedTsStateDigest: digest }]) {
  assert.throws(() => owner.inspectPendingObjectStage(invalid, selected, options, material), TypeError);
}
assert.throws(() => owner.inspectPendingObjectStage(input, '', options, material), TypeError);
assert.throws(() => owner.inspectPendingObjectStage(input, selected, '', material), TypeError);
assert.throws(() => owner.inspectPendingObjectStage(input, selected, options, ''), TypeError);
assert.throws(() => owner.attachPendingObjectStage(input, selected, '', options, material), TypeError);
assert.equal(calls.length, before);
const controller = new AbortController(); controller.abort();
await owner.recoverPendingObjectStage(attachId, selected, { signal: controller.signal });
assert.equal(calls.at(-1)[5].cancelled, true);
console.log('Node partial object routing, exact strings/IDs, selection isolation and AbortSignal PASS (stub boundary)');
