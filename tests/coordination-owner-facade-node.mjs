// Public marshalling and AbortSignal checks; native boundary is stubbed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const realRequire = createRequire(import.meta.url), calls = [];
let errorMode = false;
class KernelCancelHandle { cancel() { this.cancelled = true; } }
const native = { KernelCancelHandle, secureOwnerCreateJson: async (...args) => {
  calls.push(args);
  if (errorMode) return JSON.stringify({ok:false,code:"COORDINATION_CONFLICT",message:"selected operation conflicts"});
  return JSON.stringify({ ok:true, value:args[0] === 'coordination_operations' ? [] : {
    status:'PENDING', workspace_id:args[4], version:2, begin_command_id:'b'.repeat(43),
    protocol_digest:'d'.repeat(64), instance_id:'i'.repeat(43), step_command_id:'e'.repeat(43),
    step_action_id:'secure.structure.begin', sequence:null, head:null, policy_hash:null,
  } });
} };
const mockRequire = name => name === '/stub/native' ? native : realRequire(name);
mockRequire.resolve = () => '/stub/native';
const exports = {};
new Function('require', 'exports', 'process', readFileSync(new URL('../bindings/node/index.cjs', import.meta.url), 'utf8'))(mockRequire, exports, process);
const owner = exports.openSecureOwnerWorkspaces({ origin:'https://control.example', stateDir:'/protected/root' });
const workspace = 'w'.repeat(43), begin = 'b'.repeat(43);
await owner.enableCoordination(workspace);
assert.equal(calls.at(-1)[0], 'coordination_enable');
assert.deepEqual(JSON.parse(calls.at(-1)[2]), { version:null, participants:null });
assert.equal(calls.at(-1)[4], workspace);
const value = await owner.enableCoordination(workspace, { version:2, participants:[] });
assert.deepEqual(JSON.parse(calls.at(-1)[2]), { version:2, participants:[] });
assert.equal(value.begin_command_id, begin); assert.equal(value.sequence, null);
await owner.enableCoordination(workspace, { version:1, participants:['a'.repeat(43)] });
assert.deepEqual(JSON.parse(calls.at(-1)[2]).participants, ['a'.repeat(43)]);
await owner.resumeCoordination(workspace, begin);
assert.equal(calls.at(-1)[0], 'coordination_resume');
assert.equal(calls.at(-1)[2], undefined);
assert.equal(calls.at(-1)[3], begin); assert.equal(calls.at(-1)[4], workspace);
assert.deepEqual(await owner.coordinationOperations(workspace), []);
assert.equal(calls.at(-1)[0], 'coordination_operations');
const before = calls.length;
for (const input of [{version:true}, {version:3}, {version:'2'}, {participants:'actor'},
  {participants:['']}, {participants:[1]}, {material:{}}, {grants:[]}]) {
  assert.throws(() => owner.enableCoordination(workspace, input), TypeError);
}
assert.equal(calls.length, before);
errorMode = true;
await assert.rejects(owner.resumeCoordination(workspace, begin), error =>
  error.code === 'COORDINATION_CONFLICT' && error.message === 'selected operation conflicts');
errorMode = false;
const controller = new AbortController(); controller.abort();
await owner.enableCoordination(workspace, {version:2}, {signal:controller.signal});
assert.equal(calls.at(-1)[5].cancelled, true);
await owner.resumeCoordination(workspace, begin, {signal:controller.signal});
assert.equal(calls.at(-1)[5].cancelled, true);
await owner.coordinationOperations(workspace, {signal:controller.signal});
assert.equal(calls.at(-1)[5].cancelled, true);
console.log('Node coordination omission/empty, original BEGIN, history and AbortSignal PASS (stub boundary)');
