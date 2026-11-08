// Node JSON mapping and SafeInteger validation; native boundary is stubbed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const realRequire = createRequire(import.meta.url), calls = [];
class KernelCancelHandle { cancel() {} }
const reply = (kind, args) => {
  const configIndex = kind === 'owner' || kind === 'invitation' ? 1 : 0;
  calls.push({ kind, config: JSON.parse(args[configIndex]) });
  return JSON.stringify({ ok: true, value: kind === 'owner' || kind === 'invitation' ? [] : {
    origin: 'https://control.example', workspace_id: 'w'.repeat(43), sequence: 0,
    head: null, policy_hash: 'p'.repeat(64), structure_status: 'ACTIVE',
    objects: [], operations: [], recoveries: [],
  } });
};
const native = {
  KernelCancelHandle,
  secureReadJson: async (...args) => reply('snapshot', args),
  secureReadProfileJson: async (...args) => reply('read', args),
  secureOwnerCreateJson: async (...args) => reply('owner', args),
  securePublicAdmissionJson: async (...args) => {
    calls.push({ kind:'invitation', config:JSON.parse(args[2]) });
    return JSON.stringify({ ok:true, value:[] });
  },
};
const mockRequire = name => name === '/stub/native' ? native : realRequire(name);
mockRequire.resolve = () => '/stub/native';
const api = {};
new Function('require', 'exports', 'process', readFileSync(new URL('../bindings/node/index.cjs', import.meta.url), 'utf8'))(mockRequire, api, process);

const constructors = [
  ['snapshot', opts => api.readSecureSnapshot({ origin:'https://control.example', kernelJournalPath:'/j',
    readStatePath:'/r', lifecyclePath:'/l', identityPath:'/i', workspaceId:'w'.repeat(43),
    authority:'a'.repeat(43), ownerActorId:'o'.repeat(43), ownerKeyId:'k'.repeat(43), ...opts })],
  ['read', opts => api.readSecureWorkspace({ origin:'https://control.example', stateDir:'/s',
    identityPath:'/i', workspaceId:'w'.repeat(43), ownerActorId:'o'.repeat(43), ownerKeyId:'k'.repeat(43), ...opts })],
  ['owner', opts => api.openSecureOwnerWorkspaces({ origin:'https://control.example', stateDir:'/s', ...opts }).operations()],
  ['invitation', opts => api.openSecureInvitation({ origin:'https://control.example', stateDir:'/s',
    workspaceId:'w'.repeat(43), ownerActorId:'o'.repeat(43), ownerKeyId:'k'.repeat(43), ...opts }).pendingDecisions()],
];

for (const [kind, invoke] of constructors) {
  await invoke({});
  assert.equal(calls.at(-1).kind, kind);
  assert.equal(calls.at(-1).config.max_replay_commits, 102400, kind);
  assert.equal(calls.at(-1).config.max_replay_artifact_bytes, 64 * 1024 * 1024, kind);
  await invoke({ maxReplayArtifactBytes:4096, maxReplayCommits:27 });
  assert.equal(calls.at(-1).config.max_replay_commits, 27, kind);
  assert.equal(calls.at(-1).config.max_replay_artifact_bytes, 4096, kind);
  for (const invalid of [true, false, 0, -1, 1.5, '27', Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    const before = calls.length;
    if (kind === 'snapshot' || kind === 'read') {
      await assert.rejects(invoke({ maxReplayCommits:invalid }), TypeError, kind);
    } else {
      assert.throws(() => invoke({ maxReplayCommits:invalid }), TypeError, kind);
    }
    assert.equal(calls.length, before, `${kind} invalid limit crossed native boundary`);
  }
}
console.log('Node four-constructor default/explicit/invalid SafeInteger mapping PASS (stub native boundary)');
