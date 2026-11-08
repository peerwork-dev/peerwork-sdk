// Advance only the real service through public APIs using a byte-identical
// protected copy of a genuine stopped source. The original export stays inert.
import { createPrivateKey } from 'node:crypto';
import { mkdirSync, readFileSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [origin, source, clone, referenceRoot, workspace, mode] = process.argv.slice(2);
if (!['action', 'rotate'].includes(mode)) throw new Error('PARTIAL_OBJECT_CURRENT_INPUT');
const before = readFileSync(join(source, 'agent.state'));
mkdirSync(clone, { mode: 0o700 });
copyFileSync(join(source, 'agent.state'), join(clone, 'agent.state'));
const { SecureAgentClient } = await import(pathToFileURL(join(referenceRoot, 'dist-workspace/src/workspace-secure-agent.js')).href);
const privateKey = createPrivateKey(readFileSync(join(source, 'owner.pem')));
const agent = await SecureAgentClient.open({ baseUrl: new URL(origin).origin, privateKey,
  statePath: join(clone, 'agent.state'), intentDbPath: join(clone, 'workspace-intents.sqlite') });
try {
  const initial = await agent.journal(workspace);
  let after;
  if (mode === 'rotate') after = await agent.rotate(workspace);
  else {
    const wiki = initial.objects.find(row => row.kind === 'instances' && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('PARTIAL_OBJECT_CURRENT_WIKI');
    after = await agent.action(workspace, wiki.id, 'wiki.create', { title: 'Later signed head', body: 'Authenticated alternate stage predecessor' });
  }
  if (after.checkpoint.sequence !== initial.checkpoint.sequence + 1 || after.structure?.state !== 'ACTIVE'
    || !before.equals(readFileSync(join(source, 'agent.state')))
    || mode === 'rotate' && after.policy.payload.epoch !== initial.policy.payload.epoch + 1) {
    throw new Error('PARTIAL_OBJECT_CURRENT_NOT_ADVANCED');
  }
  process.stdout.write(JSON.stringify({ mode, source_sequence: initial.checkpoint.sequence,
    current_sequence: after.checkpoint.sequence, epoch: after.policy.payload.epoch,
    source_unchanged: true, structure: after.structure.state }) + '\n');
} finally { await agent.close(); }
