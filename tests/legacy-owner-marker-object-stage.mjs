// Genuine public-client partial object staging; no source/DB edits.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createLegacyComposedInstallMaterial } from './legacy-owner-install-composition-material.mjs';
import { createLegacyObjectInstallMaterial } from './legacy-owner-install-object-material.mjs';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot
  || !['marker-before-command', 'command-before-pending', 'cleanup-applied'].includes(mode)) throw new Error('PARTIAL_OBJECT_INPUT');
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const load = name => import(pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href);
const { SecureAgentClient } = await load('workspace-secure-agent');
const { secureHash, secureEqual, verifySecure, commitContext, verifiedJournalCheckpoint } = await load('workspace-secure-client');
const { decodeBase64Url, unsealContent, encodeCanonicalJson } = await load('workspace-secure-crypto');
const { SECURE_DOMAINS } = await load('workspace-secure-contract');
const { resolveProtocolInstall } = await load('workspace-protocol-install-plan');
const { compilePackageMaterial } = await load('workspace-protocol-package-source');
const { normalizeProtocolObjectSourceProof, readProtocolObjectSource } = await load('workspace-protocol-object-source');
const { verifyStagedProtocolObjectCheckpoint, validateProtocolObjectStageOperation, PROTOCOL_OBJECT_STAGE_ACTION } = await load('workspace-protocol-object-stage');
const { privateKey } = generateKeyPairSync('ed25519');
const paths = { state_path: join(sourceDir, 'agent.state'), pem_path: join(sourceDir, 'owner.pem'),
  intent_db_path: join(sourceDir, 'workspace-intents.sqlite'), options_path: join(sourceDir, 'install-options.json'),
  material_path: join(sourceDir, 'install-material.json') };
writeFileSync(paths.pem_path, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const agent = await SecureAgentClient.open({ baseUrl: new URL(origin).origin, privateKey,
  statePath: paths.state_path, intentDbPath: paths.intent_db_path });
try {
  const workspace = (await agent.create('Partial object stage source', 'PRIVATE', { structure: true })).workspaceId;
  const initial = await agent.journal(workspace);
  if (initial.policy.payload.v !== 3 || initial.policy.payload.visibility !== 'PRIVATE'
    || initial.structure?.state !== 'ACTIVE') throw new Error('PARTIAL_OBJECT_INITIAL');
  const middle = true; // Same public four-part author as the accepted T005 witness.
  const composed = middle ? await createLegacyComposedInstallMaterial(referenceRoot, true) : undefined;
  const material = composed?.material ?? await createLegacyObjectInstallMaterial(referenceRoot), compiled = compilePackageMaterial(material);
  const instance = randomBytes(32).toString('base64url'), key = `${workspace}.${instance}`;
  const options = { instance_id: instance, entrypoint: 'migrated_discussion', manifest: composed?.sourceManifest ?? compiled.manifest,
    ...(composed ? {dependencies:composed.dependencies} : {}),
    grants: [{ actor_id: agent.identity.actorId, actions: ['discussion.post'],
      protocol_roles: ['CONTRIBUTOR'], capabilities: ['POST'] }], expected_checkpoint: initial.checkpoint };
  const resolved = await resolveProtocolInstall(initial, options, agent.transport.discovery.protocol_features ?? []);
  if (resolved.digest !== compiled.protocolDigest || !secureEqual(resolved.manifest, compiled.manifest)) {
    throw new Error('PARTIAL_OBJECT_COMPILER');
  }
  for (const [path, value] of [[paths.options_path, options], [paths.material_path, material]]) {
    writeFileSync(path, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
  }
  const originalSave=agent.save.bind(agent); let stopped=false, sawPending=false;
  agent.save=()=>{
    originalSave();
    const marker=agent.state.protocol_object_stage_intents?.[key];
    if (!marker || stopped) return;
    const pending=Object.keys(agent.state.pending);
    if(pending.length) sawPending=true;
    const cut=mode==='marker-before-command' ? !marker.command_id
      : mode==='command-before-pending' ? !!marker.command_id && pending.length===0
      : sawPending && !!marker.command_id && pending.length===0;
    if(cut){stopped=true;throw new Error('TEST_MARKER_CUT');}
  };
  try {await agent.installProtocol(workspace,options);throw new Error('MARKER_NOT_INTERRUPTED');}
  catch(error){if(!stopped || error?.message!=='TEST_MARKER_CUT')throw error;}
  finally {agent.save=originalSave;}
  const marker=agent.state.protocol_object_stage_intents[key];
  if(Object.keys(agent.state.pending).length!==0 || Object.keys(agent.state.protocol_install_intents??{}).length!==0
    ||Object.keys(agent.state.protocol_object_stage_intents).length!==1
    ||Object.keys(marker).length!==(mode==='marker-before-command'?3:4)
    ||marker.request_hash!==await secureHash(options))throw new Error('MARKER_SHAPE');
  const proof=normalizeProtocolObjectSourceProof(marker.proof);
  if(proof.parts.length!==4 || !secureEqual(proof.source,initial.checkpoint)
    ||!secureEqual(readProtocolObjectSource(proof,marker.parts),{workspace_id:workspace,digest:compiled.protocolDigest,
      manifest:compiled.manifest,resolved_manifest:compiled.manifest,composition:composed.composition})) throw new Error('MARKER_MATERIAL');
  process.stdout.write(JSON.stringify({mode,...paths,workspace_id:workspace,owner_actor_id:agent.identity.actorId,
    owner_key_id:agent.identity.keyId,instance_id:instance,protocol_digest:compiled.protocolDigest,
    marker_hash:await secureHash(marker),orphan_command_id:marker.command_id??null,part_count:4,
    expected_accepted_parts:mode==='cleanup-applied'?1:0, original_checkpoint:initial.checkpoint,
    compiler_equality:true,cut_saved_before_throw:true})+'\n');
} finally {await agent.close();}
