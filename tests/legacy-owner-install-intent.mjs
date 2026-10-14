// Genuine f828 public-client install-intent snapshots. The hooks interrupt
// supported client boundaries; they never edit the saved state or service DB.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const [origin, sourceDir, referenceRoot, mode] = process.argv.slice(2);
if (!origin || !sourceDir || !referenceRoot
  || !['begin-applied-loss', 'begin-before-post', 'completed-end',
    'direct-begin-applied-loss', 'direct-begin-before-post',
    'direct-two-workspace-before-post', 'direct-completed-end',
    'direct-page-before-post', 'direct-page-applied-loss',
    'direct-end-before-post', 'direct-end-applied-loss',
    'direct-checkpoint-begin-before-post', 'direct-checkpoint-end-applied-loss',
    'direct-checkpoint-completed-end', 'direct-disclosure-begin-before-post',
    'direct-disclosure-end-applied-loss', 'direct-no-grants-begin-before-post',
    'direct-empty-disclosure-begin-before-post', 'direct-composition-begin-before-post',
    'direct-composition-end-applied-loss', 'direct-staged-package-begin-before-post',
    'direct-staged-package-end-applied-loss', 'direct-staged-package-page-before-post',
    'direct-staged-package-page-applied-loss', 'direct-staged-package-completed-end',
    'direct-implicit-begin-before-post', 'direct-implicit-end-applied-loss',
    'direct-object-begin-before-post', 'direct-object-end-applied-loss',
    'direct-object-page-before-post', 'direct-object-page-applied-loss', 'direct-object-completed-end'].includes(mode)) {
  throw new Error('INSTALL_INTENT_TEST_INPUT');
}
mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
const { privateKey } = generateKeyPairSync('ed25519');
const pemPath = join(sourceDir, 'owner.pem');
const statePath = join(sourceDir, 'agent.state');
const intentDbPath = join(sourceDir, 'workspace-intents.sqlite');
const optionsPath = join(sourceDir, 'install-options.json');
const materialPath = join(sourceDir, 'install-material.json');
writeFileSync(pemPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
const moduleUrl = name => pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href;
const { SecureAgentClient } = await import(moduleUrl('workspace-secure-agent'));
const { discussionPreset } = await import(moduleUrl('workspace-presets'));
const { secureHash, secureEqual } = await import(moduleUrl('workspace-secure-client'));
const { resolveProtocolInstall } = await import(moduleUrl('workspace-protocol-install-plan'));
const agent = await SecureAgentClient.open({
  baseUrl: new URL(origin).origin, privateKey, statePath, intentDbPath,
});
try {
  const created = await agent.create('Legacy install intent proof', 'PRIVATE', { structure: true });
  const workspaceId = created.workspaceId;
  let initial = await agent.journal(workspaceId);
  const disclosureOption = mode.startsWith('direct-disclosure-');
  const emptyDisclosureOption = mode.startsWith('direct-empty-disclosure-');
  const omittedGrants = mode.startsWith('direct-no-grants-');
  const compositionOption = mode.startsWith('direct-composition-');
  const implicitOption = mode.startsWith('direct-implicit-');
  const stagedPackageOption = mode.startsWith('direct-staged-package-');
  const objectSourceOption = mode.startsWith('direct-object-');
  let stagedPackage;
  let compiledMaterial;
  let installSource;
  const normalizedOptions = disclosureOption || emptyDisclosureOption || omittedGrants;
  let compositionMaterial;
  const checkpointOption = mode.startsWith('direct-checkpoint-') || disclosureOption || objectSourceOption;
  if (disclosureOption || emptyDisclosureOption || stagedPackageOption) {
    initial = await agent.enableFormatTwo(workspaceId);
    if (initial.policy.payload.protocol_format_ceiling !== 2
      || initial.structure?.state !== 'ACTIVE') throw new Error('INSTALL_DISCLOSURE_CEILING');
  }
  const retainedStep = /^direct-(page|end)-/.exec(mode.replace(
    /^direct-(checkpoint|disclosure|empty-disclosure|no-grants|composition|staged-package|implicit|object)-/, 'direct-'))?.[1];
  if (retainedStep === 'page') {
    const wiki = initial.objects.find(row => row.kind === 'instances'
      && row.value.origin_entrypoint === 'wiki');
    if (!wiki) throw new Error('INSTALL_INTENT_WIKI_MISSING');
    initial = await agent.action(workspaceId, wiki.id, 'wiki.create', {
      title: 'Retained install PAGE source', body: 'Signed original snapshot record',
    });
  }
  if (initial.policy.payload.v !== 3 || initial.policy.payload.visibility !== 'PRIVATE'
    || initial.structure?.state !== 'ACTIVE') throw new Error('INSTALL_INTENT_INITIAL_POLICY');
  let manifest;
  if (mode.startsWith('direct-')) {
    const { parseProtocolPackage, PROTOCOL_PACKAGE_FORMAT } = await import(moduleUrl('protocol-package'));
    const { createProtocolPackageClosure } = await import(moduleUrl('protocol-package-closure'));
    const { compilePackageMaterial } = await import(moduleUrl('workspace-protocol-package-source'));
    const directory = join(referenceRoot, 'protocols/discussion');
    const files = {};
    const walk = at => {
      for (const entry of readdirSync(at, { withFileTypes: true })) {
        const path = join(at, entry.name);
        if (entry.isDirectory()) walk(path);
        else files[relative(directory, path).split(sep).join('/')] = readFileSync(path, 'utf8');
      }
    };
    walk(directory);
    compositionMaterial = compositionOption || implicitOption
      ? await (await import('./legacy-owner-install-composition-material.mjs')).createLegacyComposedInstallMaterial(referenceRoot) : undefined;
    const material = objectSourceOption
      ? await (await import('./legacy-owner-install-object-material.mjs')).createLegacyObjectInstallMaterial(referenceRoot)
      : compositionMaterial ? compositionMaterial.material : disclosureOption || emptyDisclosureOption || stagedPackageOption
      ? await (await import('./legacy-owner-install-disclosure-material.mjs')).createLegacyReadableInstallMaterial(referenceRoot)
      : { v: 1, closure: createProtocolPackageClosure(
        parseProtocolPackage({ format: PROTOCOL_PACKAGE_FORMAT, files }), []), bindings: {} };
    const compiled = compilePackageMaterial(material);
    compiledMaterial = compiled;
    manifest = compositionMaterial ? compositionMaterial.sourceManifest : compiled.manifest;
    writeFileSync(materialPath, JSON.stringify(material), { mode: 0o600, flag: 'wx' });
    if (implicitOption) {
      const dependency = compositionMaterial.dependencies[0];
      // Install the compiler-selected namespaced child through the public API;
      // its authenticated protocol object, not material bytes, is availability.
      await agent.installProtocol(workspaceId, {
        instance_id: randomBytes(32).toString('base64url'), entrypoint: 'implicit_dependency',
        manifest: dependency.manifest, grants: [],
      });
      initial = await agent.journal(workspaceId);
      const installed = initial.objects.find(row => row.kind === 'protocols' && row.id === dependency.digest);
      const storedManifest = installed && (typeof installed.value.manifest === 'string'
        ? JSON.parse(installed.value.manifest) : installed.value.manifest);
      if (initial.structure?.state !== 'ACTIVE' || !installed
        || !secureEqual(storedManifest, dependency.manifest)) throw new Error('INSTALL_IMPLICIT_AUTHENTICATED_DEPENDENCY');
    }
    if (stagedPackageOption) {
      stagedPackage = await agent.stagePackageMaterial(workspaceId, material, initial.checkpoint);
      const { verifyProtocolPackageSource, verifyStagedPackageCheckpoint, readProtocolPackageMaterial }
        = await import(moduleUrl('workspace-protocol-package-source'));
      const stagedCompilation = verifyProtocolPackageSource(stagedPackage.proof, stagedPackage.journal.objects);
      installSource = verifyStagedPackageCheckpoint(stagedPackage.journal, stagedPackage.proof, stagedPackage.journal.checkpoint);
      if (!secureEqual(readProtocolPackageMaterial(stagedPackage.proof, stagedPackage.journal.objects), material)
        || stagedCompilation.protocolDigest !== compiled.protocolDigest
        || !secureEqual(stagedCompilation.manifest, compiled.manifest)
        || stagedPackage.proof.root_package_digest !== material.closure.root_package_digest
        || stagedPackage.proof.source_sha256 !== await secureHash(material)
        || stagedPackage.proof.compilation_lock_sha256 !== await secureHash(compiled.lock)
        || installSource.sequence !== initial.checkpoint.sequence + stagedPackage.proof.parts.length
        || installSource.policy_hash !== initial.checkpoint.policy_hash
        || Object.keys(agent.state.package_stage_intents ?? {}).length !== 0) {
        throw new Error('INSTALL_STAGED_PACKAGE_COMPILER_PREFIX');
      }
    }
  } else {
    manifest = discussionPreset();
    manifest.name = 'example.native-install-intent.v1';
  }
  if (mode === 'direct-two-workspace-before-post') {
    const otherCreated = await agent.create('Other pending install intent', 'PRIVATE', { structure: true });
    const otherWorkspaceId = otherCreated.workspaceId;
    const otherInitial = await agent.journal(otherWorkspaceId);
    if (otherInitial.policy.payload.v !== 3
      || otherInitial.policy.payload.visibility !== 'PRIVATE'
      || otherInitial.structure?.state !== 'ACTIVE') {
      throw new Error('INSTALL_INTENT_OTHER_INITIAL_POLICY');
    }
    const makeOptions = instanceId => ({
      instance_id: instanceId, entrypoint: 'migrated_discussion', manifest,
      grants: [{ actor_id: agent.identity.actorId, actions: ['discussion.post'],
        protocol_roles: ['CONTRIBUTOR'], capabilities: ['POST'] }],
    });
    const instanceId = randomBytes(32).toString('base64url');
    const otherInstanceId = randomBytes(32).toString('base64url');
    const options = makeOptions(instanceId);
    const otherOptions = makeOptions(otherInstanceId);
    const resolved = await resolveProtocolInstall(initial, options, []);
    const otherResolved = await resolveProtocolInstall(otherInitial, otherOptions, []);
    writeFileSync(optionsPath, JSON.stringify(options), { mode: 0o600, flag: 'wx' });
    const originalRequest = agent.request.bind(agent);
    const interrupted = new Set();
    agent.request = async (path, requestOptions) => {
      for (const id of [workspaceId, otherWorkspaceId]) {
        if (requestOptions?.method === 'POST'
          && path === `/api/workspace/v1/secure/workspaces/${id}/commits`
          && !interrupted.has(id)) {
          interrupted.add(id);
          throw new Error('TEST_STOP_BEFORE_INSTALL_BEGIN_POST');
        }
      }
      return originalRequest(path, requestOptions);
    };
    try {
      for (const [id, selected] of [[workspaceId, options], [otherWorkspaceId, otherOptions]]) {
        try {
          await agent.installProtocol(id, selected);
          throw new Error('TEST_INSTALL_NOT_INTERRUPTED');
        } catch (error) {
          if (error?.message !== 'TEST_STOP_BEFORE_INSTALL_BEGIN_POST') throw error;
        }
      }
    } finally {
      agent.request = originalRequest;
    }
    const entries = Object.entries(agent.state.pending);
    const map = agent.state.protocol_install_intents ?? {};
    const selected = entries.find(([, row]) => row.path ===
      `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`);
    const other = entries.find(([, row]) => row.path ===
      `/api/workspace/v1/secure/workspaces/${otherWorkspaceId}/commits`);
    if (interrupted.size !== 2 || entries.length !== 2 || Object.keys(map).length !== 2
      || !selected || !other || selected[0] === other[0]
      || map[`${workspaceId}.${instanceId}`] !== resolved.intentHash
      || map[`${otherWorkspaceId}.${otherInstanceId}`] !== otherResolved.intentHash
      || selected[0] !== selected[1].body?.commit?.payload?.command_id
      || other[0] !== other[1].body?.commit?.payload?.command_id
      || selected[1].body?.commit?.payload?.action_id !== 'secure.structure.begin'
      || other[1].body?.commit?.payload?.action_id !== 'secure.structure.begin') {
      throw new Error('INSTALL_INTENT_TWO_WORKSPACE_SHAPE');
    }
    const latest = await agent.journal(workspaceId);
    const otherLatest = await agent.journal(otherWorkspaceId);
    if (latest.checkpoint.sequence !== initial.checkpoint.sequence
      || otherLatest.checkpoint.sequence !== otherInitial.checkpoint.sequence) {
      throw new Error('INSTALL_INTENT_TWO_WORKSPACE_POSTED');
    }
    process.stdout.write(JSON.stringify({
      mode, workspace_id: workspaceId, other_workspace_id: otherWorkspaceId,
      owner_actor_id: agent.identity.actorId, owner_key_id: agent.identity.keyId,
      state_path: statePath, pem_path: pemPath, intent_db_path: intentDbPath,
      options_path: optionsPath, material_path: materialPath,
      instance_id: instanceId, intent_key: `${workspaceId}.${instanceId}`,
      intent_hash: resolved.intentHash, protocol_digest: resolved.digest,
      entrypoint: options.entrypoint, initial_sequence: initial.checkpoint.sequence,
      latest_sequence: latest.checkpoint.sequence,
      latest_structure_state: latest.structure?.state ?? null,
      pending_count: entries.length, pending_command_id: selected[0],
      pending_commit_hash: await secureHash(selected[1].body.commit),
      other_instance_id: otherInstanceId, other_intent_hash: otherResolved.intentHash,
      other_pending_command_id: other[0],
      other_pending_commit_hash: await secureHash(other[1].body.commit),
      other_initial_sequence: otherInitial.checkpoint.sequence,
      other_latest_sequence: otherLatest.checkpoint.sequence,
    }) + '\n');
  } else {
  const instanceId = randomBytes(32).toString('base64url');
  const options = {
    instance_id: instanceId, entrypoint: 'migrated_discussion', manifest,
    ...(compositionOption ? { dependencies: compositionMaterial.dependencies } : {}),
    ...(stagedPackageOption ? { package_source: stagedPackage.proof,
      expected_checkpoint: structuredClone(initial.checkpoint) } : {}),
    ...(!omittedGrants ? { grants: [{ actor_id: agent.identity.actorId,
      actions: disclosureOption || emptyDisclosureOption || stagedPackageOption ? ['set'] : ['discussion.post'],
      protocol_roles: disclosureOption || emptyDisclosureOption || stagedPackageOption ? [] : ['CONTRIBUTOR'],
      capabilities: disclosureOption || emptyDisclosureOption || stagedPackageOption ? [] : ['POST'] }] } : {}),
    ...(disclosureOption || emptyDisclosureOption ? { disclose: [{ schema: 'item',
      fields: emptyDisclosureOption ? [] : ['title', 'label'] }] } : {}),
    ...(checkpointOption ? { expected_checkpoint: structuredClone(initial.checkpoint) } : {}),
  };
  const resolved = await resolveProtocolInstall(stagedPackage?.journal ?? initial, options,
    disclosureOption || emptyDisclosureOption || stagedPackageOption ? agent.transport.discovery.protocol_features ?? [] : []);
  if (checkpointOption && (!secureEqual(resolved.expectedCheckpoint, initial.checkpoint)
    || !normalizedOptions && await secureHash(options) !== resolved.intentHash)) {
    throw new Error('INSTALL_INTENT_REVIEWED_CHECKPOINT_HASH');
  }
  if (stagedPackageOption && (!secureEqual(resolved.packageSource, stagedPackage.proof)
    || !secureEqual(resolved.expectedCheckpoint, installSource)
    || resolved.digest !== compiledMaterial.protocolDigest
    || !secureEqual(resolved.manifest, compiledMaterial.manifest)
    || resolved.composition !== undefined)) throw new Error('INSTALL_INTENT_STAGED_PACKAGE_RESOLUTION');
  if ((compositionOption || implicitOption) && (await secureHash(options) === resolved.intentHash
    || resolved.digest !== compositionMaterial.protocolDigest
    || !secureEqual(resolved.manifest, compositionMaterial.compiledManifest)
    || !secureEqual(resolved.composition, compositionMaterial.composition))) {
    throw new Error('INSTALL_INTENT_COMPOSITION_COMPILER_EQUALITY');
  }
  if (implicitOption && (Object.hasOwn(options, 'dependencies')
    || resolved.composition.dependencies.length !== 1
    || resolved.composition.dependencies[0].digest !== compositionMaterial.dependencies[0].digest)) {
    throw new Error('INSTALL_IMPLICIT_SELECTION');
  }
  if (normalizedOptions && (await secureHash(options) === resolved.intentHash
    || omittedGrants && resolved.grants.length !== 0
    || (disclosureOption || emptyDisclosureOption) && !secureEqual(resolved.disclose,
      [{ protocol_digest: resolved.digest, schema: 'item',
        fields: emptyDisclosureOption ? [] : ['label', 'title'] }]))) {
    throw new Error('INSTALL_INTENT_NORMALIZED_OPTIONS');
  }
  writeFileSync(optionsPath, JSON.stringify(options), { mode: 0o600, flag: 'wx' });
  const key = `${workspaceId}.${instanceId}`;
  const originalPost = agent.post.bind(agent);
  const originalRequest = agent.request.bind(agent);
  let stopped = false;
  let observedAction = null;
  if (mode.endsWith('applied-loss') && !retainedStep) {
    const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
    if (!hook.ok) throw new Error('INSTALL_INTENT_DROP_HOOK');
  }
  if (mode.endsWith('before-post')) {
    agent.request = async (path, requestOptions) => {
      if (!stopped && requestOptions?.method === 'POST'
        && path === `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`
        && (!retainedStep || JSON.parse(requestOptions.body).commit.payload.action_id
          === `secure.structure.${retainedStep}`)
        && (!objectSourceOption || retainedStep || JSON.parse(requestOptions.body).commit.payload.action_id === 'secure.structure.begin')) {
        stopped = true;
        throw new Error('TEST_STOP_BEFORE_INSTALL_BEGIN_POST');
      }
      return originalRequest(path, requestOptions);
    };
  }
  if (retainedStep && mode.endsWith('applied-loss')) {
    agent.post = async (...args) => {
      if (!stopped && args[1]?.commit?.payload?.action_id === `secure.structure.${retainedStep}`) {
        stopped = true;
        const hook = await fetch(new URL('/__test/drop-next-post', origin), { method: 'POST', body: '{}' });
        if (!hook.ok) throw new Error('INSTALL_INTENT_STEP_DROP_HOOK');
      }
      return originalPost(...args);
    };
  }
  if (mode.endsWith('completed-end')) {
    agent.post = async (...args) => {
      const action = args[1]?.commit?.payload?.action_id;
      const result = await originalPost(...args);
      if (!stopped && action === 'secure.structure.end') {
        stopped = true;
        observedAction = action;
        throw new Error('TEST_STOP_AFTER_INSTALL_END_POST');
      }
      return result;
    };
  }
  try {
    await agent.installProtocol(workspaceId, options);
    throw new Error('TEST_INSTALL_NOT_INTERRUPTED');
  } catch (error) {
    if (mode.endsWith('before-post') || mode.endsWith('completed-end')) {
      const expected = mode.endsWith('before-post')
        ? 'TEST_STOP_BEFORE_INSTALL_BEGIN_POST' : 'TEST_STOP_AFTER_INSTALL_END_POST';
      if (error?.message !== expected) throw error;
    } else {
      // Preserve the original failure unless this is the intended transport
      // loss boundary. A map/pending assertion must not hide a planner error.
      if (retainedStep ? !stopped : !Object.keys(agent.state.pending).length) throw error;
      if (error?.message === 'TEST_INSTALL_NOT_INTERRUPTED') throw error;
    }
  } finally {
    agent.post = originalPost;
    agent.request = originalRequest;
  }
  const retainedHash = agent.state.protocol_install_intents?.[key];
  if (retainedHash !== resolved.intentHash) {
    throw new Error('INSTALL_INTENT_MAP_MISSING');
  }
  const pending = Object.entries(agent.state.pending);
  const expectedPending = mode.endsWith('completed-end') ? 0 : 1;
  if (pending.length !== expectedPending) throw new Error('INSTALL_INTENT_PENDING_COUNT');
  const selected = pending[0];
  if (selected && (selected[0] !== selected[1].body?.commit?.payload?.command_id
    || selected[1].path !== `/api/workspace/v1/secure/workspaces/${workspaceId}/commits`
    || selected[1].body?.commit?.payload?.action_id !== `secure.structure.${retainedStep ?? 'begin'}`)) {
    throw new Error('INSTALL_INTENT_PENDING_BEGIN_MISMATCH');
  }
  const journal = await agent.journal(workspaceId);
  let completedObjectSource;
  let objectBeginPredecessor;
  if (objectSourceOption) {
    const { readProtocolObjectSource, normalizeProtocolObjectSourceProof } = await import(moduleUrl('workspace-protocol-object-source'));
    const { verifyStagedProtocolObjectCheckpoint } = await import(moduleUrl('workspace-protocol-object-stage'));
    const { verifiedJournalCheckpoint } = await import(moduleUrl('workspace-secure-client'));
    const marker = agent.state.protocol_object_stage_intents?.[key];
    if (!marker || marker.request_hash !== await secureHash(options) || marker.command_id !== undefined) {
      throw new Error('INSTALL_OBJECT_MARKER');
    }
    completedObjectSource = normalizeProtocolObjectSourceProof(marker.proof);
    const proof = completedObjectSource;
    if (proof.parts.length < 2 || !secureEqual(proof.source, initial.checkpoint)
      || proof.protocol_digest !== compiledMaterial.protocolDigest
      || !secureEqual(marker.parts, journal.objects.filter(row => row.kind === 'protocol_object_part'
        && row.value.source_id === proof.source_id).sort((a, b) => a.value.index - b.value.index))) {
      throw new Error('INSTALL_OBJECT_COMPLETE_PARTS');
    }
    const logical = readProtocolObjectSource(proof, journal.objects);
    if (!secureEqual(logical, { workspace_id: workspaceId, digest: compiledMaterial.protocolDigest,
      manifest: compiledMaterial.manifest, resolved_manifest: compiledMaterial.manifest })) {
      throw new Error('INSTALL_OBJECT_COMPILED_VALUE');
    }
    objectBeginPredecessor = verifyStagedProtocolObjectCheckpoint(journal, proof,
      verifiedJournalCheckpoint(journal, proof.source.sequence + proof.parts.length));
    if (selected?.[1].body.commit.payload.action_id === 'secure.structure.begin'
      ? selected[1].body.commit.payload.previous !== objectBeginPredecessor.head
        || selected[1].body.commit.payload.sequence !== objectBeginPredecessor.sequence + 1
        || selected[1].body.policy_update.payload.previous_policy !== objectBeginPredecessor.policy_hash
      : !journal.installations?.some(row => row.instance_id === instanceId
        && secureEqual(row.object_source, proof) && secureEqual(row.source, objectBeginPredecessor))) {
      throw new Error('INSTALL_OBJECT_BEGIN_SOURCE');
    }
  }
  if (stagedPackageOption && (selected?.[1].body?.commit?.payload?.action_id === 'secure.structure.begin'
    ? selected[1].body.commit.payload.previous !== installSource.head
      || selected[1].body.commit.payload.sequence !== installSource.sequence + 1
      || selected[1].body.policy_update.payload.previous_policy !== installSource.policy_hash
    : !journal.installations?.some(row => row.instance_id === instanceId
      && secureEqual(row.source, installSource)))) throw new Error('INSTALL_STAGED_PACKAGE_BEGIN_SOURCE');
  if (checkpointOption && !objectSourceOption && (selected?.[1].body?.commit?.payload?.action_id === 'secure.structure.begin'
    ? selected[1].body.commit.payload.previous !== options.expected_checkpoint.head
      || selected[1].body.commit.payload.sequence !== options.expected_checkpoint.sequence + 1
      || selected[1].body.policy_update.payload.previous_policy !== options.expected_checkpoint.policy_hash
    : !journal.installations?.some(row => row.instance_id === instanceId
      && secureEqual(row.source, options.expected_checkpoint)))) {
    throw new Error('INSTALL_INTENT_REVIEWED_CHECKPOINT_SOURCE');
  }
  const effectiveBeginPredecessor = objectBeginPredecessor ?? installSource ?? initial.checkpoint;
  if (mode.endsWith('completed-end')) {
    if (!stopped || observedAction !== 'secure.structure.end'
      || journal.structure?.state !== 'ACTIVE'
      || !journal.objects.some(row => row.kind === 'instances' && row.id === instanceId
        && row.value.protocol_digest === resolved.digest
        && row.value.origin_entrypoint === options.entrypoint)
      || !journal.installations?.some(row => row.instance_id === instanceId
        && row.protocol_digest === resolved.digest && row.entrypoint === options.entrypoint)) {
      throw new Error('INSTALL_INTENT_SIGNED_COMPLETION_MISSING');
    }
  } else if (!retainedStep && ((mode.endsWith('before-post') && (!stopped || journal.checkpoint.sequence !== effectiveBeginPredecessor.sequence))
    || (mode.endsWith('applied-loss') && journal.checkpoint.sequence !== effectiveBeginPredecessor.sequence + 1))) {
    throw new Error('INSTALL_INTENT_BEGIN_STATE_MISMATCH');
  }
  if (retainedStep) {
    const sequence = selected[1].body.commit.payload.sequence;
    if (sequence < initial.checkpoint.sequence + 2
      || journal.checkpoint.sequence !== sequence - (mode.endsWith('before-post') ? 1 : 0)
      || journal.structure?.state !== (retainedStep === 'end' && mode.endsWith('applied-loss') ? 'ACTIVE' : 'SEEDING')) {
      throw new Error('INSTALL_INTENT_RETAINED_STEP_STATE');
    }
  }
  process.stdout.write(JSON.stringify({
    mode, pending_action_id: selected?.[1].body?.commit?.payload?.action_id ?? null,
    pending_sequence: selected?.[1].body?.commit?.payload?.sequence ?? null,
    workspace_id: workspaceId, owner_actor_id: agent.identity.actorId,
    owner_key_id: agent.identity.keyId, state_path: statePath,
    pem_path: pemPath, intent_db_path: intentDbPath, options_path: optionsPath,
    material_path: mode.startsWith('direct-') ? materialPath : null,
    instance_id: instanceId, intent_key: key, intent_hash: retainedHash,
    protocol_digest: resolved.digest, entrypoint: options.entrypoint,
    initial_sequence: initial.checkpoint.sequence, latest_sequence: journal.checkpoint.sequence,
    latest_structure_state: journal.structure?.state ?? null,
    pending_count: pending.length, pending_command_id: selected?.[0] ?? null,
    pending_commit_hash: selected ? await secureHash(selected[1].body.commit) : null,
    ...(checkpointOption ? { expected_checkpoint: options.expected_checkpoint,
      canonical_options_hash: await secureHash(options) } : {}),
    ...(objectSourceOption ? { object_source: completedObjectSource,
      begin_predecessor: objectBeginPredecessor, source_parts: completedObjectSource.parts.length,
      completed_object_marker: true, compiler_equality: true } : {}),
    ...(stagedPackageOption ? { canonical_options_hash: await secureHash(options),
      expected_checkpoint: options.expected_checkpoint, package_source: stagedPackage.proof,
      begin_predecessor: installSource, source_parts: stagedPackage.proof.parts.length,
      stage_markers_cleared: true, compiler_equality: true } : {}),
    ...(compositionOption ? { canonical_options_hash: await secureHash(options),
      source_digest: compositionMaterial.sourceDigest, composition: resolved.composition,
      explicit_dependency_count: options.dependencies.length, compiler_equality: true } : {}),
    ...(implicitOption ? { canonical_options_hash: await secureHash(options),
      source_digest: compositionMaterial.sourceDigest, composition: resolved.composition,
      explicit_dependency_count: 0, original_dependencies_omitted: true,
      authenticated_dependency_count: 1, compiler_equality: true } : {}),
    ...(normalizedOptions ? { canonical_options_hash: await secureHash(options),
      normalized_disclosure: resolved.disclose ?? null,
      normalized_grants: resolved.grants, original_grants_omitted: omittedGrants } : {}),
  }) + '\n');
  }
} finally {
  agent.close();
}
