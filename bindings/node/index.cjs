'use strict';

const { platform, arch } = process;
const { join } = require('node:path');
const { types: { isProxy } } = require('node:util');
function libcFamily() {
  if (platform !== 'linux') return '';
  const report = process.report?.getReport?.();
  if (!report?.header) {
    throw new Error('Cannot determine Linux libc for the Peerwork native module');
  }
  return report?.header?.glibcVersionRuntime ? '-gnu' : '-musl';
}
const target = platform === 'win32' ? `${platform}-${arch}-msvc` : `${platform}-${arch}${libcFamily()}`;
const supported = new Set([
  'linux-x64-gnu', 'linux-arm64-gnu', 'linux-x64-musl', 'linux-arm64-musl',
  'darwin-x64', 'darwin-arm64', 'win32-x64-msvc',
]);
if (!supported.has(target)) {
  throw new Error(`Unsupported Peerwork native target ${target}`);
}
const packageName = `@peerwork/agent-sdk-${target}`;
let modulePath;
try {
  modulePath = require.resolve(packageName);
} catch (error) {
  if (error?.code === 'MODULE_NOT_FOUND') {
    throw new Error(`Missing ${packageName} native package. Install optional dependencies for this target.`, { cause: error });
  }
  throw error;
}
const binding = require(modulePath);

exports.version = binding.version;
exports.capabilities = () => JSON.parse(binding.capabilitiesJson());
exports.createIdentity = async path => JSON.parse(await binding.identityCreateJson(path));
exports.openIdentity = async path => JSON.parse(await binding.identityOpenJson(path));
exports.importIdentitySeedFile = async (path, seedFile) => JSON.parse(await binding.identityImportSeedJson(path, seedFile));
exports.importLegacyIdentityPem = async (path, pemFile) => JSON.parse(await binding.identityImportPkcs8PemJson(path, pemFile));

function strictCommandJson(input) {
  const seen = new WeakSet();
  const visit = (value, depth) => {
    if (depth > 40) throw new TypeError('Command nesting exceeds limit');
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new TypeError('Command contains a non-finite number');
      return value;
    }
    if (typeof value !== 'object' || isProxy(value) || seen.has(value)) throw new TypeError('Command contains unsupported, proxied or cyclic data');
    seen.add(value);
    let snapshot;
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError('Command array has a custom prototype');
      const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
      if (!Number.isSafeInteger(length) || length < 0) throw new TypeError('Command array length is invalid');
      const keys = Reflect.ownKeys(value);
      if (keys.length !== length + 1) throw new TypeError('Command array has extra or missing members');
      snapshot = new Array(length);
      Object.setPrototypeOf(snapshot, null);
      for (let index = 0; index < length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !('value' in descriptor)) throw new TypeError('Command array has a hole or accessor');
        snapshot[index] = visit(descriptor.value, depth + 1);
      }
    } else {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Command contains a non-plain object');
      snapshot = Object.create(null);
      for (const key of Reflect.ownKeys(value)) {
        if (typeof key !== 'string') throw new TypeError('Command contains a symbol key');
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) throw new TypeError('Command contains an accessor or hidden member');
        snapshot[key] = visit(descriptor.value, depth + 1);
      }
    }
    seen.delete(value);
    return snapshot;
  };
  return JSON.stringify(visit(input, 0));
}

/** An explicit origin and protected local paths anchor every operation. */
exports.openKernel = async options => {
  const { origin, journalPath, identityPath, requiredFeatures = [], allowLoopbackHttp = false, authority, signal } = options;
  const call = async (operation, commandJson, commandId, uploadChunk, abortSignal,
                      migrationSource, migrationBackup, trustedSignerKeyIds) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (abortSignal?.aborted) onAbort();
    abortSignal?.addEventListener('abort', onAbort, { once: true });
    try {
      return JSON.parse(await binding.kernelJson(
        operation, origin, journalPath, identityPath, requiredFeatures,
        allowLoopbackHttp, authority, commandJson, commandId, uploadChunk, handle,
        migrationSource, migrationBackup, trustedSignerKeyIds,
      ));
    } finally {
      abortSignal?.removeEventListener('abort', onAbort);
    }
  };
  const info = await call('open', undefined, undefined, undefined, signal);
  return Object.freeze({
    ...info,
    prepare: (command, options = {}) => {
      const chunk = options.uploadChunk;
      if (chunk !== undefined && !(chunk instanceof Uint8Array)) throw new TypeError('uploadChunk must be Buffer or Uint8Array');
      return call('prepare', strictCommandJson(command), undefined, chunk === undefined ? undefined : Buffer.from(chunk), options.signal);
    },
    pending: (options = {}) => call('pending', undefined, undefined, undefined, options.signal),
    status: (commandId, options = {}) => call('status', undefined, commandId, undefined, options.signal),
    submitSaved: (commandId, options = {}) => call('submit_saved', undefined, commandId, undefined, options.signal),
    migrateTsStore: (sourcePath, backupPath, trustedSignerKeyIds, options = {}) => {
      if (typeof sourcePath !== 'string' || typeof backupPath !== 'string' ||
          !Array.isArray(trustedSignerKeyIds) || trustedSignerKeyIds.length === 0 ||
          !trustedSignerKeyIds.every(id => typeof id === 'string')) {
        throw new TypeError('migrateTsStore requires source, backup, and public signer key IDs');
      }
      return call('migrate_ts_store', undefined, undefined, undefined, options.signal,
                  sourcePath, backupPath, trustedSignerKeyIds);
    },
  });
};

/** Verify and read a supported active secure journal from protected state. */
exports.readSecureSnapshot = async options => {
  if (!options || isProxy(options) ||
      (Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null)) {
    throw new TypeError('secure read options must be a plain object');
  }
  const allowed = new Set([
    'origin', 'kernelJournalPath', 'readStatePath', 'lifecyclePath', 'identityPath',
    'workspaceId', 'authority', 'ownerActorId', 'ownerKeyId', 'requiredFeatures',
    'allowLoopbackHttp', 'maxReplayArtifactBytes', 'signal',
  ]);
  const input = Object.create(null);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError('unknown secure read option');
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw new TypeError('secure read options contain an accessor or hidden member');
    input[key] = descriptor.value;
  }
  for (const key of [
    'origin', 'kernelJournalPath', 'readStatePath', 'lifecyclePath', 'identityPath',
    'workspaceId', 'authority', 'ownerActorId', 'ownerKeyId',
  ]) {
    if (typeof input[key] !== 'string' || input[key].length === 0) throw new TypeError(`${key} is required`);
  }
  if (input.requiredFeatures !== undefined &&
      (!Array.isArray(input.requiredFeatures) || isProxy(input.requiredFeatures) ||
       !input.requiredFeatures.every(feature => typeof feature === 'string'))) {
    throw new TypeError('requiredFeatures must be an array of strings');
  }
  if (input.allowLoopbackHttp !== undefined && typeof input.allowLoopbackHttp !== 'boolean') {
    throw new TypeError('allowLoopbackHttp must be boolean');
  }
  const limit = input.maxReplayArtifactBytes ?? 64 * 1024 * 1024;
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new TypeError('maxReplayArtifactBytes must be a positive safe integer');
  const config = {
    origin: input.origin,
    kernel_journal_path: input.kernelJournalPath,
    read_state_path: input.readStatePath,
    lifecycle_path: input.lifecyclePath,
    identity_path: input.identityPath,
    workspace_id: input.workspaceId,
    authority: input.authority,
    owner_actor_id: input.ownerActorId,
    owner_key_id: input.ownerKeyId,
    required_features: input.requiredFeatures ?? [],
    allow_loopback_http: input.allowLoopbackHttp ?? false,
    max_replay_artifact_bytes: limit,
  };
  const handle = new binding.KernelCancelHandle();
  const signal = input.signal;
  const onAbort = () => handle.cancel();
  if (signal?.aborted) onAbort();
  signal?.addEventListener?.('abort', onAbort, { once: true });
  try {
    const result = JSON.parse(await binding.secureReadJson(strictCommandJson(config), handle));
    if (result.ok !== true) {
      const error = new Error(result.message);
      error.code = result.code;
      throw error;
    }
    return result.value;
  } finally {
    signal?.removeEventListener?.('abort', onAbort);
  }
};

function secureProfileOptions(options) {
  if (!options || isProxy(options) ||
      (Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null)) {
    throw new TypeError('secure read options must be a plain object');
  }
  const allowed = new Set([
    'origin', 'stateDir', 'identityPath', 'workspaceId', 'authority',
    'ownerActorId', 'ownerKeyId', 'requiredFeatures', 'allowLoopbackHttp',
    'maxReplayArtifactBytes', 'signal',
  ]);
  const input = Object.create(null);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError('unknown secure read option');
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw new TypeError('secure read options contain an accessor or hidden member');
    input[key] = descriptor.value;
  }
  for (const key of ['origin', 'stateDir', 'identityPath', 'workspaceId']) {
    if (typeof input[key] !== 'string' || input[key].length === 0) throw new TypeError(`${key} is required`);
  }
  for (const key of ['authority', 'ownerActorId', 'ownerKeyId']) {
    if (input[key] !== undefined && (typeof input[key] !== 'string' || input[key].length === 0)) {
      throw new TypeError(`${key} must be a nonempty string`);
    }
  }
  if ((input.ownerActorId === undefined) !== (input.ownerKeyId === undefined)) {
    throw new TypeError('owner actor and key pins must be supplied together');
  }
  if (input.requiredFeatures !== undefined &&
      (!Array.isArray(input.requiredFeatures) || isProxy(input.requiredFeatures) ||
       !input.requiredFeatures.every(feature => typeof feature === 'string'))) {
    throw new TypeError('requiredFeatures must be an array of strings');
  }
  if (input.allowLoopbackHttp !== undefined && typeof input.allowLoopbackHttp !== 'boolean') {
    throw new TypeError('allowLoopbackHttp must be boolean');
  }
  const limit = input.maxReplayArtifactBytes ?? 64 * 1024 * 1024;
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new TypeError('maxReplayArtifactBytes must be a positive safe integer');
  const config = {
    origin: input.origin,
    state_dir: input.stateDir,
    identity_path: input.identityPath,
    workspace_id: input.workspaceId,
    owner_actor_id: input.ownerActorId ?? null,
    owner_key_id: input.ownerKeyId ?? null,
    authority: input.authority ?? null,
    required_features: input.requiredFeatures ?? [],
    allow_loopback_http: input.allowLoopbackHttp ?? false,
    max_replay_artifact_bytes: limit,
  };
  return { config, signal: input.signal };
}

/** Fetch a fresh verified checkpoint using one protected state directory. */
exports.readSecureWorkspace = async options => {
  const { config, signal } = secureProfileOptions(options);
  const handle = new binding.KernelCancelHandle();
  const onAbort = () => handle.cancel();
  if (signal?.aborted) onAbort();
  signal?.addEventListener?.('abort', onAbort, { once: true });
  try {
    const result = JSON.parse(await binding.secureReadProfileJson(strictCommandJson(config), handle));
    if (result.ok !== true) {
      const error = new Error(result.message);
      error.code = result.code;
      throw error;
    }
    return result.value;
  } finally {
    signal?.removeEventListener?.('abort', onAbort);
  }
};

/** Read verified PRIVATE state, recovering a protected direct grant when needed. */
exports.readSecurePrivateWorkspace = async options => {
  const { config, signal } = secureProfileOptions(options);
  const handle = new binding.KernelCancelHandle();
  const onAbort = () => handle.cancel();
  if (signal?.aborted) onAbort();
  signal?.addEventListener?.('abort', onAbort, { once: true });
  try {
    const result = JSON.parse(await binding.securePrivateReadJson(strictCommandJson(config), handle));
    if (result.ok !== true) {
      const error = new Error(result.message);
      error.code = result.code;
      throw error;
    }
    return result.value;
  } finally {
    signal?.removeEventListener?.('abort', onAbort);
  }
};

/** Prepare PUBLIC actions and reconcile exact saved commands against signed replay. */
exports.openSecurePublicActions = options => {
  const { config } = secureProfileOptions(options);
  const invoke = async (operation, input, commandId, signal) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.securePublicActionJson(
        operation, strictCommandJson(config), input === undefined ? undefined : strictCommandJson(input),
        commandId, handle,
      ));
      if (result.ok !== true) {
        const error = new Error(result.message);
        error.code = result.code;
        throw error;
      }
      const value = result.value;
      if (operation === 'pending') return value;
      const receipt = value.receipt_canonical_json === null ? null : JSON.parse(value.receipt_canonical_json);
      delete value.receipt_canonical_json;
      return { ...value, receipt };
    } finally {
      signal?.removeEventListener?.('abort', onAbort);
    }
  };
  return Object.freeze({
    submit: (actionId, instanceId, body, options = {}) => {
      if (typeof actionId !== 'string' || typeof instanceId !== 'string') throw new TypeError('action and instance IDs are required');
      const input = {
        action_id: actionId,
        instance_id: instanceId,
        body_json: strictCommandJson(body),
        exact_input_refs_json: options.exactInputRefs === undefined ? null : strictCommandJson(options.exactInputRefs),
        allocations_json: options.allocations === undefined ? null : strictCommandJson(options.allocations),
        command_id: options.commandId ?? null,
        issued_at_ms: options.issuedAtMs ?? null,
      };
      return invoke('submit', input, undefined, options.signal);
    },
    reconcile: (commandId, options = {}) => invoke('reconcile', undefined, commandId, options.signal),
    retrySaved: (commandId, options = {}) => invoke('retry', undefined, commandId, options.signal),
    pending: (options = {}) => invoke('pending', undefined, undefined, options.signal),
  });
};

/** Prepare, reconcile and read Owner-created workspaces from one protected root. */
exports.openSecureOwnerWorkspaces = options => {
  if (!options || typeof options.origin !== 'string' || !options.origin ||
      typeof options.stateDir !== 'string' || !options.stateDir) {
    throw new TypeError('Owner workspaces require origin and stateDir');
  }
  const config = {
    origin: options.origin,
    state_dir: options.stateDir,
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    max_replay_artifact_bytes: options.maxReplayArtifactBytes ?? 64 * 1024 * 1024,
  };
  const invoke = async (operation, input, commandId, workspaceId, signal) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.secureOwnerCreateJson(
        operation, strictCommandJson(config), input === undefined ? undefined : strictCommandJson(input),
        commandId, workspaceId, handle,
      ));
      if (result.ok !== true) {
        const error = new Error(result.message);
        error.code = result.code;
        throw error;
      }
      return result.value;
    } finally {
      signal?.removeEventListener?.('abort', onAbort);
    }
  };
  const createInput = input => {
    if (!input || typeof input.name !== 'string' || typeof input.visibility !== 'string') {
      throw new TypeError('Owner name and visibility are required');
    }
    const hasSurrogate = /[\uD800-\uDFFF]/u.test(input.name);
    const nameUtf16 = hasSurrogate
      ? Array.from({ length: input.name.length }, (_, index) => input.name.charCodeAt(index))
      : null;
    return {
      name: hasSurrogate ? '' : input.name, name_utf16: nameUtf16,
      visibility: input.visibility,
      structured: input.structured ?? false,
      keep_encrypted_json: strictCommandJson(input.keepEncrypted ?? []),
      coordination_version: input.coordinationVersion ?? null,
    };
  };
  const attachmentInput = input => {
    if (!input || typeof input !== 'object' ||
        ['workspaceId', 'protectedTsStatePath', 'protectedTsIntentDbPath',
          'protectedOwnerPkcs8Path', 'expectedOwnerActorId', 'expectedOwnerKeyId']
          .some(key => typeof input[key] !== 'string' || !input[key])) {
      throw new TypeError('attachment requires workspace, protected source paths and exact Owner actor/key pins');
    }
    return {
      workspace_id: input.workspaceId,
      protected_ts_state_path: input.protectedTsStatePath,
      protected_ts_intent_db_path: input.protectedTsIntentDbPath,
      protected_owner_pkcs8_path: input.protectedOwnerPkcs8Path,
      expected_owner_actor_id: input.expectedOwnerActorId,
      expected_owner_key_id: input.expectedOwnerKeyId,
    };
  };
  const formatTransitionInput = input => {
    if (!input || typeof input.workspaceId !== 'string' || !input.workspaceId ||
        !['UPGRADE_WIRE_V3', 'RAISE_PRIVATE_CEILING_TWO'].includes(input.transition)) {
      throw new TypeError('format transition requires workspace ID and supported transition');
    }
    return {
      workspace_id: input.workspaceId, transition: input.transition,
      command_id: input.commandId ?? null, issued_at_ms: input.issuedAtMs ?? null,
    };
  };
  const consumer = (kind, workspaceId) => {
    if (typeof workspaceId !== 'string' || !workspaceId) throw new TypeError('workspace ID is required');
    const call = async (operation, input, commandId, signal) => {
      const handle = new binding.KernelCancelHandle();
      const onAbort = () => handle.cancel();
      if (signal?.aborted) onAbort();
      signal?.addEventListener?.('abort', onAbort, { once: true });
      try {
        const result = JSON.parse(await binding.secureOwnerConsumerJson(kind, operation,
          strictCommandJson(config), workspaceId,
          input === undefined ? undefined : strictCommandJson(input), commandId, handle));
        if (result.ok !== true) {
          const error = new Error(result.message);
          error.code = result.code;
          throw error;
        }
        const value = result.value;
        if (kind === 'public_install' || kind === 'private_stage' || kind === 'private_install' || kind === 'public_admission' || kind === 'private_admission' || operation === 'pending') return value;
        const receipt = value.receipt_canonical_json === null ? null : JSON.parse(value.receipt_canonical_json);
        delete value.receipt_canonical_json;
        return { ...value, receipt };
      } finally {
        signal?.removeEventListener?.('abort', onAbort);
      }
    };
    if (kind === 'public_install') return Object.freeze({
      begin: (selection, options = {}) => {
        if (selection === null || typeof selection !== 'object' ||
            typeof selection.closureJson !== 'string' || typeof selection.grantsJson !== 'string') {
          throw new TypeError('install selection requires exact closureJson and grantsJson text');
        }
        return call('begin', {
          closure_json: selection.closureJson,
          expected_package_id: selection.expectedPackageId,
          expected_package_version: selection.expectedPackageVersion,
          expected_package_digest: selection.expectedPackageDigest,
          expected_protocol_digest: selection.expectedProtocolDigest,
          instance_id: selection.instanceId, entrypoint: selection.entrypoint,
          grants_json: selection.grantsJson,
          command_id: options.commandId ?? null, issued_at_ms: options.issuedAtMs ?? null,
        }, undefined, options.signal);
      },
      continueInstall: (beginCommandId, options = {}) => call('continue', undefined, beginCommandId, options.signal),
      pending: (options = {}) => call('pending', undefined, undefined, options.signal),
    });
    if (kind === 'private_stage') return Object.freeze({
      stage: (materialJson, expectedRootPackageDigest, expectedProtocolDigest, options = {}) => {
        if (typeof materialJson !== 'string' || typeof expectedRootPackageDigest !== 'string' ||
            typeof expectedProtocolDigest !== 'string') {
          throw new TypeError('PRIVATE stage requires materialJson and exact root/protocol digests');
        }
        return call('stage', {
          material_json: materialJson,
          expected_root_package_digest: expectedRootPackageDigest,
          expected_protocol_digest: expectedProtocolDigest,
          stage_id: options.stageId ?? null,
          command_id: options.commandId ?? null,
          issued_at_ms: options.issuedAtMs ?? null,
        }, undefined, options.signal);
      },
      continueStage: (stageId, options = {}) => call('continue', undefined, stageId, options.signal),
      stages: (options = {}) => call('stages', undefined, undefined, options.signal),
    });
    if (kind === 'private_install') return Object.freeze({
      begin: (selection, options = {}) => {
        if (selection === null || typeof selection !== 'object' ||
            typeof selection.stageId !== 'string' || typeof selection.instanceId !== 'string' ||
            typeof selection.entrypoint !== 'string' || typeof selection.grantsJson !== 'string') {
          throw new TypeError('PRIVATE install requires staged ID, instance, entrypoint and grantsJson');
        }
        return call('begin', {
          stage_id: selection.stageId,
          instance_id: selection.instanceId,
          entrypoint: selection.entrypoint,
          grants_json: selection.grantsJson,
          command_id: options.commandId ?? null,
          issued_at_ms: options.issuedAtMs ?? null,
        }, undefined, options.signal);
      },
      beginDirect: (selection, options = {}) => {
        if (selection === null || typeof selection !== 'object' ||
            typeof selection.closureJson !== 'string' ||
            typeof selection.expectedRootPackageDigest !== 'string' ||
            typeof selection.expectedProtocolDigest !== 'string' ||
            typeof selection.instanceId !== 'string' ||
            typeof selection.entrypoint !== 'string' || typeof selection.grantsJson !== 'string') {
          throw new TypeError('PRIVATE direct install requires material, exact digests, instance, entrypoint and grantsJson');
        }
        return call('begin_direct', {
          closure_json: selection.closureJson,
          expected_root_package_digest: selection.expectedRootPackageDigest,
          expected_protocol_digest: selection.expectedProtocolDigest,
          instance_id: selection.instanceId,
          entrypoint: selection.entrypoint,
          grants_json: selection.grantsJson,
          command_id: options.commandId ?? null,
          issued_at_ms: options.issuedAtMs ?? null,
        }, undefined, options.signal);
      },
      continueInstall: (beginCommandId, options = {}) => call('continue', undefined, beginCommandId, options.signal),
      installs: (options = {}) => call('installs', undefined, undefined, options.signal),
    });
    if (kind === 'public_admission' || kind === 'private_admission') return Object.freeze({
      offer: (recipientCertificateJson, scopes, options = {}) => {
        const message = options.message ?? '';
        if (typeof message !== 'string') throw new TypeError('offer message must be a string');
        const messageUtf16 = Array.from({ length: message.length }, (_, index) => message.charCodeAt(index));
        return call('offer', {
          recipient_certificate_json: recipientCertificateJson,
          scopes_json: strictCommandJson(scopes),
          message: '', message_utf16: messageUtf16,
          invite_id: options.inviteId ?? null,
          issued_at_ms: options.issuedAtMs ?? null,
          expires_at_ms: options.expiresAtMs ?? null,
        }, undefined, options.signal);
      },
      retryOffer: (inviteId, options = {}) => call('retry_offer', undefined, inviteId, options.signal),
      pendingOffers: (options = {}) => call('pending_offers', undefined, undefined, options.signal),
      deliver: (inviteId, options = {}) => call('deliver', undefined, inviteId, options.signal),
      retryDelivery: (grantId, options = {}) => call('retry_delivery', undefined, grantId, options.signal),
      pendingDeliveries: (options = {}) => call('pending_deliveries', undefined, undefined, options.signal),
    });
    return Object.freeze({
      submit: (actionId, instanceId, body, options = {}) => call('submit', {
        action_id: actionId, instance_id: instanceId, body_json: strictCommandJson(body),
        exact_input_refs_json: options.exactInputRefs === undefined ? null : strictCommandJson(options.exactInputRefs),
        allocations_json: options.allocations === undefined ? null : strictCommandJson(options.allocations),
        command_id: options.commandId ?? null, issued_at_ms: options.issuedAtMs ?? null,
      }, undefined, options.signal),
      reconcile: (commandId, options = {}) => call('reconcile', undefined, commandId, options.signal),
      retrySaved: (commandId, options = {}) => call('retry', undefined, commandId, options.signal),
      pending: (options = {}) => call('pending', undefined, undefined, options.signal),
    });
  };
  return Object.freeze({
    prepare: (input, { signal } = {}) => invoke('prepare', createInput(input), undefined, undefined, signal),
    create: (input, { signal } = {}) => invoke('create', createInput(input), undefined, undefined, signal),
    resume: (commandId, { signal } = {}) => invoke('resume', undefined, commandId, undefined, signal),
    operations: ({ signal } = {}) => invoke('operations', undefined, undefined, undefined, signal),
    attach: (input, { signal } = {}) => invoke('attach', attachmentInput(input), undefined, undefined, signal),
    resumeAttachment: (attachId, { signal } = {}) => invoke('resume_attachment', undefined, attachId, undefined, signal),
    attachments: ({ signal } = {}) => invoke('attachments', undefined, undefined, undefined, signal),
    submitFormatTransition: (input, { signal } = {}) => invoke('format_submit', formatTransitionInput(input), undefined, undefined, signal),
    resumeFormatTransition: (commandId, { signal } = {}) => invoke('format_resume', undefined, commandId, undefined, signal),
    formatTransitions: ({ signal } = {}) => invoke('format_history', undefined, undefined, undefined, signal),
    read: (workspaceId, { signal } = {}) => invoke('read', undefined, undefined, workspaceId, signal),
    publicActions: workspaceId => consumer('public_action', workspaceId),
    privateActions: workspaceId => consumer('private_action', workspaceId),
    publicInstaller: workspaceId => consumer('public_install', workspaceId),
    privatePackageStager: workspaceId => consumer('private_stage', workspaceId),
    privatePackageInstaller: workspaceId => consumer('private_install', workspaceId),
    publicAdmission: workspaceId => consumer('public_admission', workspaceId),
    privateAdmission: workspaceId => consumer('private_admission', workspaceId),
  });
};

/** Anonymous catalog metadata is advisory; exact digest inspection checks bytes, not publisher trust. */
exports.openPublicCatalog = options => {
  if (!options || typeof options.origin !== 'string' || !options.origin) {
    throw new TypeError('catalog origin is required');
  }
  const config = {
    origin: options.origin,
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    max_listing_bytes: options.maxListingBytes ?? null,
  };
  const call = async (operation, query, after, limit, digest, signal) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.publicCatalogJson(
        operation, strictCommandJson(config), query, after, limit, digest, handle,
      ));
      if (result.ok !== true) {
        const error = new Error(result.message);
        error.code = result.code;
        throw error;
      }
      const value = result.value;
      if (operation === 'search') value.listing = JSON.parse(value.listing_canonical_json);
      else {
        value.summary = JSON.parse(value.summary_canonical_json);
        value.bundle = JSON.parse(value.bundle_canonical_json);
      }
      return value;
    } finally {
      signal?.removeEventListener?.('abort', onAbort);
    }
  };
  return Object.freeze({
    search: (query, options = {}) => call('search', query, options.after, options.limit ?? 20, undefined, options.signal),
    inspectExact: (digest, options = {}) => call('inspect', undefined, undefined, undefined, digest, options.signal),
  });
};

/** Create protected recipient keys and explicitly publish their signed directory entry. */
exports.openSecureRecipientEnrollment = options => {
  if (!options || typeof options.origin !== 'string' || typeof options.stateDir !== 'string') {
    throw new TypeError('recipient enrollment requires origin and stateDir');
  }
  const invoke = async (operation, signal, mode, expectedCertificateHash, updateId) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.secureRecipientEnrollmentJson(
        operation, options.origin, options.stateDir,
        options.allowLoopbackHttp ?? false, handle, mode, expectedCertificateHash, updateId,
      ));
      if (result.ok !== true) {
        const error = new Error(result.message);
        error.code = result.code;
        throw error;
      }
      return result.value;
    } finally {
      signal?.removeEventListener?.('abort', onAbort);
    }
  };
  return Object.freeze({
    createLocal: () => invoke('create_local'),
    publish: (options = {}) => invoke('publish', options.signal),
    pending: () => invoke('pending'),
    certificateJson: () => invoke('certificate'),
    updateKey: (mode, expectedCertificateHash, options = {}) => invoke('update_key', options.signal,
      mode, expectedCertificateHash, options.updateId),
    retryKeyUpdate: (updateId, options = {}) => invoke('retry_key_update', options.signal,
      undefined, undefined, updateId),
    pendingKeyUpdates: () => invoke('pending_key_updates'),
    keyUpdates: () => invoke('key_updates'),
  });
};

/** Signed public identity lookup with explicit peer actor/key pins and protected continuity. */
exports.openSecureIdentityDirectory = options => {
  if (!options || typeof options.origin !== 'string' || !options.origin ||
      typeof options.stateDir !== 'string' || !options.stateDir) {
    throw new TypeError('identity directory requires origin and stateDir');
  }
  const identityPath = options.identityPath ?? join(options.stateDir, 'identity.state');
  if (typeof identityPath !== 'string' || !identityPath) throw new TypeError('identityPath must be a path');
  return Object.freeze({
    lookup: async (actorId, signingKeyId, { signal } = {}) => {
      if (typeof actorId !== 'string' || !actorId || typeof signingKeyId !== 'string' || !signingKeyId) {
        throw new TypeError('explicit peer actor and signing key pins are required');
      }
      const handle = new binding.KernelCancelHandle();
      const onAbort = () => handle.cancel();
      if (signal?.aborted) onAbort();
      signal?.addEventListener?.('abort', onAbort, { once: true });
      try {
        const result = JSON.parse(await binding.secureIdentityDirectoryJson(
          options.origin, options.stateDir, identityPath, actorId, signingKeyId,
          options.allowLoopbackHttp ?? false, handle,
        ));
        if (result.ok !== true) {
          const error = new Error(result.message);
          error.code = result.code;
          throw error;
        }
        return result.value;
      } finally {
        signal?.removeEventListener?.('abort', onAbort);
      }
    },
  });
};

const admissionCall = (role, config) => async (operation, input, inviteId, grantId, decision, signal) => {
  const handle = new binding.KernelCancelHandle();
  const onAbort = () => handle.cancel();
  if (signal?.aborted) onAbort();
  signal?.addEventListener?.('abort', onAbort, { once: true });
  try {
    const result = JSON.parse(await binding.securePublicAdmissionJson(
      role, operation, strictCommandJson(config),
      input === undefined ? undefined : strictCommandJson(input),
      inviteId, grantId, decision, handle,
    ));
    if (result.ok !== true) {
      const error = new Error(result.message);
      error.code = result.code;
      throw error;
    }
    return result.value;
  } finally {
    signal?.removeEventListener?.('abort', onAbort);
  }
};

/** Owner-signed PUBLIC offer and delivery from the protected latest profile. */
exports.openSecurePublicAdmission = options => {
  const { config } = secureProfileOptions(options);
  const call = admissionCall('owner', config);
  return Object.freeze({
    offer: (recipientCertificateJson, scopes, options = {}) => {
      const message = options.message ?? '';
      if (typeof message !== 'string') throw new TypeError('offer message must be a string');
      const messageUtf16 = Array.from({ length: message.length }, (_, index) => message.charCodeAt(index));
      return call('offer', {
      recipient_certificate_json: recipientCertificateJson,
      scopes_json: strictCommandJson(scopes),
      message: '', message_utf16: messageUtf16,
      invite_id: options.inviteId ?? null,
      issued_at_ms: options.issuedAtMs ?? null,
      expires_at_ms: options.expiresAtMs ?? null,
      }, undefined, undefined, undefined, options.signal);
    },
    retryOffer: (inviteId, options = {}) => call('retry_offer', undefined, inviteId, undefined, undefined, options.signal),
    pendingOffers: () => call('pending_offers'),
    deliver: (inviteId, options = {}) => call('deliver', undefined, inviteId, undefined, undefined, options.signal),
    retryDelivery: (grantId, options = {}) => call('retry_delivery', undefined, undefined, grantId, undefined, options.signal),
    pendingDeliveries: () => call('pending_deliveries'),
  });
};

/** Recipient consent/receipt with explicit owner and authority pins. */
exports.openSecureInvitation = options => {
  if (!options || typeof options.origin !== 'string' || typeof options.stateDir !== 'string' ||
      typeof options.workspaceId !== 'string' || typeof options.ownerActorId !== 'string' ||
      typeof options.ownerKeyId !== 'string' ||
      (options.authority !== undefined && (typeof options.authority !== 'string' || options.authority.length === 0))) {
    throw new TypeError('recipient decision requires origin, stateDir, workspaceId and owner pins');
  }
  const config = {
    origin: options.origin, state_dir: options.stateDir,
    identity_path: require('node:path').join(options.stateDir, 'identity.state'),
    workspace_id: options.workspaceId, owner_actor_id: options.ownerActorId,
    owner_key_id: options.ownerKeyId, authority: options.authority ?? '',
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    required_features: options.requiredFeatures ?? [],
    max_replay_artifact_bytes: options.maxReplayArtifactBytes ?? 64 * 1024 * 1024,
  };
  const call = admissionCall('recipient', config);
  return Object.freeze({
    decide: (inviteId, decision, options = {}) => call('decide', undefined, inviteId, undefined, decision, options.signal),
    retryDecision: (inviteId, options = {}) => call('retry_decision', undefined, inviteId, undefined, undefined, options.signal),
    pendingDecisions: () => call('pending_decisions'),
    receive: (inviteId, options = {}) => call('receive', undefined, inviteId, undefined, undefined, options.signal),
    retryReceive: (inviteId, options = {}) => call('retry_receive', undefined, inviteId, undefined, undefined, options.signal),
    pendingReceipts: () => call('pending_receipts'),
  });
};

/** Begin and continue a PUBLIC direct install through protected local state. */
exports.openSecurePublicPackageInstaller = options => {
  const { config } = secureProfileOptions(options);
  const invoke = async (operation, input, beginCommandId, signal) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.securePublicInstallJson(
        operation, strictCommandJson(config), input === undefined ? undefined : strictCommandJson(input),
        beginCommandId, handle,
      ));
      if (result.ok !== true) {
        const error = new Error(result.message);
        error.code = result.code;
        throw error;
      }
      return result.value;
    } finally {
      signal?.removeEventListener?.('abort', onAbort);
    }
  };
  return Object.freeze({
    begin: (selection, options = {}) => {
      if (selection === null || typeof selection !== 'object' ||
          typeof selection.closureJson !== 'string' || typeof selection.grantsJson !== 'string') {
        throw new TypeError('install selection requires exact closureJson and grantsJson text');
      }
      const input = {
        closure_json: selection.closureJson,
        expected_package_id: selection.expectedPackageId,
        expected_package_version: selection.expectedPackageVersion,
        expected_package_digest: selection.expectedPackageDigest,
        expected_protocol_digest: selection.expectedProtocolDigest,
        instance_id: selection.instanceId,
        entrypoint: selection.entrypoint,
        grants_json: selection.grantsJson,
        command_id: options.commandId ?? null,
        issued_at_ms: options.issuedAtMs ?? null,
      };
      return invoke('begin', input, undefined, options.signal);
    },
    continueInstall: (beginCommandId, options = {}) => invoke('continue', undefined, beginCommandId, options.signal),
    pending: (options = {}) => invoke('pending', undefined, undefined, options.signal),
  });
};
