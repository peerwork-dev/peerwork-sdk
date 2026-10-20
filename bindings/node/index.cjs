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

exports.loadConfig = async path => {
  const result = JSON.parse(await binding.loadConfigJson(path));
  if (result.ok !== true) { const error = new Error(result.message); error.code = result.code; throw error; }
  const config = { origin: result.value.origin, stateDir: result.value.state_dir };
  if (Object.hasOwn(result.value, 'transport')) {
    config.transport = {
      requestTimeoutMs: result.value.transport.request_timeout_ms,
      additionalRootPemFiles: result.value.transport.additional_root_pem_files,
    };
  }
  return config;
};
exports.version = binding.version;
exports.capabilities = () => JSON.parse(binding.capabilitiesJson());
exports.createIdentity = async path => JSON.parse(await binding.identityCreateJson(path));
exports.openIdentity = async path => {
  try {
    return JSON.parse(await binding.identityOpenJson(path));
  } catch (error) {
    const code = typeof error.message === 'string' && error.message.match(/^(IDENTITY_MISSING|IDENTITY_STATE): /)?.[1];
    if (code) error.code = code;
    throw error;
  }
};
exports.importIdentitySeedFile = async (path, seedFile) => JSON.parse(await binding.identityImportSeedJson(path, seedFile));
exports.importLegacyIdentityPem = async (path, pemFile) => JSON.parse(await binding.identityImportPkcs8PemJson(path, pemFile));
/** Import a legacy Owner PEM into identity.state under the supplied Owner config. */
exports.importLegacyOwnerIdentity = async (configFile, pemFile) => JSON.parse(await binding.identityImportOwnerPemJson(configFile, pemFile));

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

function transportJsonValue(value) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value) || isProxy(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new TypeError('transport must be a plain object');
  }
  const allowed = new Set(['requestTimeoutMs', 'additionalRootPemFiles']);
  const input = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new TypeError('unknown transport option');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) throw new TypeError('transport options contain an accessor or hidden member');
    input[key] = descriptor.value;
  }
  const timeout = Object.hasOwn(input, 'requestTimeoutMs') ? input.requestTimeoutMs : 15000;
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw new TypeError('requestTimeoutMs must be a positive safe integer');
  const roots = Object.hasOwn(input, 'additionalRootPemFiles') ? input.additionalRootPemFiles : [];
  if (!Array.isArray(roots) || isProxy(roots) || roots.length > 16) {
    throw new TypeError('additionalRootPemFiles must contain at most 16 nonempty paths');
  }
  const copiedRoots = JSON.parse(strictCommandJson(roots));
  if (copiedRoots.some(path => typeof path !== 'string' || path.length === 0)) {
    throw new TypeError('additionalRootPemFiles must contain at most 16 nonempty paths');
  }
  return { request_timeout_ms: timeout, additional_root_pem_files: copiedRoots };
}

function withTransport(config, transport) {
  const value = transportJsonValue(transport);
  if (value !== undefined) config.transport = value;
  return config;
}

function selectedBindingsJson(selection) {
  if (!Object.hasOwn(selection, 'bindings')) return null;
  const bindings = selection.bindings;
  if (bindings === null || typeof bindings !== 'object' || Array.isArray(bindings)) {
    throw new TypeError('bindings must be a JSON object');
  }
  return strictCommandJson(bindings);
}

function selectedDisclosure(selection) {
  if (!Object.hasOwn(selection, 'disclose')) return null;
  if (!Array.isArray(selection.disclose)) {
    throw new TypeError('disclose must be an array of schema/fields selections');
  }
  return selection.disclose;
}

class KernelError extends Error {
  constructor(code, message) { super(message); this.name = 'KernelError'; this.code = code; }
}
exports.KernelError = KernelError;

/** An explicit origin and protected local paths anchor every operation. */
exports.openKernel = async options => {
  const { origin, journalPath, identityPath, requiredFeatures = [], allowLoopbackHttp = false, authority, signal, transport } = options;
  const transportJson = transport === undefined ? undefined : strictCommandJson(transportJsonValue(transport));
  const call = async (operation, commandJson, commandId, uploadChunk, abortSignal,
                      migrationSource, migrationBackup, trustedSignerKeyIds) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (abortSignal?.aborted) onAbort();
    abortSignal?.addEventListener('abort', onAbort, { once: true });
    try {
      const value = JSON.parse(await binding.kernelJson(
        operation, origin, journalPath, identityPath, requiredFeatures,
        allowLoopbackHttp, authority, commandJson, commandId, uploadChunk, handle,
        migrationSource, migrationBackup, trustedSignerKeyIds, transportJson,
      ));
      if (value?.ok === false) throw new KernelError(value.code, value.message);
      return value;
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
    'allowLoopbackHttp', 'maxReplayArtifactBytes', 'maxReplayCommits', 'transport', 'signal',
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
  const maxReplayCommits = input.maxReplayCommits ?? 102400;
  if (!Number.isSafeInteger(maxReplayCommits) || maxReplayCommits <= 0) throw new TypeError('maxReplayCommits must be a positive safe integer');
  const config = withTransport({
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
    max_replay_commits: maxReplayCommits,
  }, input.transport);
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
    'maxReplayArtifactBytes', 'maxReplayCommits', 'transport', 'signal',
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
  const maxReplayCommits = input.maxReplayCommits ?? 102400;
  if (!Number.isSafeInteger(maxReplayCommits) || maxReplayCommits <= 0) throw new TypeError('maxReplayCommits must be a positive safe integer');
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
    max_replay_commits: maxReplayCommits,
  };
  withTransport(config, input.transport);
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
const openSecureActions = (options, privateMode) => {
  const { config } = secureProfileOptions(options);
  const invoke = async (operation, input, commandId, signal, operationId) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const args = [operation, strictCommandJson(config), input === undefined ? undefined : strictCommandJson(input), commandId];
      const result = JSON.parse(await (privateMode
        ? binding.securePrivateActionJson(...args, operationId, handle)
        : binding.securePublicActionJson(...args, handle)));
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
      if (privateMode && options.operationId != null && (typeof options.operationId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(options.operationId))) throw new TypeError('operationId must be a 43-character token');
      return invoke('submit', input, undefined, options.signal, options.operationId);
    },
    reconcile: (commandId, options = {}) => invoke('reconcile', undefined, commandId, options.signal),
    retrySaved: (commandId, options = {}) => invoke('retry', undefined, commandId, options.signal),
    pending: (options = {}) => invoke('pending', undefined, undefined, options.signal),
  });
};

/** Uses the selected member profile, current PRIVATE keyring and policy scopes. */
exports.openSecurePrivateActions = options => openSecureActions(options, true);
exports.openSecurePublicActions = options => openSecureActions(options, false);

/** Prepare, reconcile and read Owner-created workspaces from one protected root. */
exports.openSecureOwnerWorkspaces = options => {
  if (!options || typeof options.origin !== 'string' || !options.origin ||
      typeof options.stateDir !== 'string' || !options.stateDir) {
    throw new TypeError('Owner workspaces require origin and stateDir');
  }
  const config = withTransport({
    origin: options.origin,
    state_dir: options.stateDir,
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    max_replay_artifact_bytes: options.maxReplayArtifactBytes ?? 64 * 1024 * 1024,
    max_replay_commits: checkedMaxReplayCommits(options.maxReplayCommits),
  }, options.transport);
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
  const coordinationInput = input => {
    if (!input || typeof input !== 'object' || Array.isArray(input) ||
        Object.keys(input).some(key => key !== 'version' && key !== 'participants')) {
      throw new TypeError('coordination input permits only version and participants');
    }
    if (input.version != null && input.version !== 1 && input.version !== 2) {
      throw new TypeError('coordination version must be 1 or 2');
    }
    if (input.participants != null && (!Array.isArray(input.participants) ||
        input.participants.some(actor => typeof actor !== 'string' || !actor))) {
      throw new TypeError('participants must be an array of nonempty actor IDs');
    }
    return { version: input.version ?? null, participants: input.participants ?? null };
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
    if (input.recoverPendingAction !== undefined && typeof input.recoverPendingAction !== 'boolean') {
      throw new TypeError('recoverPendingAction must be a boolean');
    }
    if (input.retainPendingActionCommandId !== undefined && input.retainPendingActionCommandId !== null &&
        (typeof input.retainPendingActionCommandId !== 'string' || !input.retainPendingActionCommandId)) {
      throw new TypeError('retainPendingActionCommandId must be a nonempty string');
    }
    if (input.retainPendingActionCommandId && input.recoverPendingAction !== true) {
      throw new TypeError('retaining a pending Owner action requires recoverPendingAction');
    }
    const kernelIds = input.kernelPendingCommandIds ?? [];
    if (!Array.isArray(kernelIds) || kernelIds.some(id => typeof id !== 'string' || !id)) {
      throw new TypeError('kernelPendingCommandIds must be an array of nonempty strings');
    }
    if (kernelIds.length &&
        (typeof input.expectedKernelIntentDbDigest !== 'string' || !input.expectedKernelIntentDbDigest)) {
      throw new TypeError('selected kernel commands require the inspected intent DB digest');
    }
    if (input.expectedKernelIntentDbDigest !== undefined && input.expectedKernelIntentDbDigest !== null &&
        typeof input.expectedKernelIntentDbDigest !== 'string') {
      throw new TypeError('expectedKernelIntentDbDigest must be a string');
    }
    const stageId = input.selectedPendingPackageStageCommandId;
    const orphanId = input.selectedOrphanPackageStageCommandId;
    const stateDigest = input.expectedTsStateDigest;
    if (stageId != null && orphanId != null) {
      throw new TypeError('select one pending or orphan package stage');
    }
    const selectedStageId = stageId ?? orphanId;
    if ((selectedStageId == null) !== (stateDigest == null)) {
      throw new TypeError('selected package stage requires the inspected TS state digest');
    }
    if (selectedStageId != null &&
        (typeof selectedStageId !== 'string' || !selectedStageId || typeof stateDigest !== 'string' || !stateDigest)) {
      throw new TypeError('selected package stage ID and TS state digest must be nonempty strings');
    }
    return {
      workspace_id: input.workspaceId,
      protected_ts_state_path: input.protectedTsStatePath,
      protected_ts_intent_db_path: input.protectedTsIntentDbPath,
      protected_owner_pkcs8_path: input.protectedOwnerPkcs8Path,
      expected_owner_actor_id: input.expectedOwnerActorId,
      expected_owner_key_id: input.expectedOwnerKeyId,
      recover_pending_action: input.recoverPendingAction ?? false,
      retain_pending_action_command_id: input.retainPendingActionCommandId ?? null,
      kernel_pending_command_ids: kernelIds,
      expected_kernel_intent_db_digest: input.expectedKernelIntentDbDigest ?? null,
      selected_pending_package_stage_command_id: stageId ?? null,
      selected_orphan_package_stage_command_id: orphanId ?? null,
      expected_ts_state_digest: stateDigest ?? null,
    };
  };
  const multipartStageRequest = (input, materialJson, selection) => {
    const allowed = new Set([
      'workspaceId', 'protectedTsStatePath', 'protectedTsIntentDbPath',
      'protectedOwnerPkcs8Path', 'expectedOwnerActorId', 'expectedOwnerKeyId',
      'recoverPendingAction', 'retainPendingActionCommandId',
      'kernelPendingCommandIds', 'expectedKernelIntentDbDigest',
      'selectedPendingPackageStageCommandId', 'selectedOrphanPackageStageCommandId',
      'expectedTsStateDigest',
    ]);
    if (!input || typeof input !== 'object' || Object.keys(input).some(key => !allowed.has(key)) ||
        typeof materialJson !== 'string' || !materialJson) {
      throw new TypeError('multipart stage requires exact attachment fields and nonempty materialJson');
    }
    const selectedId = selection === 'pending' ? input.selectedPendingPackageStageCommandId :
      selection === 'orphan' ? input.selectedOrphanPackageStageCommandId : null;
    const conflictingId = selection === 'pending' ? input.selectedOrphanPackageStageCommandId :
      input.selectedPendingPackageStageCommandId;
    if (selection == null ? input.selectedPendingPackageStageCommandId != null ||
        input.selectedOrphanPackageStageCommandId != null || input.expectedTsStateDigest != null :
        !selectedId || conflictingId != null || !input.expectedTsStateDigest) {
      throw new TypeError('multipart stage requires the selected command and inspected TS state digest');
    }
    return { attachment_input: attachmentInput(input), material_json: materialJson };
  };
  const directBeginRequest = (input, selectedCommandId, expectedDigest, optionsJson, materialJson, attach) => {
    const allowed = new Set([
      'workspaceId', 'protectedTsStatePath', 'protectedTsIntentDbPath',
      'protectedOwnerPkcs8Path', 'expectedOwnerActorId', 'expectedOwnerKeyId',
      'recoverPendingAction', 'retainPendingActionCommandId',
      'kernelPendingCommandIds', 'expectedKernelIntentDbDigest',
      'selectedPendingPackageStageCommandId', 'selectedOrphanPackageStageCommandId',
      'expectedTsStateDigest',
    ]);
    if (!input || typeof input !== 'object' || Object.keys(input).some(key => !allowed.has(key)) ||
        typeof selectedCommandId !== 'string' || !selectedCommandId ||
        typeof optionsJson !== 'string' || !optionsJson ||
        typeof materialJson !== 'string' || !materialJson ||
        (attach ? typeof expectedDigest !== 'string' || !expectedDigest : expectedDigest != null)) {
      throw new TypeError('direct install requires exact source, selected ID, options, material and inspected digest for attach');
    }
    const source = attachmentInput(input);
    if (source.recover_pending_action || source.retain_pending_action_command_id != null ||
        source.kernel_pending_command_ids.length || source.selected_pending_package_stage_command_id != null ||
        source.selected_orphan_package_stage_command_id != null || source.expected_ts_state_digest != null) {
      throw new TypeError('direct install selection cannot be combined with other attachment recovery');
    }
    return { attachment_input: source, selected_command_id: selectedCommandId,
      expected_ts_state_digest: expectedDigest ?? null, options_json: optionsJson,
      material_json: materialJson };
  };
  const markerHash = value => {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError('markerHash must be an inspected SHA256, not a command ID');
    return value;
  };
  const markerIntentRequest = (input, hash, digest, options, material, attach) => {
    const { selected_command_id, ...value } = directBeginRequest(input, markerHash(hash), digest, options, material, attach);
    return { ...value, selected_marker_hash: selected_command_id };
  };
  const completedDirectRequest = (input, selectedInstanceId, expectedDigest, optionsJson, materialJson, attach) => {
    const { selected_command_id, ...value } = directBeginRequest(input, selectedInstanceId,
      expectedDigest, optionsJson, materialJson, attach);
    return { ...value, selected_instance_id: selected_command_id };
  };
  const formatTransitionInput = input => {
    if (!input || typeof input.workspaceId !== 'string' || !input.workspaceId ||
        !['UPGRADE_WIRE_V3', 'RAISE_PRIVATE_CEILING_TWO'].includes(input.transition)) {
      throw new TypeError('format transition requires workspace ID and supported transition');
    }
    const allowed = new Set(['workspaceId', 'transition', 'commandId', 'issuedAtMs']);
    if (Object.keys(input).some(key => !allowed.has(key)) ||
        (input.commandId != null && (typeof input.commandId !== 'string' || !input.commandId)) ||
        (input.issuedAtMs != null && (!Number.isSafeInteger(input.issuedAtMs) || input.issuedAtMs < 0))) {
      throw new TypeError('invalid format transition option');
    }
    return {
      workspace_id: input.workspaceId, transition: input.transition,
      command_id: input.commandId ?? null, issued_at_ms: input.issuedAtMs ?? null,
    };
  };
  const consumer = (kind, workspaceId) => {
    if (typeof workspaceId !== 'string' || !workspaceId) throw new TypeError('workspace ID is required');
    const call = async (operation, input, commandId, signal, operationId) => {
      const handle = new binding.KernelCancelHandle();
      const onAbort = () => handle.cancel();
      if (signal?.aborted) onAbort();
      signal?.addEventListener?.('abort', onAbort, { once: true });
      try {
        const result = JSON.parse(await binding.secureOwnerConsumerJson(kind, operation,
          strictCommandJson(config), workspaceId,
          input === undefined ? undefined : strictCommandJson(input), commandId, handle, operationId));
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
        if (Object.hasOwn(selection, 'disclose')) {
          throw new TypeError('PUBLIC install does not accept private field disclosure');
        }
        return call('begin', {
          closure_json: selection.closureJson,
          expected_package_id: selection.expectedPackageId,
          expected_package_version: selection.expectedPackageVersion,
          expected_package_digest: selection.expectedPackageDigest,
          expected_protocol_digest: selection.expectedProtocolDigest,
          instance_id: selection.instanceId, entrypoint: selection.entrypoint,
          grants_json: selection.grantsJson,
          bindings_json: selectedBindingsJson(selection),
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
          disclose: selectedDisclosure(selection),
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
          bindings_json: selectedBindingsJson(selection),
          expected_root_package_digest: selection.expectedRootPackageDigest,
          expected_protocol_digest: selection.expectedProtocolDigest,
          instance_id: selection.instanceId,
          entrypoint: selection.entrypoint,
          grants_json: selection.grantsJson,
          disclose: selectedDisclosure(selection),
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
      submit: (actionId, instanceId, body, options = {}) => {
        if (options.operationId != null && (kind !== 'private_action' || typeof options.operationId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(options.operationId))) {
          throw new TypeError('operationId is a stable 43-character ID available only for guarded PRIVATE actions');
        }
        return call('submit', {
        action_id: actionId, instance_id: instanceId, body_json: strictCommandJson(body),
        exact_input_refs_json: options.exactInputRefs === undefined ? null : strictCommandJson(options.exactInputRefs),
        allocations_json: options.allocations === undefined ? null : strictCommandJson(options.allocations),
        command_id: options.commandId ?? null, issued_at_ms: options.issuedAtMs ?? null,
        }, undefined, options.signal, options.operationId);
      },
      reconcile: (commandId, options = {}) => call('reconcile', undefined, commandId, options.signal),
      retrySaved: (commandId, options = {}) => call('retry', undefined, commandId, options.signal),
      pending: (options = {}) => call('pending', undefined, undefined, options.signal),
    });
  };
  const inspectDirectPacket = (input, selectedCommandId, optionsJson, materialJson, { signal } = {}) => invoke(
    'direct_begin_inspect', directBeginRequest(input, selectedCommandId, null, optionsJson, materialJson, false), undefined, undefined, signal);
  const attachDirectPacket = (input, selectedCommandId, expectedTsStateDigest, optionsJson, materialJson, { signal } = {}) => invoke(
    'direct_begin_attach', directBeginRequest(input, selectedCommandId, expectedTsStateDigest, optionsJson, materialJson, true), undefined, undefined, signal);
  const recoverDirectPacket = (attachId, expectedCommandId, { signal } = {}) => invoke(
    'direct_begin_recover', undefined, expectedCommandId, attachId, signal);
  return Object.freeze({
    prepare: (input, { signal } = {}) => invoke('prepare', createInput(input), undefined, undefined, signal),
    create: (input, { signal } = {}) => invoke('create', createInput(input), undefined, undefined, signal),
    resume: (commandId, { signal } = {}) => invoke('resume', undefined, commandId, undefined, signal),
    operations: ({ signal } = {}) => invoke('operations', undefined, undefined, undefined, signal),
    guardTime: workspaceId => new OwnerWorkspaceGuardTimeClient(config, workspaceId),
    enableCoordination: (workspaceId, input = {}, { signal } = {}) => invoke(
      'coordination_enable', coordinationInput(input), undefined, workspaceId, signal),
    resumeCoordination: (workspaceId, beginCommandId, { signal } = {}) => invoke(
      'coordination_resume', undefined, beginCommandId, workspaceId, signal),
    coordinationOperations: (workspaceId, { signal } = {}) => invoke(
      'coordination_operations', undefined, undefined, workspaceId, signal),
    attach: (input, { signal } = {}) => invoke('attach', attachmentInput(input), undefined, undefined, signal),
    inspectKernelPending: (input, { signal } = {}) => invoke('kernel_inspect', attachmentInput(input), undefined, undefined, signal),
    inspectPendingPackageStage: (input, { signal } = {}) => invoke('stage_inspect', attachmentInput(input), undefined, undefined, signal),
    inspectPendingMultipartPackageStage: (input, materialJson, { signal } = {}) => invoke(
      'stage_multipart_inspect', multipartStageRequest(input, materialJson, null), undefined, undefined, signal),
    attachPendingMultipartPackageStage: (input, materialJson, { signal } = {}) => invoke(
      'stage_multipart_attach', multipartStageRequest(input, materialJson, 'pending'), undefined, undefined, signal),
    recoverPendingPackageStage: (attachId, expectedCommandId, { signal } = {}) => invoke('stage_recover', undefined, expectedCommandId, attachId, signal),
    objectStageIntentCandidates: (input, { signal } = {}) => invoke(
      'object_intent_candidates', attachmentInput(input), undefined, undefined, signal),
    inspectObjectStageIntent: (input, hash, optionsJson, materialJson, { signal } = {}) => invoke(
      'object_intent_inspect', markerIntentRequest(input, hash, null, optionsJson, materialJson, false), undefined, undefined, signal),
    attachObjectStageIntent: (input, hash, expectedTsStateDigest, optionsJson, materialJson, { signal } = {}) => invoke(
      'object_intent_attach', markerIntentRequest(input, hash, expectedTsStateDigest, optionsJson, materialJson, true), undefined, undefined, signal),
    recoverObjectStageIntent: (attachId, hash, { signal } = {}) => invoke(
      'object_intent_recover', undefined, markerHash(hash), attachId, signal),
    inspectPendingObjectStage: (input, selectedCommandId, optionsJson, materialJson, { signal } = {}) => invoke(
      'object_stage_inspect', directBeginRequest(input, selectedCommandId, null, optionsJson, materialJson, false), undefined, undefined, signal),
    attachPendingObjectStage: (input, selectedCommandId, expectedTsStateDigest, optionsJson, materialJson, { signal } = {}) => invoke(
      'object_stage_attach', directBeginRequest(input, selectedCommandId, expectedTsStateDigest, optionsJson, materialJson, true), undefined, undefined, signal),
    recoverPendingObjectStage: (attachId, expectedCommandId, { signal } = {}) => invoke(
      'object_stage_recover', undefined, expectedCommandId, attachId, signal),
    inspectPendingDirectInstallBegin: inspectDirectPacket,
    attachPendingDirectInstallBegin: attachDirectPacket,
    recoverPendingDirectInstallBegin: recoverDirectPacket,
    inspectPendingDirectInstallPacket: inspectDirectPacket,
    attachPendingDirectInstallPacket: attachDirectPacket,
    recoverPendingDirectInstallPacket: recoverDirectPacket,
    inspectCompletedDirectInstall: (input, selectedInstanceId, optionsJson, materialJson, { signal } = {}) => invoke(
      'direct_completed_inspect', completedDirectRequest(input, selectedInstanceId, null, optionsJson, materialJson, false), undefined, undefined, signal),
    attachCompletedDirectInstall: (input, selectedInstanceId, expectedTsStateDigest, optionsJson, materialJson, { signal } = {}) => invoke(
      'direct_completed_attach', completedDirectRequest(input, selectedInstanceId, expectedTsStateDigest, optionsJson, materialJson, true), undefined, undefined, signal),
    inspectOrphanPackageStage: (input, { signal } = {}) => invoke('orphan_inspect', attachmentInput(input), undefined, undefined, signal),
    inspectMultipartOrphanPackageStage: (input, materialJson, { signal } = {}) => invoke(
      'orphan_multipart_inspect', multipartStageRequest(input, materialJson, null), undefined, undefined, signal),
    attachMultipartOrphanPackageStage: (input, materialJson, { signal } = {}) => invoke(
      'orphan_multipart_attach', multipartStageRequest(input, materialJson, 'orphan'), undefined, undefined, signal),
    replanOrphanPackageStage: (attachId, originalCommandId, materialJson, { signal } = {}) => {
      if (materialJson != null && (typeof materialJson !== 'string' || !materialJson)) {
        throw new TypeError('materialJson must be a nonempty JSON string when supplied');
      }
      return invoke('orphan_replan', materialJson ?? undefined, originalCommandId, attachId, signal);
    },
    kernelCommandStatus: (attachId, { signal } = {}) => invoke('kernel_status', undefined, attachId, undefined, signal),
    recoverKernelCommand: (attachId, commandId, { signal } = {}) => invoke('kernel_recover', undefined, commandId, attachId, signal),
    resumeAttachment: (attachId, { signal } = {}) => invoke('resume_attachment', undefined, attachId, undefined, signal),
    retainPendingAction: (attachId, expectedCommandId, { signal } = {}) => invoke('retain_pending_action', undefined, expectedCommandId, attachId, signal),
    retireCoordinationIntent: (attachId, markerKey, expectedInputHash, { signal } = {}) => invoke('coordination_marker_retire', { attach_id: attachId, marker_key: markerKey, expected_input_hash: expectedInputHash }, undefined, undefined, signal),
    attachments: ({ signal } = {}) => invoke('attachments', undefined, undefined, undefined, signal),
    submitFormatTransition: (input, { signal } = {}) => invoke('format_submit', formatTransitionInput(input), undefined, undefined, signal),
    resumeFormatTransition: (workspaceId, commandId, { signal } = {}) => invoke('format_resume', undefined, commandId, workspaceId, signal),
    formatTransitions: (workspaceId, { signal } = {}) => invoke('format_history', undefined, undefined, workspaceId, signal),
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

function checkedMaxReplayCommits(value) {
  const limit = value ?? 102400;
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new TypeError('maxReplayCommits must be a positive safe integer');
  return limit;
}

/** Anonymous catalog metadata is advisory; exact digest inspection checks bytes, not publisher trust. */
exports.openPublicCatalog = options => {
  if (!options || typeof options.origin !== 'string' || !options.origin) {
    throw new TypeError('catalog origin is required');
  }
  const config = withTransport({
    origin: options.origin,
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    max_listing_bytes: options.maxListingBytes ?? null,
  }, options.transport);
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
  const transportJson = options.transport === undefined ? undefined : strictCommandJson(transportJsonValue(options.transport));
  const invoke = async (operation, signal, mode, expectedCertificateHash, updateId) => {
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (signal?.aborted) onAbort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.secureRecipientEnrollmentJson(
        operation, options.origin, options.stateDir,
        options.allowLoopbackHttp ?? false, handle, mode, expectedCertificateHash, updateId, transportJson,
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
  const transportJson = options.transport === undefined ? undefined : strictCommandJson(transportJsonValue(options.transport));
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
          options.allowLoopbackHttp ?? false, handle, transportJson,
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
  const config = withTransport({
    origin: options.origin, state_dir: options.stateDir,
    identity_path: require('node:path').join(options.stateDir, 'identity.state'),
    workspace_id: options.workspaceId, owner_actor_id: options.ownerActorId,
    owner_key_id: options.ownerKeyId, authority: options.authority ?? '',
    allow_loopback_http: options.allowLoopbackHttp ?? false,
    required_features: options.requiredFeatures ?? [],
    max_replay_artifact_bytes: options.maxReplayArtifactBytes ?? 64 * 1024 * 1024,
    max_replay_commits: checkedMaxReplayCommits(options.maxReplayCommits),
  }, options.transport);
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
      if (Object.hasOwn(selection, 'disclose')) {
        throw new TypeError('PUBLIC install does not accept private field disclosure');
      }
      const input = {
        closure_json: selection.closureJson,
        bindings_json: selectedBindingsJson(selection),
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

/** Explicit local observations. No implicit observer, upload or business calls. */
exports.openAcquisitionObservations = options => {
  if (!options || typeof options.path !== 'string') throw new TypeError('observation path is required');
  const config = strictCommandJson({path: options.path, max_records: options.maxRecords ?? null,
    max_store_bytes: options.maxStoreBytes ?? null});
  const call = async (operation, input) => {
    const result = JSON.parse(await binding.acquisitionObservationsJson(operation, config,
      input === undefined ? null : strictCommandJson(input)));
    if (result.ok !== true) { const error = new Error(result.message); error.code = result.code; throw error; }
    return result.value;
  };
  return Object.freeze({
    attestExternalPrincipal: attestation => call('attest_external_principal', attestation),
    attestations: () => call('attestations'),
    append: event => call('append', event),
    export: () => call('export'),
    snapshots: () => call('snapshots'),
    scorecard: window => call('scorecard', window),
    recordCatalogResult: (event, result) => call('catalog_result', {event,
      catalog_origin: result.catalog_origin, bundle_digest: result.bundle_digest,
      bundle_canonical_json: result.bundle_canonical_json}),
    recordInstallResult: input => call('install_result', input),
    recordActionResult: (event, selectedInstanceId, resultInstanceId, result) => call('action_result', {
      event, selected_instance_id: selectedInstanceId, result_instance_id: resultInstanceId,
      result_status: result.status, result_command_id: result.command_id,
      result_commit_hash: result.commit_hash ?? null, result_sequence: result.sequence ?? null,
    }),
  });
};


class AgentContextError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'AgentContextError';
    this.envelope = envelope;
    this.operation_id = envelope.operation_id;
    this.code = envelope.code;
    this.layer = envelope.layer;
    this.effect_certainty = envelope.effect_certainty;
    this.continuation = envelope.continuation;
  }
}
exports.AgentContextError = AgentContextError;
/** Open existing protected member context offline; every call rechecks pins. */
exports.openContext = async ({ profilePath, expectedActor, expectedService, signal }) => {
  for (const [name, value] of Object.entries({ profilePath, expectedActor, expectedService })) {
    if (typeof value !== 'string' || !value) throw new TypeError(`${name} is required`);
  }
  let expectedFingerprint;
  const call = async (operation, request, abortSignal) => {
    const wire = request === undefined ? undefined : strictCommandJson({
      ...request, expected_fingerprint: expectedFingerprint,
    });
    const handle = new binding.KernelCancelHandle();
    const onAbort = () => handle.cancel();
    if (abortSignal?.aborted) onAbort();
    abortSignal?.addEventListener('abort', onAbort, { once: true });
    try {
      const result = JSON.parse(await binding.agentContextJson(
        operation, profilePath, expectedActor, expectedService, wire, handle));
      if (result.ok !== true) throw new AgentContextError(result);
      return result.value;
    } finally {
      abortSignal?.removeEventListener('abort', onAbort);
    }
  };
  const opened = await call('open', undefined, signal);
  expectedFingerprint = opened.context.fingerprint;
  const descriptorJson = JSON.stringify(opened.context);
  return Object.freeze({
    get descriptor() { return JSON.parse(descriptorJson); },
    discover: (workspaceId, options = {}) => {
      const query = {};
      if (options.after !== undefined) query.after = options.after;
      if (options.limit !== undefined) query.limit = options.limit;
      return call('discover', { workspace_id: workspaceId, query }, options.signal);
    },
    describe: (workspaceId, options) => {
      const query = {};
      if (options.instanceId !== undefined) query.instance_id = options.instanceId;
      if (options.actionId !== undefined) query.action_id = options.actionId;
      if (options.recordId !== undefined) query.record_id = options.recordId;
      if (options.revision !== undefined) query.revision = options.revision;
      if (options.objectRef !== undefined) query.object_ref = options.objectRef;
      return call('describe', { workspace_id: workspaceId, query }, options.signal);
    },
    inspect: (workspaceId, options = {}) => call('inspect', { workspace_id: workspaceId }, options.signal),
    operate: (workspaceId, intent, operationId, options = {}) => call('operate', {
      workspace_id: workspaceId, intent, operation_id: operationId,
    }, options.signal),
    recover: (workspaceId, options = {}) => {
      const request = { workspace_id: workspaceId };
      if (options.operationId !== undefined) request.operation_id = options.operationId;
      if (options.commandId !== undefined) request.command_id = options.commandId;
      return call('recover', request, options.signal);
    },
    operations: (workspaceId, options = {}) => call('operations', { workspace_id: workspaceId }, options.signal),
    eventsSync: (workspaceId, options = {}) => call('events.sync', { workspace_id: workspaceId }, options.signal),
    eventsReceive: (workspaceId, consumerId, options = {}) => {
      const request = { workspace_id: workspaceId, consumer_id: consumerId };
      if (options.filterVersion !== undefined) request.filter_version = options.filterVersion;
      request.lease_ms = options.leaseMs ?? 30000;
      request.wait_ms = options.waitMs ?? 0;
      return call('events.receive', request, options.signal);
    },
    eventsAck: (workspaceId, consumerId, ackToken, options = {}) => {
      const request = { workspace_id: workspaceId, consumer_id: consumerId, ack_token: ackToken };
      if (options.filterVersion !== undefined) request.filter_version = options.filterVersion;
      return call('events.ack', request, options.signal);
    },
    eventsStatus: (workspaceId, options = {}) => call('events.status', { workspace_id: workspaceId }, options.signal),
  });
};

/** Explicit no-overwrite binding of existing protected profiles; creates no identity. */
exports.bindContext = async ({profilePath, expectedActor, expectedService, workspaceProfiles, signal}) => {
  const handle = new binding.KernelCancelHandle();
  const onAbort = () => handle.cancel();
  if (signal?.aborted) onAbort();
  signal?.addEventListener('abort', onAbort, {once: true});
  try {
    const result = JSON.parse(await binding.agentContextJson('bind', profilePath, expectedActor,
      expectedService, strictCommandJson({workspace_profiles: workspaceProfiles}), handle));
    if (result.ok !== true) throw new AgentContextError(result);
    return await exports.openContext({profilePath, expectedActor, expectedService, signal});
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
};


async function navigation(operation, input, signal) {
  const cancel = new binding.KernelCancelHandle();
  const abort = () => cancel.cancel();
  if (signal?.aborted) abort();
  signal?.addEventListener('abort', abort, {once:true});
  try {
    const result = JSON.parse(await binding.navigationJson(operation, strictCommandJson(input), cancel));
    if (result.ok !== true) { const error = new Error(result.message); error.code = result.code; throw error; }
    return result.value;
  } finally { signal?.removeEventListener('abort', abort); }
}
class WorkspaceUrls {
  constructor({browserOrigin='https://peerwork.dev',controlOrigin='https://api.peerwork.dev',allowLoopbackHttp=false}={}) {
    this._origins={browser_origin:browserOrigin,control_origin:controlOrigin,allow_loopback_http:allowLoopbackHttp};
  }
  build(workspaceId,{visibility='PRIVATE',kind='workspace',instanceId=null,recordId=null,entityId=null}={}) {
    return navigation('url',{...this._origins,workspace_id:workspaceId,visibility,kind,instance_id:instanceId,record_id:recordId,entity_id:entityId});
  }
  async workspace(workspaceId,options={}) { return (await this.build(workspaceId,options)).browser_url; }
  async instance(workspaceId,instanceId,options={}) { return (await this.build(workspaceId,{...options,kind:'instance',instanceId})).browser_url; }
  async record(workspaceId,recordId,options={}) { return (await this.build(workspaceId,{...options,kind:'record',recordId})).browser_url; }
}
class ChangelogClient {
  constructor({source}={}) { this.source=source ? JSON.parse(strictCommandJson(source)) : null; }
  static async officialSource() { return (await navigation('changelog.source',{})).source; }
  async read({limit=20,offset=0,checkpoint=null,signal}={}) {
    const source=this.source ?? await ChangelogClient.officialSource();
    return navigation('changelog.read',{source,limit,offset,checkpoint},signal);
  }
}
exports.WorkspaceUrls=WorkspaceUrls;
exports.ChangelogClient=ChangelogClient;


class ReadViewError extends Error {
  constructor(result) { super(result.message); this.name='ReadViewError'; this.code=result.code; }
}
class PublicReadViewClient {
  constructor({origin,workspaceId,ownerActorId,ownerKeyId,audience,serviceKey,
               acceptAuthorizedState,transport,allowLoopbackHttp=false}) {
    this._source=JSON.parse(strictCommandJson({origin,workspace_id:workspaceId,
      owner_actor_id:ownerActorId,owner_key_id:ownerKeyId,audience,service_key:serviceKey,
      accept_authorized_state:acceptAuthorizedState,allow_loopback_http:allowLoopbackHttp,
      ...(transport ? {transport:transportJsonValue(transport)} : {})}));
  }
  async _read(selection,{floor=null,signal}={}) {
    const cancel=new binding.KernelCancelHandle(),abort=()=>cancel.cancel();
    if(signal?.aborted)abort();
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const result=JSON.parse(await binding.readViewJson(strictCommandJson({...this._source,selection,floor}),cancel));
      if(result.ok!==true)throw new ReadViewError(result);
      return result.value;
    } finally { signal?.removeEventListener('abort',abort); }
  }
  get(kind,id,options={}) { return this._read({kind:'get',object_kind:kind,id},options); }
  list(instanceId,schema,{limit=20,cursor=null,...options}={}) {
    return this._read({kind:'list',instance_id:instanceId,schema,limit,cursor},options);
  }
}
exports.PublicReadViewClient=PublicReadViewClient;
exports.ReadViewError=ReadViewError;


class PrivateReadViewClient {
  constructor(options) {
    const {acceptAuthorizedState,...profileOptions}=JSON.parse(strictCommandJson(options));
    const {config}=secureProfileOptions(profileOptions);
    this._profile=JSON.parse(strictCommandJson(config));
    this._acceptAuthorizedState=acceptAuthorizedState;
  }
  async _read(selection,{floor=null,signal}={}) {
    const cancel=new binding.KernelCancelHandle(),abort=()=>cancel.cancel();
    if(signal?.aborted)abort();
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const result=JSON.parse(await binding.privateReadViewJson(strictCommandJson({profile:this._profile,
        accept_authorized_state:this._acceptAuthorizedState,selection,floor}),cancel));
      if(result.ok!==true)throw new ReadViewError(result);
      return result.value;
    } finally {signal?.removeEventListener('abort',abort);}
  }
  get(kind,id,options={}) {return this._read({kind:'get',object_kind:kind,id},options);}
  list(instanceId,schema,{limit=20,cursor=null,...options}={}) {
    return this._read({kind:'list',instance_id:instanceId,schema,limit,cursor},options);
  }
}
exports.PrivateReadViewClient=PrivateReadViewClient;


/** Bounded system structure selection with original-author verification and local decryption. */
class CurrentPageClient {
  constructor(options) {
    const {config}=secureProfileOptions(options);
    this._profile=JSON.parse(strictCommandJson(config));
  }
  async _read(query,{floor=null,signal}={}) {
    const cancel=new binding.KernelCancelHandle(),abort=()=>cancel.cancel();
    if(signal?.aborted)abort();
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const result=JSON.parse(await binding.currentPageJson(strictCommandJson({profile:this._profile,query,floor}),cancel));
      if(result.ok!==true)throw new ReadViewError(result);
      return result.value;
    } finally {signal?.removeEventListener('abort',abort);}
  }
  get(kind,id,options={}) {return this._read({kind:'get',object_kind:kind,id},options);}
  instances({limit=20,cursor=null,...options}={}) {
    return this._read({kind:'instances',limit,...(cursor===null?{}:{cursor})},options);
  }
  records(instanceId,schema,{limit=20,cursor=null,...options}={}) {
    return this._read({kind:'records',instance_id:instanceId,...(schema==null?{}:{schema}),
      limit,...(cursor===null?{}:{cursor})},options);
  }
  list(instanceId,schema,options={}) {return this.records(instanceId,schema,options);}
}
exports.CurrentPageClient=CurrentPageClient;
exports.openCurrentPages=(options)=>new CurrentPageClient(options);


/** Explicit Owner guard-time consent and exact durable recovery; no content-key input. */
class OwnerWorkspaceGuardTimeClient {
  constructor(config, workspaceId) {
    this._config=JSON.parse(strictCommandJson(config));
    this._workspaceId=workspaceId;
  }
  async _call(operation,input,{signal}={}) {
    const cancel=new binding.KernelCancelHandle(),abort=()=>cancel.cancel();
    if(signal?.aborted)abort();
    signal?.addEventListener('abort',abort,{once:true});
    try {
      const result=JSON.parse(await binding.ownerGuardTimeJson(strictCommandJson(this._config),
        operation,strictCommandJson({workspace_id:this._workspaceId,...input}),cancel));
      if(result.ok!==true){const error=new Error(result.message);error.code=result.code;throw error;}
      return result.value;
    } finally {signal?.removeEventListener('abort',abort);}
  }
  enable(input,options={}) {
    const allowed=['expectedPolicyHash','audience','serviceKey','disclosure','operationId'];
    if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(key=>!allowed.includes(key)))throw new TypeError('Guard-time activation requires explicit policy hash, service pins and GUARD_WINDOW consent');
    return this._call('enable',{expected_policy_hash:input.expectedPolicyHash,audience:input.audience,
      service_key:input.serviceKey,disclosure:input.disclosure,
      ...(input.operationId===undefined?{}:{operation_id:input.operationId})},options);
  }
  resume(operationId,options={}) {return this._call('resume',{operation_id:operationId},options);}
  history(options={}) {return this._call('history',{},options);}
}
exports.OwnerWorkspaceGuardTimeClient=OwnerWorkspaceGuardTimeClient;
