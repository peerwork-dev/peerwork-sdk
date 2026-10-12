'use strict';

const { platform, arch } = process;
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
