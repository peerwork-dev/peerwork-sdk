'use strict';

const { platform, arch } = process;
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
