'use strict';

const { platform, arch } = process;
function libcFamily() {
  if (platform !== 'linux') return '';
  const report = process.report?.getReport?.();
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
let binding;
try {
  binding = require(`@peerwork/agent-sdk-${target}`);
} catch (error) {
  if (error?.code === 'MODULE_NOT_FOUND') {
    throw new Error(`Missing @peerwork/agent-sdk-${target} native package. Install optional dependencies for this target.`, { cause: error });
  }
  throw error;
}

exports.version = binding.version;
exports.capabilities = () => JSON.parse(binding.capabilitiesJson());
