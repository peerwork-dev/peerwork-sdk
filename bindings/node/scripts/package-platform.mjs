import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const [target, library, output = 'dist'] = process.argv.slice(2);
const targets = new Map([
  ['linux-x64-gnu', ['linux', 'x64', 'glibc']],
  ['linux-arm64-gnu', ['linux', 'arm64', 'glibc']],
  ['linux-x64-musl', ['linux', 'x64', 'musl']],
  ['linux-arm64-musl', ['linux', 'arm64', 'musl']],
  ['darwin-x64', ['darwin', 'x64']],
  ['darwin-arm64', ['darwin', 'arm64']],
  ['win32-x64-msvc', ['win32', 'x64']],
]);
if (!targets.has(target) || !library) {
  console.error('usage: node package-platform.mjs TARGET BUILT_LIBRARY [OUTPUT_DIR]');
  process.exit(2);
}
const [os, cpu, libc] = targets.get(target);
const dir = resolve(output, `agent-sdk-${target}`);
mkdirSync(dir, { recursive: true });
copyFileSync(resolve(library), join(dir, 'index.node'));
if (libc === 'musl') {
  const runtimeDir = process.env.PEERWORK_MUSL_CXX_LIB_DIR;
  if (!runtimeDir) {
    throw new Error('PEERWORK_MUSL_CXX_LIB_DIR is required to bundle the musl C++ runtime');
  }
  const bundled = ['libc++.so.1', 'libc++abi.so.1', 'libunwind.so.1'];
  const needed = execFileSync('patchelf', ['--print-needed', join(dir, 'index.node')], { encoding: 'utf8' }).trim().split('\n');
  for (const name of bundled) {
    if (!needed.includes(name)) throw new Error(`Expected ${name} in musl addon dependencies`);
  }
  if (needed.some(name => name.startsWith('libstdc++') || name.startsWith('libgcc_s'))) {
    throw new Error('Musl addon unexpectedly depends on the GNU C++ runtime');
  }
  const bundledDir = join(dir, 'lib');
  mkdirSync(bundledDir, { recursive: true });
  for (const name of bundled) {
    const file = join(bundledDir, name);
    copyFileSync(join(runtimeDir, name), file);
    execFileSync('patchelf', ['--set-rpath', '$ORIGIN', file]);
  }
  execFileSync('patchelf', ['--set-rpath', '$ORIGIN/lib', join(dir, 'index.node')]);
  copyFileSync(new URL('../../../third_party/llvm-20.1.8-LICENSE.txt', import.meta.url), join(dir, 'LLVM-LICENSE.txt'));
}
const metadata = {
  name: `@peerwork/agent-sdk-${target}`,
  version: '0.0.1',
  description: 'Experimental native Peerwork SDK binary for one platform',
  license: 'Apache-2.0',
  repository: 'https://github.com/peerwork-dev/peerwork-sdk',
  os: [os],
  cpu: [cpu],
  files: ['index.node', 'index.cjs', 'lib/', 'LICENSE', 'README.md', ...(libc === 'musl' ? ['LLVM-LICENSE.txt'] : [])],
  main: 'index.cjs',
};
if (libc) metadata.libc = [libc];
writeFileSync(join(dir, 'package.json'), `${JSON.stringify(metadata, null, 2)}\n`);
writeFileSync(join(dir, 'index.cjs'), "'use strict';\nmodule.exports = require('./index.node');\n");
writeFileSync(join(dir, 'README.md'), `# ${metadata.name}\n\nExperimental platform binary. No verified operations yet.\n`);
copyFileSync(new URL('../LICENSE', import.meta.url), join(dir, 'LICENSE'));
console.log(`${metadata.name}: ${basename(library)} -> ${dir}`);
