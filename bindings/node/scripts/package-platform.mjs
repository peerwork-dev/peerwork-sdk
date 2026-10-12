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
const metadata = {
  name: `@peerwork/agent-sdk-${target}`,
  version: '0.0.1',
  description: 'Experimental native Peerwork SDK binary for one platform',
  license: 'Apache-2.0',
  repository: 'https://github.com/peerwork-dev/peerwork-sdk',
  os: [os],
  cpu: [cpu],
  files: ['index.node', 'index.cjs', 'LICENSE', 'README.md'],
  main: 'index.cjs',
};
if (libc) metadata.libc = [libc];
writeFileSync(join(dir, 'package.json'), `${JSON.stringify(metadata, null, 2)}\n`);
writeFileSync(join(dir, 'index.cjs'), "'use strict';\nmodule.exports = require('./index.node');\n");
writeFileSync(join(dir, 'README.md'), `# ${metadata.name}\n\nExperimental platform binary. No verified operations yet.\n`);
copyFileSync(resolve('LICENSE'), join(dir, 'LICENSE'));
console.log(`${metadata.name}: ${basename(library)} -> ${dir}`);
