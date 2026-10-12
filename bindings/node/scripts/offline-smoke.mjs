import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const installedRoot = process.argv[2];
if (!installedRoot) {
  console.error('usage: node offline-smoke.mjs INSTALLED_CONSUMER_DIR');
  process.exit(2);
}
const sdk = createRequire(import.meta.url)(resolve(installedRoot, 'node_modules', '@peerwork', 'agent-sdk'));
const capabilities = sdk.capabilities();
if (sdk.version() !== '0.0.1' || capabilities.version !== '0.0.1') {
  throw new Error('native core version/manifest mismatch');
}
console.log(JSON.stringify({ version: sdk.version(), capabilities }));
