import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const installedRoot = process.argv[2];
if (!installedRoot) {
  console.error('usage: node offline-smoke.mjs INSTALLED_CONSUMER_DIR');
  process.exit(2);
}
const sdk = createRequire(import.meta.url)(resolve(installedRoot, 'node_modules', '@peerwork', 'agent-sdk'));
const capabilities = sdk.capabilities();
const metadata = JSON.parse(readFileSync(resolve(installedRoot, 'node_modules', '@peerwork', 'agent-sdk', 'package.json'), 'utf8'));
if (sdk.version() !== metadata.version || capabilities.version !== metadata.version) {
  throw new Error('native core version/manifest mismatch');
}
if (typeof sdk.protocols !== 'function' || !capabilities.owner_protocol_bundle_binding || typeof sdk.delivery !== 'function' || !capabilities.agent_delivery || typeof sdk.protocolSession !== 'function' || typeof sdk.ProtocolSessionError !== 'function') {
  throw new Error('protocol session facade missing from installed package');
}
console.log(JSON.stringify({ version: sdk.version(), capabilities }));
