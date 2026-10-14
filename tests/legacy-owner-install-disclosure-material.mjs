// Author a distinct supported format-two package before any installation.
// Reuses the accepted private-package-options reference author/preview flow.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function createLegacyReadableInstallMaterial(referenceRoot) {
  const load = name => import(pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href);
  const { manifestCanonical, SEMANTICS } = await load('workspace-manifest');
  const { previewProtocolPackage } = await load('protocol-compiler');
  const { parseProtocolPackage, PROTOCOL_COMPILER_VERSION, PROTOCOL_LOCK_FORMAT,
    PROTOCOL_METADATA_FORMAT, PROTOCOL_PACKAGE_FORMAT, PROTOCOL_SOURCE_FORMAT } = await load('protocol-package');
  const { createProtocolPackageClosure } = await load('protocol-package-closure');
  const manifest = manifestCanonical({ name: 'example.native-retained-disclosure.v1', display_version: '1',
    semantics: SEMANTICS, dependencies: [], format_version: 2,
    state_array_types: [{ path: ['data'], kind: 'json' }], initial_state: { count: 0, data: [] },
    record_schemas: { item: { type: 'object', fields: { label: 'string', title: 'string', secret: 'string' },
      required: ['label', 'title', 'secret'], max_bytes: 1024, protection: { v: 1, fields: {
        label: { protection: 'server_readable', type: 'opaque' },
        title: { protection: 'server_readable', type: 'opaque' },
        secret: { protection: 'e2ee' },
      } } } },
    actions: [{ id: 'set', reads: [], writes: [['count']],
      revisionEffects: { control: true, contentEntities: [] }, variants: [{ when: [], effects: [
        { op: 'set', path: ['count'], value: { from: 'literal', value: 1 } },
      ] }] }],
  }).manifest;
  const files = {
    'package.json': JSON.stringify({ format: PROTOCOL_METADATA_FORMAT, package_id: 'legacy-direct-disclosure',
      version: '1.0.0', name: 'Legacy direct disclosure fixture', description: 'Isolated author-selected disclosure',
      license: 'Apache-2.0', license_file: 'LICENSE', source_maintainers: [{ name: 'Test' }] }),
    'protocol.source.json': JSON.stringify({ format: PROTOCOL_SOURCE_FORMAT, semantics: SEMANTICS,
      manifest, imports: [], parameters: [], exports: [], bindings: [], derive: [] }),
    'release.lock.json': JSON.stringify({ format: PROTOCOL_LOCK_FORMAT, compiler_version: PROTOCOL_COMPILER_VERSION,
      semantics: SEMANTICS, dependencies: [], baseline_bindings: {}, output_protocol_digest: '0'.repeat(64) }),
    'README.md': 'Genuine public author flow for direct disclosure.', 'LICENSE': 'Test fixture.',
    'fixtures/basic.json': JSON.stringify({ id: 'basic', action_id: 'set', state: { count: 0, data: [] },
      body: {}, auth: { actorId: 'A'.repeat(43), workspaceRoles: [], protocolRoles: [], capabilities: [] },
      exact_inputs: [], expected: { accepted: true } }),
  };
  const bundle = { format: PROTOCOL_PACKAGE_FORMAT, files };
  const preview = previewProtocolPackage(bundle, { loadExactPackage: () => undefined });
  if (!preview.passed) throw new Error('INSTALL_DISCLOSURE_AUTHOR_PREVIEW_FAILED');
  files['release.lock.json'] = JSON.stringify({ ...JSON.parse(files['release.lock.json']),
    output_protocol_digest: preview.protocolDigest });
  return { v: 1, closure: createProtocolPackageClosure(parseProtocolPackage(bundle), []), bindings: {} };
}
