// Genuine oversized protocol value, matching f828's large-protocol package test.
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function createLegacyObjectInstallMaterial(referenceRoot) {
  const load = name => import(pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href);
  const { previewProtocolPackage } = await load('protocol-compiler');
  const { parseProtocolPackage, PROTOCOL_PACKAGE_FORMAT } = await load('protocol-package');
  const { createProtocolPackageClosure } = await load('protocol-package-closure');
  const { compilePackageMaterial } = await load('workspace-protocol-package-source');
  const { manifestDigest } = await load('workspace-contract');
  const { encodeCanonicalJson } = await load('workspace-secure-crypto');
  const { SECURE_LIMITS } = await load('workspace-secure-contract');
  const { secureEqual } = await load('workspace-secure-client');
  const directory = join(referenceRoot, 'protocols/discussion'), files = {};
  const walk = at => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const path = join(at, entry.name);
      if (entry.isDirectory()) walk(path);
      else files[relative(directory, path).split(sep).join('/')] = readFileSync(path, 'utf8');
    }
  };
  walk(directory);
  const source = JSON.parse(files['protocol.source.json']), original = source.manifest.actions[0];
  source.manifest.name = 'example.native-retained-object-source.v1';
  source.manifest.actions = Array.from({ length: 8 }, (_, index) => {
    const action = structuredClone(original);
    action.id = index === 0 ? 'discussion.post' : `large.package.post${index}`;
    action.variants[0].effects[0].value.fields.message = { from: 'literal', value: `package ${index}: ` + 'y'.repeat(7000) };
    return action;
  });
  files['protocol.source.json'] = JSON.stringify(source);
  const bundle = { format: PROTOCOL_PACKAGE_FORMAT, files };
  const preview = previewProtocolPackage(bundle, { loadExactPackage: () => undefined });
  if (!preview.passed || preview.unresolvedRequiredInputs.length) throw new Error('INSTALL_OBJECT_AUTHOR_PREVIEW');
  files['release.lock.json'] = JSON.stringify({ ...JSON.parse(files['release.lock.json']), output_protocol_digest: preview.protocolDigest });
  const material = { v: 1, closure: createProtocolPackageClosure(parseProtocolPackage(bundle), []), bindings: {} };
  const compiled = compilePackageMaterial(material), normalized = manifestDigest(source.manifest);
  if (compiled.protocolDigest !== normalized.digest || !secureEqual(compiled.manifest, normalized.manifest)) {
    throw new Error('INSTALL_OBJECT_COMPILER_EQUALITY');
  }
  const value = { workspace_id: 'W'.repeat(43), digest: compiled.protocolDigest,
    manifest: compiled.manifest, resolved_manifest: compiled.manifest };
  if (encodeCanonicalJson({ kind: 'protocols', id: compiled.protocolDigest, revision: 1,
    provenance: 'AUTHOR_SIGNED', value }).byteLength <= SECURE_LIMITS.objectBytes) {
    throw new Error('INSTALL_OBJECT_VALUE_NOT_OVERSIZED');
  }
  return material;
}
