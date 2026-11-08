// Genuine one-import material; no saved state or service database is edited.
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

export async function createLegacyComposedInstallMaterial(referenceRoot, largeObject = false) {
  const load = name => import(pathToFileURL(join(referenceRoot, `dist-workspace/src/${name}.js`)).href);
  const { manifestCanonical, SEMANTICS } = await load('workspace-manifest');
  const { discussionPreset } = await load('workspace-presets');
  const { previewProtocolPackage } = await load('protocol-compiler');
  const { parseProtocolPackage, PROTOCOL_COMPILER_VERSION, PROTOCOL_LOCK_FORMAT,
    PROTOCOL_METADATA_FORMAT, PROTOCOL_PACKAGE_FORMAT, PROTOCOL_SOURCE_FORMAT } = await load('protocol-package');
  const { createProtocolPackageClosure, exactPackageLoader } = await load('protocol-package-closure');
  const { compilePackageMaterial } = await load('workspace-protocol-package-source');
  const { resolveSecureProtocol, secureManifestDigest } = await load('workspace-secure-composition');
  const { secureEqual } = await load('workspace-secure-client');

  const directory = join(referenceRoot, 'protocols/discussion');
  const childFiles = {};
  const walk = at => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const path = join(at, entry.name);
      if (entry.isDirectory()) walk(path);
      else childFiles[relative(directory, path).split(sep).join('/')] = readFileSync(path, 'utf8');
    }
  };
  walk(directory);
  const child = parseProtocolPackage({ format: PROTOCOL_PACKAGE_FORMAT, files: childFiles });
  const selectedImport = { alias: 'discussion', package_digest: child.packageDigest, namespace: 'dep' };
  const ownManifest = manifestCanonical({ ...discussionPreset(),
    name: 'example.legacy-explicit-composition.v1', dependencies: [] }).manifest;
  if (largeObject) {
    const original = structuredClone(ownManifest.actions[0]);
    ownManifest.actions = Array.from({length: 8}, (_, index) => {
      const action = structuredClone(original);
      action.id = index === 0 ? 'discussion.post' : `large.package.post${index}`;
      action.variants[0].effects[0].value.fields.message = {from:'literal', value:'\\'.repeat(3000)};
      return action;
    });
  }
  const files = {
    'package.json': JSON.stringify({ format: PROTOCOL_METADATA_FORMAT, package_id: 'legacy-explicit-composition',
      version: '1.0.0', name: 'Legacy explicit composition fixture', description: 'One exact public dependency',
      license: 'Apache-2.0', license_file: 'LICENSE', source_maintainers: [{ name: 'Test' }] }),
    'protocol.source.json': JSON.stringify({ format: PROTOCOL_SOURCE_FORMAT, semantics: SEMANTICS,
      manifest: ownManifest, imports: [selectedImport], parameters: [], exports: [], bindings: [], derive: [] }),
    'release.lock.json': JSON.stringify({ format: PROTOCOL_LOCK_FORMAT, compiler_version: PROTOCOL_COMPILER_VERSION,
      semantics: SEMANTICS, dependencies: [selectedImport], baseline_bindings: {}, output_protocol_digest: '0'.repeat(64) }),
    'README.md': 'Genuine public author flow with one explicit imported package.', 'LICENSE': 'Test fixture.',
    'fixtures/root-authorized.json': JSON.stringify({
      ...JSON.parse(childFiles['fixtures/authorized-interaction.json']), id: 'root-authorized',
    }),
  };
  const bundle = { format: PROTOCOL_PACKAGE_FORMAT, files };
  const preview = previewProtocolPackage(bundle, { loadExactPackage: digest => digest === child.packageDigest ? child : undefined });
  if (!preview.passed || preview.unresolvedRequiredInputs.length) throw new Error('INSTALL_COMPOSITION_AUTHOR_PREVIEW_FAILED');
  files['release.lock.json'] = JSON.stringify({ ...JSON.parse(files['release.lock.json']),
    output_protocol_digest: preview.protocolDigest });
  const material = { v: 1, closure: createProtocolPackageClosure(parseProtocolPackage(bundle), [child]), bindings: {} };
  const compiled = compilePackageMaterial(material);
  // Reconstruct only this simple root's public source transformation: one
  // namespace import, no parameters/interfaces/derivations of its own.
  const dependencies = compiled.resolvedDependencyManifests.map(node => ({ digest: node.protocolDigest, manifest: node.manifest }));
  if (dependencies.length !== 1) throw new Error('INSTALL_COMPOSITION_DEPENDENCY_COUNT');
  const sourceManifest = manifestCanonical({ ...ownManifest, dependencies: dependencies.map(node => node.digest) }).manifest;
  const ownSource = await secureManifestDigest(ownManifest);
  if (ownSource.digest !== compiled.sourceDigest) throw new Error('INSTALL_COMPOSITION_OWN_SOURCE_DIGEST');
  const source = await secureManifestDigest(sourceManifest);
  const resolved = await resolveSecureProtocol(sourceManifest, digest => dependencies.find(node => node.digest === digest)?.manifest);
  if (resolved.composition.source_digest !== source.digest
    || !secureEqual(resolved.composition.source_manifest, sourceManifest)
    || resolved.digest !== compiled.protocolDigest || !secureEqual(resolved.manifest, compiled.manifest)
    || !secureEqual(resolved.composition.dependencies, dependencies)) throw new Error('INSTALL_COMPOSITION_COMPILER_EQUALITY');
  // Independently reselect the complete exact closure through the public loader.
  exactPackageLoader(material.closure)(child.packageDigest);
  return { material, sourceManifest, dependencies, compiledManifest: compiled.manifest,
    protocolDigest: compiled.protocolDigest, sourceDigest: source.digest,
    compilerOwnSourceDigest: compiled.sourceDigest,
    composition: resolved.composition };
}
