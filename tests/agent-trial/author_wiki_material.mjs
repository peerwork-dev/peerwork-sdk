// Operator-side authoring proof for the exact selected f828 Wiki package.
// This only parses public source and uses the pinned public TS compiler.
import {createHash} from 'node:crypto';
import {readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {join, relative, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';

const [sourceRoot, outputDir] = process.argv.slice(2);
if (!sourceRoot || !outputDir) throw new Error('WIKI_AUTHOR_INPUT_REQUIRED');
const expectedCommit = 'f828b6c50a0a58d1e718af90f653b214adcc3328';
if (execFileSync('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'], {encoding:'utf8'}).trim() !== expectedCommit) {
  throw new Error('WIKI_AUTHOR_SOURCE_COMMIT_CHANGED');
}
execFileSync('git', ['-C', sourceRoot, 'diff', '--quiet', 'HEAD', '--', 'protocols/wiki']);
const pinned = {
  'protocols/wiki/package.json': '30635c8e33a5f3083815ee278cef6a6d0decf4beafe56dfbfdf0dd3b74e16446',
  'protocols/wiki/protocol.source.json': 'e24ba55f7a4d43aa98452228cec5eab060f0d8980008b2aaf00f79c262d84834',
  'protocols/wiki/release.lock.json': 'edafe1fd8e4714c92acba73099dbc6a47de4eba435272a900963f41baed226a8',
  'protocols/wiki/README.md': '1042eb0950e9df1025f205edf93bf35a3f3abe1ea43aaf029c6281e6a43a23a4',
  'protocols/wiki/LICENSE': 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30',
  'protocols/wiki/fixtures/authorized-interaction.json': '8f9e5bbda01f1affcdb47a6197b005683a8fd95b64fce2b39927294555de81d6',
  'protocols/wiki/fixtures/unauthenticated-rejected.json': '4531eb253beb54998c07d5d78547f5b4dce7225283133334246dda4556b9ac36',
};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const packagePath = join(sourceRoot, 'protocols/wiki');
const files = {};
function walk(path) {
  for (const entry of readdirSync(path, {withFileTypes:true})) {
    const child = join(path, entry.name);
    if (entry.isSymbolicLink()) throw new Error('WIKI_SOURCE_SYMLINK');
    if (entry.isDirectory()) walk(child);
    else if (entry.isFile()) {
      const rel = relative(packagePath, child).split(sep).join('/');
      const bytes = readFileSync(child);
      const expected = pinned[`protocols/wiki/${rel}`];
      if (!expected || hash(bytes) !== expected) throw new Error(`WIKI_SOURCE_FILE_CHANGED:${rel}`);
      files[rel] = bytes.toString('utf8');
    }
  }
}
walk(packagePath);
if (Object.keys(files).length !== Object.keys(pinned).length) throw new Error('WIKI_SOURCE_FILE_SET_CHANGED');
const dist = join(sourceRoot, 'dist-workspace/src');
for (const [name, expected] of Object.entries({
  'protocol-package.js':'c864257535bd3f63128d4c943356fa36f84381244ca980531727abee3b60466a',
  'protocol-package-closure.js':'6ff03ece18806633775fc1dd46bcb5915dc31dd75bfa6ee9cc4255bc47b1761b',
  'protocol-compiler.js':'918f83ce69f8fa7cc5bb21d715079a619c3459a38b6e1c11120808c9b32eb498',
  'workspace-protocol-package-source.js':'3c069458b5c2c7d09f3d7d179a5d215b651b47c8fc43bd8b045fdd5db58f2681',
})) if (hash(readFileSync(join(dist, name))) !== expected) throw new Error(`WIKI_COMPILER_CHANGED:${name}`);
const {PROTOCOL_PACKAGE_FORMAT, parseProtocolPackage} = await import(pathToFileURL(join(dist, 'protocol-package.js')).href);
const {createProtocolPackageClosure} = await import(pathToFileURL(join(dist, 'protocol-package-closure.js')).href);
const {compilePackageMaterial} = await import(pathToFileURL(join(dist, 'workspace-protocol-package-source.js')).href);
const pkg = parseProtocolPackage({format:PROTOCOL_PACKAGE_FORMAT, files});
const closure = createProtocolPackageClosure(pkg, []);
const material = {v:1, closure, bindings:{}};
const compiled = compilePackageMaterial(material);
if (pkg.source.manifest.actions.map(action=>action.id).sort().join(',') !==
    ['wiki.branch','wiki.create','wiki.revise','wiki.select_head'].sort().join(',')) throw new Error('WIKI_ACTION_SET_CHANGED');
if (pkg.source.manifest.record_schemas['wiki.revision'] === undefined) throw new Error('WIKI_SCHEMA_MISSING');
if (compiled.protocolDigest !== '33f799e4b168b28032348a26e8c5d320cb2c43550e3effc60f584dc4561717a3') throw new Error('WIKI_COMPILED_DIGEST_CHANGED');
if (compiled.sourceDigest !== '05300473589495f96080b96c78962acc0c0ecc8bf1ae82d84f214042a6d30ca2') throw new Error('WIKI_SOURCE_DIGEST_CHANGED');
writeFileSync(join(outputDir, 'closure.json'), JSON.stringify(closure) + '\n', {mode:0o600, flag:'wx'});
writeFileSync(join(outputDir, 'material.json'), JSON.stringify(material) + '\n', {mode:0o600, flag:'wx'});
writeFileSync(join(outputDir, 'author-proof.json'), JSON.stringify({
  source_commit:expectedCommit, package_file_count:Object.keys(files).length,
  root_package_digest:pkg.packageDigest, source_digest:compiled.sourceDigest,
  protocol_digest:compiled.protocolDigest, entrypoint:'wiki',
  action_ids:pkg.source.manifest.actions.map(action=>action.id).sort(),
  closure_bytes:Buffer.byteLength(JSON.stringify(closure)),
}) + '\n', {mode:0o600, flag:'wx'});
process.stdout.write(JSON.stringify({source_commit:expectedCommit, root_package_digest:pkg.packageDigest,
  source_digest:compiled.sourceDigest, protocol_digest:compiled.protocolDigest,
  action_count:pkg.source.manifest.actions.length, closure_bytes:Buffer.byteLength(JSON.stringify(closure))}) + '\n');
