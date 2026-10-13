// Direct pinned TypeScript oracle for the official connected proposal/task package.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync,readdirSync,statSync,writeFileSync} from 'node:fs';
import {join,relative,sep} from 'node:path';
import {pathToFileURL} from 'node:url';

const root=process.env.PEERWORK_REFERENCE_ROOT;
if(!root)throw Error('PEERWORK_REFERENCE_ROOT is required');
const commit=execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
assert.equal(commit,'f828b6c50a0a58d1e718af90f653b214adcc3328');
for(const source of ['src/protocol-package.ts','src/protocol-package-closure.ts','src/protocol-compiler.ts']){
  assert.ok(statSync(join(root,'dist-workspace',source.replace(/\.ts$/,'.js'))).mtimeMs>=statSync(join(root,source)).mtimeMs);
}
const moduleAt=async path=>import(pathToFileURL(join(root,'dist-workspace/src',path)).href);
const {parseProtocolPackageBytes,canonicalProtocolPackageBytes}=await moduleAt('protocol-package.js');
const {createProtocolPackageClosure,exactPackageLoader}=await moduleAt('protocol-package-closure.js');
const {compileProtocolPackage}=await moduleAt('protocol-compiler.js');
function load(name){
  const base=join(root,'protocols',name),files={};
  function visit(path){for(const item of readdirSync(path,{withFileTypes:true})){
    const full=join(path,item.name);
    if(item.isDirectory())visit(full);
    else if(item.isFile())files[relative(base,full).split(sep).join('/')]=readFileSync(full,'utf8');
  }}
  visit(base);
  return parseProtocolPackageBytes(Buffer.from(canonicalProtocolPackageBytes({format:'peerwork.protocol-package.v1',files})));
}
const proposal=load('proposal-adoption-component');
const task=load('tasks-proposal-component');
const parent=load('tasks-proposal-adoption');
const closure=createProtocolPackageClosure(parent,[proposal,task]);
const compiled=compileProtocolPackage(parent,{loadExactPackage:exactPackageLoader(closure)});
assert.ok(compiled.passed);
assert.deepEqual(compiled.unresolvedRequiredInputs,[]);
assert.ok(compiled.manifest.actions.some(item=>item.id==='tasks.task.create_from_proposal'));
assert.ok(compiled.manifest.actions.some(item=>item.id==='proposal.proposal.adopt'));
assert.equal(compiled.dependencyClosure.length,2);
const value={reference_commit:commit,root_package_digest:parent.packageDigest,
  proposal_package_digest:proposal.packageDigest,task_package_digest:task.packageDigest,
  protocol_digest:compiled.protocolDigest,source_digest:compiled.sourceDigest,
  dependency_closure:compiled.dependencyClosure,
  compiled_manifest:compiled.manifest,closure};
const output=process.argv[2];
if(!output)throw Error('output path required');
writeFileSync(output,JSON.stringify(value)+'\n');
