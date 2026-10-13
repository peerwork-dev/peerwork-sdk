import assert from 'node:assert/strict';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {mkdtempSync, mkdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {serve} from '@hono/node-server';

// Run as `node --input-type=module < SCRIPT` from the pinned f828 reference
// worktree. This deliberately uses the reference client and service only.
const root = process.env.PEERWORK_REFERENCE_ROOT;
assert.ok(root, 'PEERWORK_REFERENCE_ROOT is required');
const load = name => import(pathToFileURL(resolve(root, 'dist-workspace/src', `${name}.js`)).href);
const {openKernel, WorkspaceKernel} = await load('workspace-kernel');
const {createWorkspaceControlApp} = await load('workspace-http');
const {SecureAgentClient} = await load('workspace-secure-agent');
const {manifestCanonical, SEMANTICS} = await load('workspace-manifest');
const {previewProtocolPackage} = await load('protocol-compiler');
const {parseProtocolPackage, PROTOCOL_COMPILER_VERSION, PROTOCOL_LOCK_FORMAT,
  PROTOCOL_METADATA_FORMAT, PROTOCOL_PACKAGE_FORMAT, PROTOCOL_SOURCE_FORMAT} = await load('protocol-package');
const {createProtocolPackageClosure} = await load('protocol-package-closure');
const {compilePackageMaterial} = await load('workspace-protocol-package-source');
const {secureHash} = await load('workspace-secure-client');

const auth = {actorId:'A'.repeat(43), workspaceRoles:[], protocolRoles:[], capabilities:[]};
function packageFrom(name, manifest, parameters, fixture) {
  const files = {
    'package.json': JSON.stringify({format:PROTOCOL_METADATA_FORMAT, package_id:name,
      version:'1.0.0', name, description:'Reference options fixture', license:'Apache-2.0',
      license_file:'LICENSE', source_maintainers:[{name:'Test'}]}),
    'protocol.source.json': JSON.stringify({format:PROTOCOL_SOURCE_FORMAT, semantics:SEMANTICS,
      manifest, imports:[], parameters, exports:[], bindings:[], derive:[]}),
    'release.lock.json': JSON.stringify({format:PROTOCOL_LOCK_FORMAT,
      compiler_version:PROTOCOL_COMPILER_VERSION, semantics:SEMANTICS, dependencies:[],
      baseline_bindings:{}, output_protocol_digest:'0'.repeat(64)}),
    'README.md':'Reference package options fixture.', 'LICENSE':'Test fixture.',
    'fixtures/basic.json':JSON.stringify(fixture),
  };
  const bundle = {format:PROTOCOL_PACKAGE_FORMAT, files};
  const preview = previewProtocolPackage(bundle, {loadExactPackage:() => undefined});
  assert.equal(preview.passed, true, JSON.stringify(preview.fixtureResults));
  files['release.lock.json'] = JSON.stringify({...JSON.parse(files['release.lock.json']),
    output_protocol_digest:preview.protocolDigest});
  return parseProtocolPackage(bundle);
}

const readableManifest = manifestCanonical({name:'Readable option', display_version:'1',
  semantics:SEMANTICS, dependencies:[], format_version:2,
  state_array_types:[{path:['data'],kind:'json'}], initial_state:{count:0,data:[]},
  record_schemas:{item:{type:'object', fields:{label:'string'}, required:['label'], max_bytes:1024,
    protection:{v:1, fields:{label:{protection:'server_readable', type:'opaque'}}}}},
  actions:[{id:'set', reads:[], writes:[['count']],
    revisionEffects:{control:true,contentEntities:[]}, variants:[{when:[], effects:[
      {op:'set',path:['count'],value:{from:'literal',value:1}}]}]}]}).manifest;
const readablePackage = packageFrom('readable-option', readableManifest, [],
  {id:'basic', action_id:'set', state:{count:0}, body:{}, auth, exact_inputs:[],
    expected:{accepted:true}});
const readableMaterial = {v:1, closure:createProtocolPackageClosure(readablePackage, []), bindings:{}};
const readableCompiled = compilePackageMaterial(readableMaterial);
assert.equal(readableCompiled.manifest.format_version, 2);

const bindingManifest = manifestCanonical({name:'Binding option', display_version:'1',
  semantics:SEMANTICS, dependencies:[], protocol_roles:['AUTHOR','REVIEWER'],
  initial_state:{count:0}, record_schemas:{}, actions:[{id:'vote', reads:[], writes:[['count']],
    revisionEffects:{control:true,contentEntities:[]}, variants:[{
      when:[{op:'has_protocol_role',role:'REVIEWER'}],
      effects:[{op:'set',path:['count'],value:{from:'literal',value:1}}]}]}]}).manifest;
const parameter = [{name:'selectedRole',type:'enum',values:['AUTHOR','REVIEWER'],
  default:'REVIEWER',binding:{kind:'protocol_role_guard',action_id:'vote',
    variant_index:0,guard_index:0}}];
const bindingPackage = packageFrom('binding-option', bindingManifest, parameter,
  {id:'basic', action_id:'vote', state:{count:0}, body:{}, auth, exact_inputs:[],
    expected:{accepted:false,code:'CONSTRAINT_FAILED'}});
const bindingClosure = createProtocolPackageClosure(bindingPackage, []);
const bindingDefault = compilePackageMaterial({v:1,closure:bindingClosure,bindings:{}});
const bindingSelected = compilePackageMaterial({v:1,closure:bindingClosure,
  bindings:{selectedRole:'AUTHOR'}});
assert.notEqual(bindingDefault.protocolDigest, bindingSelected.protocolDigest);
assert.equal(bindingSelected.manifest.actions[0].variants[0].when[0].role, 'AUTHOR');
assert.equal(bindingDefault.manifest.actions[0].variants[0].when[0].role, 'REVIEWER');

const temp = mkdtempSync(join(tmpdir(), 'peerwork-private-options-'));
const db = openKernel(join(temp,'control.sqlite'),'private-options');
const kernel = new WorkspaceKernel(db,'private-options',randomBytes(32));
const server = serve({fetch:createWorkspaceControlApp(kernel).fetch,hostname:'127.0.0.1',port:0});
let owner;
try {
  await new Promise(resolve => server.once('listening',resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const baseUrl = `http://localhost:${address.port}`;
  const ownerDir = join(temp,'owner');
  mkdirSync(ownerDir,{mode:0o700});
  owner = await SecureAgentClient.open({baseUrl,privateKey:generateKeyPairSync('ed25519').privateKey,
    statePath:join(ownerDir,'state.json'),intentDbPath:join(ownerDir,'intents.sqlite')});
  const results = [];
  for (const [label,disclose] of [['default',undefined],
      ['explicit',[{schema:'item',fields:['label']}]]]) {
    const {workspaceId} = await owner.create(`Reference ${label}`,'PRIVATE',{structure:true});
    await owner.enableFormatTwo(workspaceId);
    const prior = await owner.journal(workspaceId);
    const priorPolicy = prior.policy.payload;
    const instance_id = randomBytes(32).toString('base64url');
    const installed = await owner.installProtocol(workspaceId,{instance_id,
      entrypoint:'readable',manifest:readableCompiled.manifest,
      ...(disclose ? {disclose} : {})});
    assert.equal(installed.policy.payload.protocol_format_ceiling,2);
    assert.equal(await secureHash(installed.policy), installed.checkpoint.policy_hash);
    assert.equal(installed.policy.payload.epoch, priorPolicy.epoch);
    assert.equal(installed.policy.payload.owner_id, priorPolicy.owner_id);
    assert.equal(installed.policy.payload.signing_key, priorPolicy.signing_key);
    assert.deepEqual(installed.policy.payload.members, priorPolicy.members);
    for (const existing of priorPolicy.structure.protocols)
      assert.deepEqual(installed.policy.payload.structure.protocols.find(
        item => item.protocol_digest === existing.protocol_digest), existing);
    for (const existing of priorPolicy.structure.instances)
      assert.deepEqual(installed.policy.payload.structure.instances.find(
        item => item.instance_id === existing.instance_id), existing);
    for (const existing of priorPolicy.structure.disclosure) {
      const retained = installed.policy.payload.structure.disclosure.find(
        item => item.protocol_digest === existing.protocol_digest && item.schema === existing.schema);
      assert.ok(retained);
      assert.deepEqual([...retained.fields].sort(), [...existing.fields].sort());
    }
    const protocol = installed.policy.payload.structure.protocols.find(
      item => item.protocol_digest === readableCompiled.protocolDigest);
    assert.ok(protocol);
    const field = protocol.schemas.item.fields.label;
    const approved = installed.policy.payload.structure.disclosure.find(
      item => item.protocol_digest === readableCompiled.protocolDigest && item.schema === 'item');
    assert.ok(approved);
    assert.equal(field.protection,disclose ? 'server_readable' : 'e2ee');
    assert.deepEqual(approved.fields,disclose ? ['label'] : []);
    results.push({mode:label,workspace_id:workspaceId,policy_hash:installed.checkpoint.policy_hash,
      sequence:installed.checkpoint.sequence,field,disclosure:approved.fields});
  }
  process.stdout.write(JSON.stringify({reference_commit:'f828b6c50a0a58d1e718af90f653b214adcc3328',
    readable:{material:readableMaterial,root_package_digest:readablePackage.packageDigest,
      protocol_digest:readableCompiled.protocolDigest,results},
    binding:{closure:bindingClosure,root_package_digest:bindingPackage.packageDigest,
      default_protocol_digest:bindingDefault.protocolDigest,
      selected_bindings:{selectedRole:'AUTHOR'},
      selected_protocol_digest:bindingSelected.protocolDigest}})+'\n');
} finally {
  owner?.close();
  if ('closeAllConnections' in server) server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  db.close();
  rmSync(temp,{recursive:true,force:true});
}
