// Consume an already-authorized synthetic member operation; never bootstrap a second fixture.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
const [packagePath,fixturePath,cliPath,outputPath]=process.argv.slice(2);
assert.ok(packagePath&&fixturePath&&cliPath&&outputPath,'package fixture CLI output required');
const fixture=JSON.parse(readFileSync(fixturePath,'utf8'));
const config=JSON.parse(readFileSync(fixture.profile_path,'utf8'));
assert.equal(config.workspace_id,fixture.workspace_id);
assert.notEqual(fixture.member_actor_id,fixture.owner_actor_id);
assert.match(fixture.command_id,/^[A-Za-z0-9_-]{43}$/);
const sdk=createRequire(import.meta.url)(packagePath);
const actions=sdk.openSecurePrivateActions({origin:config.origin,stateDir:config.state_dir,
  identityPath:config.identity_path,workspaceId:config.workspace_id,
  ownerActorId:config.owner_actor_id,ownerKeyId:config.owner_key_id,
  authority:config.authority,allowLoopbackHttp:config.allow_loopback_http,
  transport:config.transport&&{requestTimeoutMs:config.transport.request_timeout_ms,
    additionalRootPemFiles:config.transport.additional_root_pem_files}});
const before=await actions.pending();
let submitted;
if(fixture.new_action){
  assert.match(fixture.operation_id,/^[A-Za-z0-9_-]{43}$/);
  assert.equal(fixture.new_action.action_id,'wiki.create');
  submitted=await actions.submit(fixture.new_action.action_id,fixture.new_action.instance_id,fixture.new_action.body,
    {commandId:fixture.command_id,operationId:fixture.operation_id});
  assert.equal(submitted.status,'PENDING');
  assert.equal(submitted.command_id,fixture.command_id);
}
const reconciled=await actions.reconcile(fixture.command_id);
assert.equal(reconciled.status,'ACCEPTED');
assert.equal(reconciled.receipt.actor_id,fixture.member_actor_id);
const cli=verb=>{
  const run=spawnSync(cliPath,['secure',verb,fixture.profile_path,fixture.command_id],{encoding:'utf8',timeout:90000});
  assert.equal(run.status,0,`${verb}: ${run.stderr}`);
  const result=JSON.parse(run.stdout);
  assert.equal(result.status,'ACCEPTED');
  assert.equal(result.command_id,fixture.command_id);
  assert.equal(result.commit_hash,reconciled.commit_hash);
  assert.equal(result.receipt.actor_id,fixture.member_actor_id);
  return result;
};
cli('private-action-status');
cli('private-action-retry');
const after=await actions.pending();
assert.ok(!after.some(x=>x.command_id===fixture.command_id));
const result={status:'PASS',scope:'locally installed native Node member submit/reconcile and CLI status/exact saved retry; reused Python fixture, no bootstrap',
  command_id:fixture.command_id,workspace_id:fixture.workspace_id,member_actor_id:fixture.member_actor_id,
  node_submit:submitted?.status??null,node_status:reconciled.status,cli_status:'ACCEPTED',cli_retry:'ACCEPTED',pending_before:before.length,pending_after:after.length};
writeFileSync(outputPath,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify(result));
