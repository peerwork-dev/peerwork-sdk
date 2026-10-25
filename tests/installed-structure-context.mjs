// Installed npm + wheel + CLI acceptance against the same frozen synthetic
// service. No source-module replacement, native mocks or production identities.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {spawn,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createInterface} from 'node:readline';

const exec=promisify(execFile);
const prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX);
const sdk=createRequire(join(prefix,'node','package.json'))('@peerwork/agent-sdk');
const state=mkdtempSync(join(resolve(process.env.TMPDIR),'structure-installed-'));
const node=process.execPath;
const server=spawn(node,[new URL('./structure-profile-service.mjs',import.meta.url).pathname],{
 env:{...process.env,PEERWORK_TEST_STATE:state,PEERWORK_STRUCTURE_TEST_DROPS:'2'},stdio:['ignore','pipe','inherit'],
});
try {
 const lines=createInterface({input:server.stdout});
 const first=await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error('synthetic service startup timeout')),30000);
  lines.once('line',line=>{clearTimeout(timer);resolve(line);});
  server.once('exit',code=>{clearTimeout(timer);reject(new Error(`synthetic service exited ${code}`));});
 });
 const {origin}=JSON.parse(first);
 const ownerDir=join(state,'owner'),workerDir=join(state,'worker');
 mkdirSync(ownerDir,{mode:0o700});mkdirSync(workerDir,{mode:0o700});
 const ownerPath=join(ownerDir,'identity.state'),workerPath=join(workerDir,'identity.state');
 const owner=await sdk.createIdentity(ownerPath),worker=await sdk.createIdentity(workerPath);
 assert.notEqual(owner.actor_id,worker.actor_id);
 const kernel=await sdk.openKernel({origin,journalPath:join(ownerDir,'operations.sqlite'),identityPath:ownerPath,allowLoopbackHttp:true});
 const created=await kernel.executeStructureIntent({action:'structure.workspace.create',idempotency_key:'create',body:{name:'Installed collaboration'}});
 assert.equal(created.state,'ACCEPTED');const workspace=created.result.workspace_id;
 const context=await sdk.bindStructureContext({profilePath:join(ownerDir,'context.json'),expectedActor:owner.actor_id,
  expectedService:'installed-candidate',origin,identityPath:ownerPath,journalPath:join(ownerDir,'operations.sqlite'),workspaceIds:[workspace],allowLoopbackHttp:true});
 const manifest={name:'installed-claim',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],initial_state:{holder:null},
  record_schemas:{claim:{type:'object',fields:{status:'string'},required:['status'],max_bytes:256}},actions:[{id:'claim',reads:[['holder']],writes:[['holder']],
   revisionEffects:{control:true,contentEntities:[]},variants:[{when:[{op:'eq',left:{from:'state',path:['holder']},right:{from:'literal',value:null}}],effects:[
    {op:'set',path:['holder'],value:{from:'auth',field:'actorId'}},{op:'append',schema:'claim',value:{from:'literal',value:{status:'claimed'}},relations:[]}]}]}]};
 const adopted=await context.operate(workspace,{kind:'structure.intent',request:{action:'structure.adopt',body:{manifest,bootstrap_grant:{actions:['claim']}}}},'adopt');
 assert.equal(adopted.status,'verified');const {instance_id:instance,protocol_digest:protocol,workspace_revision:revision}=adopted.result;
 const member=await context.operate(workspace,{kind:'structure.intent',request:{action:'structure.member.set',expected_workspace_revision:revision,
  body:{actor_id:worker.actor_id,state:'ACTIVE',expected_membership_id:null}}},'admit');
 assert.equal(member.status,'verified');
 const grant=await context.operate(workspace,{kind:'structure.intent',request:{action:'structure.grant.set',instance_id:instance,protocol_digest:protocol,
  body:{actor_id:worker.actor_id,membership_id:member.result.membership_id,expected_grant_revision:null,actions:['claim']}}},'grant');
 assert.equal(grant.status,'verified');
 const tail=await context.executeStructureIntent(workspace,{action:'structure.events.read',body:{}});
 assert.equal(tail.result.events.length,0);
 const input=join(state,'worker-input.json');writeFileSync(input,JSON.stringify({origin,workspace,instance,protocol,worker:worker.actor_id,
  worker_dir:workerDir,after_sequence:tail.result.checkpoint}),{mode:0o600});
 const python=await exec(process.env.PEERWORK_TEST_PYTHON??'python3',[new URL('./installed-structure-context.py',import.meta.url).pathname,input],{
  env:{...process.env,PYTHONPATH:join(prefix,'python'),PEERWORK_INSTALLED_PREFIX:prefix},timeout:60000,maxBuffer:262144,
 });
 const workerResult=JSON.parse(python.stdout);assert.equal(workerResult.actor_id,worker.actor_id);assert.equal(workerResult.state_holder,worker.actor_id);
 const request=join(state,'cli-request.json');writeFileSync(request,JSON.stringify({workspace_id:workspace,expected_fingerprint:workerResult.fingerprint,
  intent:{action:'structure.records.read',instance_id:instance,protocol_digest:protocol,body:{limit:1}}}),{mode:0o600});
 const cli=await exec(join(prefix,'bin','peerwork'),['context','execute-structure',join(workerDir,'context.json'),worker.actor_id,'installed-candidate',request],{timeout:30000,maxBuffer:262144});
 const cliResult=JSON.parse(cli.stdout);assert.equal(cliResult.ok,true);assert.equal(cliResult.value.status,'verified');assert.equal(cliResult.value.result.records.length,1);
 assert.equal(cliResult.value.opened_contents[0].text,'Installed private body 🚀');
 const ownerRead=await context.executeStructureIntent(workspace,{action:'structure.records.read',instance_id:instance,protocol_digest:protocol,body:{limit:1}});
 assert.equal(ownerRead.status,'verified');assert.equal(ownerRead.opened_contents[0].state,'KEY_UNAVAILABLE');
 assert.equal(JSON.stringify(ownerRead).includes('Installed private body'),false);
 const current=await context.describe(workspace,{instanceId:instance,protocolDigest:protocol});
 const rebuilt=await context.operate(workspace,{kind:'structure.intent',request:{action:'structure.maintenance.rebuild',instance_id:instance,
  protocol_digest:protocol,expected_instance_revision:current.result.revision,body:{expected_event_revision:current.result.event_revision}}},'repair-current');
 assert.equal(rebuilt.status,'verified');assert.equal(rebuilt.result.maintenance.status,'APPLIED');
 assert.notEqual(rebuilt.command_id,rebuilt.observation_command_id);
 const fresh=await sdk.bindStructureContext({profilePath:join(ownerDir,'fresh-context.json'),expectedActor:owner.actor_id,
  expectedService:'installed-candidate',origin,identityPath:ownerPath,journalPath:join(ownerDir,'fresh-operations.sqlite'),workspaceIds:[workspace],allowLoopbackHttp:true});
 const operations=await fresh.operations(workspace,{view:'HISTORY',limit:1});
 const operation=operations.result.operations[0];assert.equal(operation.job_id,rebuilt.result.maintenance.job_id);
 const followed=await fresh.followOperation(workspace,{job_id:operation.job_id,instance_id:operation.instance_id,protocol_digest:operation.protocol_digest});
 assert.equal(followed.status,'verified');assert.equal(followed.command_id,rebuilt.command_id);
 assert.equal((await kernel.pendingPage({limit:1})).items.length,0);
 const maintenance=await (await fetch(`${origin}__test/maintenance-counts`)).json();
 assert.deepEqual(maintenance,{jobs:1,maintenance_dropped:0,journal_reads:0});
 const counts=await (await fetch(`${origin}__test/counts`)).json();assert.deepEqual(counts,{records:1,dropped:2,journal_reads:0});
 const collaboration=await (await fetch(`${origin}__test/collaboration-counts`)).json();assert.deepEqual(collaboration,{workspaces:1,identities:2,grant_heads:2,current_records:1});
 console.log(JSON.stringify({status:'PASS',profile:'backend-structure-v1',installed:{node:true,python_wheel:true,cli:true},identities:2,
  workspace_count:1,produced_records:1,dropped_replies:2,journal_reads:0,worker_durable_intents:workerResult.durable_intents,
  worker_accepted_responses:workerResult.accepted_responses,checks:['private-create','adopt','member-and-grant','context-bind','bounded-discover-and-describe',
   'one-call-action','lost-response-recovery','same-operation-deduplication','author-verified-records-and-events','CLI-bounded-read',
   'bounded-local-pending','one-call-body-encryption','author-and-AEAD-opening','fresh-context-key-reuse','body-not-in-journal',
   'missing-key-preserves-structure','one-call-backend-maintenance','fresh-context-operation-discovery-and-follow',
   'no-legacy-history-or-identity-migration']}));
} finally {
 server.kill();await new Promise(resolve=>{if(server.exitCode!==null||server.signalCode!==null)resolve();else server.once('exit',resolve);});
 rmSync(state,{recursive:true,force:true});
}
