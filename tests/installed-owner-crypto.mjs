// Actual installed SDKs; no production data or keys are used.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN;
const sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');let stage='setup',worker;
const config=async selection=>{const r=await fetch(origin+'/_test/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(selection)});assert.equal(r.status,200);};
async function profile(name){const path=join(state,name);mkdirSync(path,{mode:0o700});const identity=join(path,'identity'),journal=join(path,'operations.sqlite'),info=await sdk.createIdentity(identity),kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true});return{path,identity,journal,info,kernel};}
async function accepted(p){const r=await p;assert.equal(r.state,'ACCEPTED',JSON.stringify(r));return r.result;}
try{
 const baseline=await(await fetch(origin+'/_test/status')).json();await config({offset_ms:0});
 const owner=await profile('owner'),member=await profile('follower'),revoke=await profile('revoke'),newDevice=await profile('new-device');
 const workspace=(await accepted(owner.kernel.executeStructureIntent({action:'structure.workspace.create',body:{name:'Automatic Owner crypto acceptance'}}))).workspace_id;
 const manifest={name:'auto-crypto-note',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],initial_state:{},record_schemas:{note:{type:'object',fields:{status:'string'},required:['status'],max_bytes:256}},actions:[{id:'post',reads:[],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[{op:'eq',left:{from:'literal',value:1},right:{from:'literal',value:1}}],effects:[{op:'append',schema:'note',value:{from:'literal',value:{status:'POSTED'}},relations:[]}]}]}]};
 const adopted=await accepted(owner.kernel.executeStructureIntent({action:'structure.adopt',workspace_id:workspace,body:{manifest,bootstrap_grant:{actions:['post']}}})),scope={workspace_id:workspace,instance_id:adopted.instance_id,protocol_digest:adopted.protocol_digest};
 const action=(key,text,revision=1)=>({action:'structure.action',...scope,expected_instance_revision:revision,idempotency_key:key,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text}]});
 const metadata=async()=> (await accepted(owner.kernel.executeStructureIntent({action:'structure.workspace.get',workspace_id:workspace,body:{}}))).structure;
 const read=async kernel=>accepted(kernel.executeStructureIntent({action:'structure.records.read',...scope,body:{limit:32}}));
 await accepted(owner.kernel.executeStructureIntent(action('initial','Initial encrypted body')));
 const write={instance_id:scope.instance_id,protocol_digest:scope.protocol_digest,action_id:'post'};
 for(const worker of [member,revoke]){const request=await worker.kernel.requestAccess({workspace_id:workspace,label:'Automatic crypto fixture',write});worker.grant=await accepted(owner.kernel.authorizeAccess({workspace_id:workspace,request_jws:request.request_jws,ttl_ms:3600000,follow_current_key:true}));}
 assert.equal((await read(member.kernel)).opened_contents[0].state,'OPENED');
 let current=await metadata();await accepted(owner.kernel.executeStructureIntent({action:'structure.member.set',workspace_id:workspace,expected_workspace_revision:current.workspace_revision,body:{actor_id:revoke.info.actor_id,state:'REVOKED',expected_membership_id:revoke.grant.structure.membership_id}}));
 current=await metadata();assert.equal(current.content_key_head.usable,false);assert.equal(current.content_key_head.epoch,1);
 stage='member-cannot-maintain';await assert.rejects(member.kernel.executeStructureIntent(action('not-owner','No implicit Owner delegation')),e=>e.code==='CONTENT_KEY_ROTATION_REQUIRED');assert.equal((await metadata()).content_key_head.epoch,1);
 stage='automatic-owner-publication';const before=await(await fetch(origin+'/_test/status')).json();await config({key_drop_count:2,hold_next_delivery:true});
 const started=performance.now(),intent=action('owner-auto-write','Owner writes after automatic rotation'),posted=await accepted(owner.kernel.executeStructureIntent(intent));assert.ok(performance.now()-started<15000);
 current=await metadata();assert.equal(current.content_key_head.epoch,2);assert.equal(current.content_key_head.usable,true);
 const after=await(await fetch(origin+'/_test/status')).json();assert.equal(after.deliveryReads,before.deliveryReads,'business write must not wait for every recipient');assert.equal(after.deliveryHolds,before.deliveryHolds,'business path did not enter the held delivery');await config({hold_next_delivery:false});
 const repeated=await accepted(owner.kernel.executeStructureIntent(intent));assert.equal(repeated.command_id,posted.command_id);assert.equal((await metadata()).content_key_head.epoch,2);assert.equal((await read(owner.kernel)).structure.records.length,2);
 stage='independent-delivery';const pendingBodies=await read(member.kernel);assert.ok(pendingBodies.opened_contents.some(v=>v.state==='KEY_UNAVAILABLE'));
 const workerSelection=join(owner.path,'worker.json');writeFileSync(workerSelection,JSON.stringify({workspace_id:workspace}),{mode:0o600});
 worker=spawn(join(prefix,'bin/peerwork'),['kernel','coordinate-content-keys',origin,owner.journal,owner.identity,workerSelection,'--allow-loopback-http','--watch'],{stdio:['ignore','pipe','pipe']});
 writeFileSync(join(state,'crypto-worker-process.json'),JSON.stringify({pid:worker.pid,started_at:new Date().toISOString(),selection:workerSelection}));
 let workerOutput='',workerErrors='';worker.stderr.on('data',c=>{workerErrors+=c;});
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Crypto worker did not finish delivery: '+workerErrors)),15000);worker.stdout.on('data',c=>{workerOutput+=c;if(workerOutput.split('\n').some(line=>{try{return JSON.parse(line).state==='COMPLETED';}catch{return false;}})){clearTimeout(timer);resolve();}});worker.once('exit',(code)=>{clearTimeout(timer);reject(new Error('Crypto worker exited before delivery: '+code));});});
 worker.kill('SIGTERM');await new Promise(resolve=>worker.once('exit',resolve));worker=undefined;writeFileSync(join(state,'crypto-worker-output.log'),workerOutput);
 const ready=await read(member.kernel);assert.equal(ready.structure.records.length,2);assert.ok(ready.opened_contents.every(v=>v.state==='OPENED'));
 let refused=false;try{const denied=await revoke.kernel.executeStructureIntent({action:'structure.records.read',...scope,body:{limit:32}});assert.equal(denied.state,'REJECTED');refused=true;}catch(e){if(e.code==='OPERATION_REJECTED')refused=true;else throw e;}assert.ok(refused);
 stage='expired-head-approval';await config({offset_ms:3600001});const request=await newDevice.kernel.requestAccess({workspace_id:workspace,label:'Fresh device after expiry'});
 const approval=await accepted(owner.kernel.authorizeAccess({workspace_id:workspace,request_jws:request.request_jws}));assert.ok(approval.structure.membership_id);current=await metadata();assert.equal(current.content_key_head.epoch,3);assert.equal(current.content_key_head.usable,true);
 const opened=await read(newDevice.kernel);assert.ok(opened.opened_contents.every(v=>v.state==='KEY_UNAVAILABLE'),'approval delivered only the explicitly selected current key, not all historical keys');
 stage='business-cas-preserved';current=await metadata();await accepted(owner.kernel.executeStructureIntent({action:'structure.member.set',workspace_id:workspace,expected_workspace_revision:current.workspace_revision,body:{actor_id:newDevice.info.actor_id,state:'REVOKED',expected_membership_id:approval.structure.membership_id}}));
 const stale=await owner.kernel.executeStructureIntent(action('stale-business-cas','Must never rebase business state',999));assert.equal(stale.state,'REJECTED');assert.equal(stale.result.structure.error.code,'STALE_REVISION');assert.equal((await metadata()).content_key_head.epoch,4);assert.equal((await read(owner.kernel)).structure.records.length,2);
 stage='uncertain-crypto-parent-recovery';const onceMore=await profile('uncertain-revoke');
 const pendingRequest=await onceMore.kernel.requestAccess({workspace_id:workspace,label:'Uncertain crypto recovery fixture'});
 const pendingGrant=await accepted(owner.kernel.authorizeAccess({workspace_id:workspace,request_jws:pendingRequest.request_jws}));current=await metadata();
 await accepted(owner.kernel.executeStructureIntent({action:'structure.member.set',workspace_id:workspace,expected_workspace_revision:current.workspace_revision,body:{actor_id:onceMore.info.actor_id,state:'REVOKED',expected_membership_id:pendingGrant.structure.membership_id}}));
 await config({key_drop_count:2,operation_drop_count:100});const uncertainIntent=action('uncertain-auto-write','Original body after uncertain prerequisite');
 const waiting=await owner.kernel.executeStructureIntent(uncertainIntent);assert.equal(waiting.state,'PENDING');assert.equal(waiting.phase,'PREPARATION');assert.equal(waiting.effect_certainty,'NOT_SUBMITTED');
 current=await metadata();assert.equal(current.content_key_head.epoch,5);assert.notEqual(waiting.command_id,current.content_key_head.command_id);
 const pendingPage=await owner.kernel.pendingPage();assert.ok(pendingPage.preparations.items.some(v=>v.command_id===waiting.command_id));assert.ok(pendingPage.items.some(v=>v.command_id===current.content_key_head.command_id));assert.equal((await read(owner.kernel)).structure.records.length,2);
 await config({key_drop_count:0,operation_drop_count:0});const selectionPath=join(owner.path,'uncertain-parent.json');writeFileSync(selectionPath,JSON.stringify({origin,journal_path:owner.journal,identity_path:owner.identity,command_id:waiting.command_id}),{mode:0o600});
 const recovered=JSON.parse((await exec(join(prefix,'python/bin/python'),['tests/installed-structure-parent.py','resume',selectionPath])).stdout);assert.equal(recovered.command_id,waiting.command_id);
 const repeatedUnknown=await accepted(owner.kernel.executeStructureIntent(uncertainIntent));assert.equal(repeatedUnknown.command_id,waiting.command_id);assert.equal((await metadata()).content_key_head.epoch,5);assert.equal((await read(owner.kernel)).structure.records.length,3);
 const completedPage=await owner.kernel.pendingPage();assert.ok(!completedPage.preparations.items.some(v=>v.command_id===waiting.command_id));
 const final=await(await fetch(origin+'/_test/status')).json();assert.equal(final.journalRequests,baseline.journalRequests);
 const result={status:'PASS',automatic_owner_rotation:true,initialization_and_rotation_reply_loss_recovered:true,business_write_does_not_wait_for_recipient_fanout:true,separate_follow_recipient_delivery:true,native_cli_crypto_worker:true,revoked_recipient_excluded:true,member_has_no_implicit_crypto_authority:true,expired_head_approval_automatically_rotates:true,default_approval_does_not_grant_retained_history:true,original_business_cas_preserved:true,single_business_record_per_operation:true,uncertain_crypto_parent_resumed_by_python:true,uncertain_crypto_did_not_submit_business_early:true,journal_requests:0};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}catch(error){console.error(JSON.stringify({stage,name:error.name,code:error.code,message:error.message}));process.exitCode=1;}

finally{if(worker&&worker.exitCode===null){worker.kill('SIGTERM');await new Promise(resolve=>worker.once('exit',resolve));}}
