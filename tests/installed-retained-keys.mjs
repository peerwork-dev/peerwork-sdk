// Real installed Node/wheel/CLI and isolated PostgreSQL. All keys are synthetic.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN;
const sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk'),python=join(prefix,'python/bin/python'),cli=join(prefix,'bin/peerwork');let stage='setup',child;
const config=async v=>{const r=await fetch(origin+'/_test/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v)});assert.equal(r.status,200);};
async function profile(name){const path=join(state,name);mkdirSync(path,{mode:0o700});const identity=join(path,'identity'),journal=join(path,'operations.sqlite'),info=await sdk.createIdentity(identity),kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true});return{path,identity,journal,info,kernel};}
async function accepted(p){const r=await p;assert.equal(r.state,'ACCEPTED',JSON.stringify(r));return r.result;}
function file(name,data){const path=join(state,name);writeFileSync(path,JSON.stringify(data),{mode:0o600});return path;}
try{
 await config({offset_ms:0,drop_next_approval:false,history_drop_count:0,operation_drop_count:0});const baseline=await(await fetch(origin+'/_test/status')).json();
 const owner=await profile('owner'),plain=await profile('plain'),history=await profile('history'),py=await profile('python'),commandLine=await profile('cli'),interrupted=await profile('interrupted');
 const workspace=(await accepted(owner.kernel.executeStructureIntent({action:'structure.workspace.create',body:{name:'Retained-key installed acceptance'}}))).workspace_id;
 const manifest={name:'history-note',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],initial_state:{},record_schemas:{note:{type:'object',fields:{status:'string'},required:['status'],max_bytes:256}},actions:[{id:'post',reads:[],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[{op:'eq',left:{from:'literal',value:1},right:{from:'literal',value:1}}],effects:[{op:'append',schema:'note',value:{from:'literal',value:{status:'POSTED'}},relations:[]}]}]}]};
 const adopted=await accepted(owner.kernel.executeStructureIntent({action:'structure.adopt',workspace_id:workspace,body:{manifest,bootstrap_grant:{actions:['post']}}})),scope={workspace_id:workspace,instance_id:adopted.instance_id,protocol_digest:adopted.protocol_digest};const records=[];
 stage='seed-35-epochs';for(let i=1;i<=35;i++){
  if(i>1){const r=await owner.kernel.rotateContentKey({workspace_id:workspace,idempotency_key:'history-epoch-'+i});assert.equal(r.state,'COMPLETED');}
  const posted=await accepted(owner.kernel.executeStructureIntent({action:'structure.action',...scope,expected_instance_revision:1,idempotency_key:'record-'+i,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text:'Historical body '+i}]}));records.push(posted.produced_record_ids[0]);
 }
 const key=(await owner.kernel.ensureLocalContentKey(workspace)).key_id,read=kernel=>accepted(kernel.executeStructureIntent({action:'structure.records.read',...scope,body:{limit:32}}));
 stage='default-excludes-history';const plainRequest=await plain.kernel.requestAccess({workspace_id:workspace,label:'Current key only'}),plainGrant=await accepted(owner.kernel.authorizeAccess({workspace_id:workspace,request_jws:plainRequest.request_jws}));assert.equal(plainGrant.key_history,undefined);assert.equal(plainGrant.structure.retained_key_job,undefined);const plainRead=(await read(plain.kernel)).opened_contents;assert.ok(plainRead.filter(v=>v.state==='KEY_UNAVAILABLE').length>=31);assert.ok(plainRead.filter(v=>v.state==='OPENED').length<=1);
 const write={instance_id:scope.instance_id,protocol_digest:scope.protocol_digest,action_id:'post'};
 stage='single-owner-call';const request=await history.kernel.requestAccess({workspace_id:workspace,label:'Explicit retained keys',write}),selection={workspace_id:workspace,request_jws:request.request_jws,include_history:true,selected_write:{...write,protocol_roles:[],capabilities:[]}};
 const granted=await accepted(owner.kernel.authorizeAccess(selection));assert.equal(granted.key_history.state,'READY');assert.equal(granted.key_history.through_epoch,35);assert.equal(granted.structure.retained_key_job.state,'PENDING','original receipt is immutable; readiness is separate');
 const selected=await read(history.kernel);assert.equal(selected.opened_contents.length,32);assert.ok(selected.opened_contents.every(v=>v.state==='OPENED'));
 await accepted(history.kernel.executeStructureIntent({action:'structure.action',...scope,expected_instance_revision:1,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text:'Member uses the authenticated current key'}]}));assert.equal((await history.kernel.ensureLocalContentKey(workspace)).key_id,key);
 await accepted(history.kernel.executeStructureIntent({action:'structure.record.get',...scope,body:{record_id:records[33],revision:1}}));assert.equal((await history.kernel.ensureLocalContentKey(workspace)).key_id,key,'historical import cannot reset current selection');
 stage='python-and-cli';for(const device of [py,commandLine]){
  const request=await device.kernel.requestAccess({workspace_id:workspace,label:'Cross-language history'}),s={workspace_id:workspace,request_jws:request.request_jws,include_history:true};
  if(device===py){const input=file('python-owner.json',{origin,identity_path:owner.identity,journal_path:owner.journal,selection:s});const r=JSON.parse((await exec(python,['tests/installed-retained-keys.py','approve',input])).stdout);assert.equal(r.key_history.state,'READY');}
  else{const input=file('cli-owner.json',s),r=JSON.parse((await exec(cli,['kernel','access-approve',origin,owner.journal,owner.identity,input,'--allow-loopback-http'])).stdout);assert.equal(r.result.key_history.state,'READY');}
 }
 const pyInput=file('python-reader.json',{origin,identity_path:py.identity,journal_path:py.journal,scope});assert.equal(JSON.parse((await exec(python,['tests/installed-retained-keys.py','read',pyInput])).stdout).opened,32);
 const cliInput=file('cli-reader.json',{action:'structure.records.read',...scope,body:{limit:32}}),cliRead=JSON.parse((await exec(cli,['kernel','intent',origin,commandLine.journal,commandLine.identity,cliInput,'--allow-loopback-http'])).stdout);assert.equal(cliRead.result.opened_contents.length,32);assert.ok(cliRead.result.opened_contents.every(v=>v.state==='OPENED'));
 stage='forced-process-restart';const before=await(await fetch(origin+'/_test/status')).json(),restartRequest=await interrupted.kernel.requestAccess({workspace_id:workspace,label:'Interrupted retained delivery'}),restartSelection={workspace_id:workspace,request_jws:restartRequest.request_jws,include_history:true};
 await config({hold_next_history:true});const restartFile=file('restart-owner.json',restartSelection);child=spawn(cli,['kernel','access-approve',origin,owner.journal,owner.identity,restartFile,'--allow-loopback-http'],{stdio:['ignore','pipe','pipe']});file('history-process.json',{pid:child.pid,started_at:new Date().toISOString(),selection:restartFile});
 let held=false;for(let n=0;n<100;n++){const status=await(await fetch(origin+'/_test/status')).json();if(status.historyHolds>before.historyHolds){held=true;break;}if(child.exitCode!==null)throw new Error('Approval child exited before the held committed batch');await new Promise(r=>setTimeout(r,100));}assert.ok(held);
 child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));child=undefined;await config({release_history_hold:true,hold_next_history:false});
 const resumed=await accepted(owner.kernel.authorizeAccess(restartSelection));assert.equal(resumed.key_history.state,'READY');const restartedRead=await read(interrupted.kernel);assert.equal(restartedRead.opened_contents.length,32);assert.ok(restartedRead.opened_contents.every(v=>v.state==='OPENED'));
 stage='lost-final-batch-remains-pending';const lastDevice=await profile('lost-final-batch'),lastRequest=await lastDevice.kernel.requestAccess({workspace_id:workspace,label:'Lost final batch'});
 await config({history_drop_count:100,history_drop_after:1,operation_drop_count:100});
 const lost=await accepted(owner.kernel.authorizeAccess({workspace_id:workspace,request_jws:lastRequest.request_jws,include_history:true}));assert.equal(lost.key_history.state,'PENDING');
 const stillUnknown=await owner.kernel.coordinateContentKeys({workspace_id:workspace});assert.equal(stillUnknown.state,'PENDING','completed backend cursor must not hide an unverified saved final batch');
 await config({history_drop_count:0,history_drop_after:0,operation_drop_count:0});const coordinateFile=file('coordinate-history.json',{workspace_id:workspace});
 const completed=JSON.parse((await exec(cli,['kernel','coordinate-content-keys',origin,owner.journal,owner.identity,coordinateFile,'--allow-loopback-http'])).stdout);assert.equal(completed.state,'COMPLETED');
 const finalRead=await read(lastDevice.kernel);assert.ok(finalRead.opened_contents.every(v=>v.state==='OPENED'));assert.equal((await owner.kernel.pendingPage()).items.length,0);
 stage='expired-admission-window';await config({offset_ms:11*60000});const again=await accepted(owner.kernel.authorizeAccess(selection));assert.equal(again.command_id,granted.command_id);assert.equal(again.key_history.state,'READY');
 const final=await(await fetch(origin+'/_test/status')).json();assert.equal(final.journalRequests,baseline.journalRequests);
 const result={status:'PASS',epochs:35,single_owner_approval_finishes_history:true,default_current_only:true,retained_import_preserves_current_key:true,installed_node_python_cli_approval_and_read:true,forced_sigkill_after_history_commit_recovered:true,lost_final_batch_not_falsely_completed:true,cli_worker_reconciles_completed_job_stages:true,expired_admission_request_not_reused:true,journal_requests:0};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}catch(error){console.error(JSON.stringify({stage,name:error.name,code:error.code,message:error.message,details:error.details}));process.exitCode=1;}
finally{if(child&&child.exitCode===null){child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));}await config({release_history_hold:true,hold_next_history:false,history_drop_count:0,history_drop_after:0,operation_drop_count:0,offset_ms:0}).catch(()=>{});}
