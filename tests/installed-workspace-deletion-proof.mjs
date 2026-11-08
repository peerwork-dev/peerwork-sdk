// A valid service signature cannot substitute another Owner, workspace or
// original authorization. No private fixture or production key is used.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {readFileSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {createPrivateKey,createHash} from 'node:crypto';
import {signKernelJws,verifyKernelJws} from '../../e2ee-main-integration-20261006/dist-workspace/src/workspace-jws.js';
import {RECEIPT_TYPE,canonicalStructured,hash} from '../../e2ee-main-integration-20261006/dist-workspace/src/workspace-contract.js';
const prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),origin=process.env.PEERWORK_ACCESS_TEST_ORIGIN,path=resolve(process.env.PEERWORK_DELETION_FIXTURE),input=readFileSync(path),fixture=JSON.parse(input),sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk'),receiptKey=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,7)]),format:'der',type:'pkcs8'});
let mutation='NONE';const requests=[];
const server=createServer(async(req,res)=>{try{
 const parts=[];for await(const part of req)parts.push(part);const body=Buffer.concat(parts);let command;if(req.url.endsWith('/commands'))command=JSON.parse(Buffer.from(JSON.parse(body).jws.split('.')[1],'base64url'));
 const response=await fetch(origin+req.url,{method:req.method,headers:{'content-type':'application/json'},...req.method==='POST'?{body}:{}});const wire=await response.json();
 if(command?.action_id==='structure.workspace.deletion.get'&&mutation!=='NONE'){
  const job=wire.result.deletion;assert.ok(job);if(mutation==='OWNER')job.owner_id='O'.repeat(43);if(mutation==='WORKSPACE')job.workspace_id='W'.repeat(43);if(mutation==='COMMAND'){job.command_id='C'.repeat(43);job.job_id=job.command_id;}if(mutation==='DIGEST')job.intent_digest='a'.repeat(64);if(mutation==='KIND')job.kind='CURRENT_RECORDS';if(mutation==='FINAL_TIME')job.completed_at=null;if(mutation==='CREATED_TYPE')job.created_at='not-a-timestamp';if(mutation==='FINAL_BEFORE_CREATED')job.completed_at=job.created_at-1;if(mutation==='FINAL_PHASE')job.phase='ALIASES';if(mutation==='AUTHOR_SIGNATURE'){const p=job.source.author_intent.split('.');p[2]=Buffer.alloc(64).toString('base64url');job.source.author_intent=p.join('.');}
  const receipt=verifyKernelJws(wire.receipt,RECEIPT_TYPE).payload;wire.receipt=signKernelJws({...receipt,result_digest:hash(canonicalStructured(wire.result))},RECEIPT_TYPE,receiptKey);requests.push(mutation);
 }
 res.statusCode=response.status;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(wire));
}catch(error){res.statusCode=500;res.end(JSON.stringify({error:{code:'SYNTHETIC_PROXY_FAILURE'}}));}});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try{
 const before=await(await fetch(origin+'/_test/status')).json(),proxy='http://127.0.0.1:'+server.address().port,kernel=await sdk.openKernel({origin:proxy,identityPath:fixture.owner_identity,journalPath:join(state,'proof.sqlite'),allowLoopbackHttp:true}),query={action:'structure.workspace.deletion.get',workspace_id:fixture.workspace_id,body:{command_id:fixture.command_id}};
 assert.equal((await kernel.executeStructureIntent(query)).state,'ACCEPTED');const cases=['OWNER','WORKSPACE','COMMAND','DIGEST','KIND','FINAL_TIME','FINAL_PHASE','AUTHOR_SIGNATURE','CREATED_TYPE','FINAL_BEFORE_CREATED'];for(const kind of cases){mutation=kind;const refused=await kernel.executeStructureIntent(query);assert.equal(refused.state,'PENDING',kind+' substitution must never become an accepted observation');assert.equal(refused.code,'VERIFICATION_FAILED');assert.equal(refused.retryable,false);}
 mutation='NONE';assert.equal((await kernel.executeStructureIntent(query)).state,'ACCEPTED');const pending=await kernel.pendingPage();assert.equal(pending.items.length,0);assert.equal(pending.preparations.items.length,0);const after=await(await fetch(origin+'/_test/status')).json();assert.equal(after.commands,before.commands);assert.equal(after.journalRequests,before.journalRequests);assert.deepEqual(requests,cases);assert.equal(createHash('sha256').update(readFileSync(path)).digest('hex'),createHash('sha256').update(input).digest('hex'));const result={status:'PASS',fresh_valid_service_receipts:true,rejected_substitutions:cases,pure_read_no_pending_or_business_mutation:true,valid_observation_still_works:true,fixture_sha256:createHash('sha256').update(input).digest('hex')};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}finally{await new Promise(resolve=>server.close(resolve));}
