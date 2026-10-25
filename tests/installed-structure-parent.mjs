// Installed npm/wheel/CLI, synthetic identities, real isolated PostgreSQL service.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createServer} from 'node:http';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),upstream=process.env.PEERWORK_ACCESS_TEST_ORIGIN;
const sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');
let gate=false,contexts=0,journals=0,stage='setup';const active=new Set();
const proxy=createServer(async(req,res)=>{
 try{
  if(req.url.includes('/journal'))journals++;
  if(req.url.startsWith('/api/workspace/v1/structure/context')){
   contexts++;if(gate){active.add(res);res.on('close',()=>active.delete(res));return;}
  }
  const chunks=[];for await(const c of req)chunks.push(c);
  const response=await fetch(upstream+req.url,{method:req.method,headers:{'content-type':'application/json'},body:['GET','HEAD'].includes(req.method)?undefined:Buffer.concat(chunks),redirect:'manual'});
  res.writeHead(response.status,{'Content-Type':response.headers.get('content-type')||'application/json'});res.end(Buffer.from(await response.arrayBuffer()));
 }catch{if(!res.headersSent)res.writeHead(502);res.end();}
});
await new Promise(r=>proxy.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${proxy.address().port}`;
const python=join(prefix,'python/bin/python'),cli=join(prefix,'bin/peerwork');
async function profile(name){const path=join(state,name);mkdirSync(path,{mode:0o700});const identity=join(path,'identity'),journal=join(path,'operations.sqlite'),info=await sdk.createIdentity(identity),kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true,transport:{requestTimeoutMs:750}});return {path,identity,journal,info,kernel};}
async function accepted(p){const r=await p;assert.equal(r.state,'ACCEPTED',JSON.stringify(r));return r.result;}
function selection(profile,id){const path=join(profile.path,'resume.json');writeFileSync(path,JSON.stringify({origin,identity_path:profile.identity,journal_path:profile.journal,command_id:id}),{mode:0o600});return path;}
async function pending(p){const started=performance.now(),r=await p;assert.equal(r.state,'PENDING');assert.equal(r.phase,'PREPARATION');assert.equal(r.effect_certainty,'NOT_SUBMITTED');assert.equal(r.recovery,'RESUME_SAME_INTENT');assert.ok(performance.now()-started<4000);return r;}
try{
 const baseline=await(await fetch(upstream+'/_test/status')).json();const owner=await profile('owner'),member=await profile('member');
 const created=await accepted(owner.kernel.executeStructureIntent({action:'structure.workspace.create',idempotency_key:'parent-workspace',body:{name:'Durable preparation acceptance'}})),workspace=created.workspace_id;
 const manifest={name:'parent-note',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],initial_state:{},record_schemas:{note:{type:'object',fields:{status:'string'},required:['status'],max_bytes:256}},actions:[{id:'post',reads:[],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[{op:'eq',left:{from:'literal',value:1},right:{from:'literal',value:1}}],effects:[{op:'append',schema:'note',value:{from:'literal',value:{status:'POSTED'}},relations:[]}]}]}]};
 const adopted=await accepted(owner.kernel.executeStructureIntent({action:'structure.adopt',workspace_id:workspace,body:{manifest,bootstrap_grant:{actions:['post']}}}));
 stage='plaintext-preparation';const text='Synthetic secret retained only in encrypted parent plan';
 const intent={action:'structure.action',workspace_id:workspace,instance_id:adopted.instance_id,protocol_digest:adopted.protocol_digest,expected_instance_revision:1,idempotency_key:'body-once',body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text}]};
 gate=true;const bodyPending=await pending(owner.kernel.executeStructureIntent(intent));
 let page=await owner.kernel.pendingPage();assert.ok(page.preparations.items.some(i=>i.command_id===bodyPending.command_id));assert.equal(page.items.length,0);
 const bodySelection=selection(owner,bodyPending.command_id);
 assert.equal(JSON.parse((await exec(python,['tests/installed-structure-parent.py','page',bodySelection])).stdout).found_preparation,true);
 const pageOptions=join(state,'page-options.json');writeFileSync(pageOptions,'{}');
 const cliPage=JSON.parse((await exec(cli,['kernel','pending-page',origin,owner.journal,owner.identity,pageOptions,'--allow-loopback-http'])).stdout);assert.ok(cliPage.preparations.items.some(i=>i.command_id===bodyPending.command_id));
 assert.ok(!readFileSync(owner.journal).includes(Buffer.from(text)));try{assert.ok(!readFileSync(owner.journal+'-wal').includes(Buffer.from(text)));}catch(e){if(e.code!=='ENOENT')throw e;}
 await assert.rejects(owner.kernel.executeStructureIntent({...intent,plaintext_contents:[{record_index:0,text:'Changed private input'}]}),e=>e.code==='STATE_CONFLICT');
 gate=false;for(const res of active)res.destroy();
 stage='python-parent-resume';const bodyResult=JSON.parse((await exec(python,['tests/installed-structure-parent.py','resume',bodySelection])).stdout);assert.equal(bodyResult.command_id,bodyPending.command_id);assert.ok(bodyResult.record_id);
 page=await owner.kernel.pendingPage();assert.equal(page.preparations.items.length,0);assert.equal(page.items.length,0);
 stage='known-business-outcome-before-prerequisites';gate=true;let before=contexts;const repeated=await accepted(owner.kernel.executeStructureIntent(intent));assert.equal(repeated.command_id,bodyPending.command_id);assert.equal(contexts,before);gate=false;
 stage='approval-preparation';const request=await member.kernel.requestAccess({workspace_id:workspace,label:'Parent recovery member'}),approval={workspace_id:workspace,request_jws:request.request_jws,deliver_content_keys:false};
 gate=true;const accessPending=await pending(owner.kernel.authorizeAccess(approval));
 page=await owner.kernel.pendingPage();assert.equal(page.preparations.items[0].kind,'ACCESS');
 gate=false;for(const res of active)res.destroy();
 stage='cli-parent-approval-resume';const granted=JSON.parse((await exec(cli,['kernel','resume-intent',origin,owner.journal,owner.identity,accessPending.command_id,'--allow-loopback-http'])).stdout);assert.equal(granted.state,'ACCEPTED');assert.equal(granted.result.command_id,accessPending.command_id);
 gate=true;before=contexts;const again=await accepted(owner.kernel.authorizeAccess(approval));assert.equal(again.command_id,accessPending.command_id);assert.equal(contexts,before);gate=false;
 const memberRead=await accepted(member.kernel.executeStructureIntent({action:'structure.records.read',workspace_id:workspace,instance_id:adopted.instance_id,protocol_digest:adopted.protocol_digest,body:{limit:32}}));assert.equal(memberRead.structure.records.length,1);
 const final=await(await fetch(upstream+'/_test/status')).json();assert.equal(final.journalRequests,baseline.journalRequests);assert.equal(journals,0);
 const result={status:'PASS',native_encrypted_preparation:true,preparation_timeout_is_resumable:true,body_recovered_by_installed_python:true,approval_recovered_by_installed_cli:true,offline_preparation_lists_node_python_cli:true,changed_input_rejected:true,known_outcome_skips_prerequisites:true,single_business_record:true,journal_requests:0};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}catch(error){console.error(JSON.stringify({stage,name:error.name,code:error.code,message:error.message}));process.exitCode=1;}
finally{gate=false;for(const res of active)res.destroy();proxy.closeAllConnections();await new Promise(r=>proxy.close(r));}
