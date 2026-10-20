// Real current TypeScript Owner -> selected native executable. Synthetic only.
// No production access; all source identities stay in the protected output root.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,cpSync,renameSync,chmodSync} from 'node:fs';
import {generateKeyPairSync} from 'node:crypto';
import {execFile as callbackExecFile} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(callbackExecFile);
const [referenceArg,cliArg,outArg,baselineArg]=process.argv.slice(2);
assert(referenceArg&&cliArg&&outArg,'reference checkout, native executable and fresh protected output required');
const reference=resolve(referenceArg),cli=resolve(cliArg),out=resolve(outArg);
mkdirSync(out,{mode:0o700});
const require=createRequire(join(reference,'package.json'));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server')));
const load=name=>import(pathToFileURL(join(reference,'dist-workspace/src',name+'.js')));
const {openKernel,WorkspaceKernel}=await load('workspace-kernel');
const {createWorkspaceControlApp}=await load('workspace-http');
const {SecureAgentClient}=await load('workspace-secure-agent');
const {secureToken,secureHash}=await load('workspace-secure-client');
const db=openKernel(join(out,'control.sqlite'),'owner-guard-migration');
const kernel=new WorkspaceKernel(db,'owner-guard-migration',Buffer.alloc(32,71));
const app=createWorkspaceControlApp(kernel);let posts=0;
const server=serve({hostname:'127.0.0.1',port:0,fetch:(req,env,ctx)=>{
 if(req.method==='POST'&&new URL(req.url).pathname.endsWith('/commits'))posts++;
 return app.fetch(req,env,ctx);
}});
await new Promise(r=>server.once('listening',r));
const origin='http://127.0.0.1:'+server.address().port;
const source=join(out,'source');mkdirSync(source,{mode:0o700});
const pem=join(source,'owner.pem'),state=join(source,'agent.state'),intentDb=join(source,'intents.sqlite');
const {privateKey}=generateKeyPairSync('ed25519');writeFileSync(pem,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
let agent;const result={status:'RUNNING',synthetic_only:true,cases:[],workflow_acceptance:'SCRIPTED_NOT_NATURAL_AGENT_TRIAL'};
async function command(args,expect=true,executable=cli){
 let run;try{run=await execFile(executable,args,{timeout:90000,maxBuffer:8*1024*1024});}
 catch(e){run=e;}
 const bytes=run.stdout?.trim()||run.stderr?.trim();
 assert(bytes,'Native command returned no JSON: '+args[1]+' exit='+String(run.code));
 const parsed=JSON.parse(bytes),response=Object.hasOwn(parsed,'code')?{ok:false,error:parsed}:{ok:true,value:parsed};
 writeFileSync(join(out,'command-'+String(result.command_count=(result.command_count??0)+1).padStart(3,'0')+'.json'),
  JSON.stringify({verb:args[1],response},null,2)+'\n',{mode:0o600});
 if(expect)assert(response.ok,JSON.stringify(response));return response;
}
function snapshot(name,value){const dir=join(out,name);mkdirSync(dir,{mode:0o700});
 cpSync(pem,join(dir,'owner.pem'));cpSync(intentDb,join(dir,'intents.sqlite'));chmodSync(join(dir,'intents.sqlite'),0o600);
 writeFileSync(join(dir,'agent.state'),JSON.stringify(value),{mode:0o600});return dir;}
function inputs(name,dir,metadata){const config=join(out,name+'-config.json'),input=join(out,name+'-input.json');
 const native=join(out,name+'-native');mkdirSync(native,{mode:0o700});
 writeFileSync(config,JSON.stringify({origin,state_dir:native,allow_loopback_http:true}),{mode:0o600});
 writeFileSync(input,JSON.stringify({workspace_id:metadata.workspace,protected_ts_state_path:join(dir,'agent.state'),
  protected_ts_intent_db_path:join(dir,'intents.sqlite'),protected_owner_pkcs8_path:join(dir,'owner.pem'),
  expected_owner_actor_id:metadata.actor,expected_owner_key_id:metadata.key}),{mode:0o600});
 return {config,input,native};}
try{
 agent=await SecureAgentClient.open({baseUrl:origin,privateKey,statePath:state,intentDbPath:intentDb});
 const created=await agent.create('Owner migration regression','PRIVATE',{structure:true});
 let journal=await agent.journal(created.workspaceId);const discovery=agent.transport.discovery;
 await agent.enableGuardTime(created.workspaceId,{expectedPolicyHash:journal.checkpoint.policy_hash,
  audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW'});
 const empty=structuredClone(agent.state);
 journal=await agent.journal(created.workspaceId);
 const instance=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki');assert(instance);
 const operation=secureToken(),canary='Original confirmed timed action';
 await agent.action(created.workspaceId,instance.id,'wiki.create',{title:canary,body:'Verified migration body'},[],operation);
 const completed=structuredClone(agent.state);assert.equal(Object.values(completed.guard_time_action_intents)[0].status,'CONFIRMED');
 const pendingOperation=secureToken(),request=agent.request.bind(agent);let blocked=false;
 agent.request=async(path,options)=>{if(!blocked&&path.endsWith('/commits')&&options?.method==='POST'){
  blocked=true;throw Error('TEST_STOP_BEFORE_POST');}return request(path,options);};
 await assert.rejects(agent.action(created.workspaceId,instance.id,'wiki.create',{title:'Recovered timed action',body:'Same operation'},[],pendingOperation),/TEST_STOP_BEFORE_POST/);
 agent.request=request;assert(blocked);
 const pending=structuredClone(agent.state),beforeRecovery=posts;
 const metadata={workspace:created.workspaceId,actor:agent.identity.actorId,key:agent.identity.keyId};
 await agent.close();agent=null;
 if(process.env.PEERWORK_MIGRATION_PYTHON&&process.env.PEERWORK_MIGRATION_NODE_CONSUMER){
  for(const facade of ['python','node'])for(const [name,original,error] of [['completed',completed,null],['pending',pending,'SOURCE_GUARD_TIME_PENDING']]){
   const dir=snapshot('facade-'+facade+'-'+name,original),bound=inputs(facade+'-'+name,dir,metadata),before=posts;
   const runner=new URL('owner-migration-facade-consumer.'+(facade==='python'?'py':'mjs'),import.meta.url);
   const executable=facade==='python'?process.env.PEERWORK_MIGRATION_PYTHON:process.execPath;
   const args=facade==='python'?[runner.pathname,bound.config,bound.input]:[runner.pathname,process.env.PEERWORK_MIGRATION_NODE_CONSUMER,bound.config,bound.input];
   args.push('--remove-synthetic-source');
   const ran=await execFile(executable,args,{timeout:90000,maxBuffer:1024*1024});const value=JSON.parse(ran.stdout);
   if(error)assert.equal(value.code,error);else{assert.equal(value.status,'ATTACHED');assert.equal(value.workspace_id,metadata.workspace);}
   assert.equal(posts,before);result.cases.push({name:facade+'-'+name,status:'PASS',additional_commit_posts:0});
  }
 }
 for(const [name,original,error] of [['empty',empty,null],['completed',completed,null],['pending',pending,'SOURCE_GUARD_TIME_PENDING']]){
  const dir=snapshot('legacy-'+name,original),bound=inputs(name,dir,metadata),before=posts;
  if(baselineArg&&name==='completed'){
   const baseline=inputs('published014-baseline',dir,metadata);
   const refused=await command(['secure','owner-attach',baseline.config,baseline.input],false,resolve(baselineArg));
   assert.equal(refused.error.code,'SOURCE_UNRESOLVED');assert.equal(posts,before);
   result.baseline={version:'0.1.4',same_real_completed_source:'SOURCE_UNRESOLVED',additional_commit_posts:0};
  }
  const attached=await command(['secure','owner-attach',bound.config,bound.input],!error);
  if(error){assert.equal(attached.error.code,error);const history=await command(['secure','owner-attachments',bound.config]);assert.equal(history.value.length,0);}
  else{
   assert.equal(attached.value.status,'ATTACHED');renameSync(dir,dir+'-removed');
   const resumed=await command(['secure','owner-attach-resume',bound.config,attached.value.attach_id]);assert.equal(resumed.value.status,'ATTACHED');
   const read=await command(['secure','owner-read',bound.config,metadata.workspace]);
   assert.equal(read.value.workspace_id,metadata.workspace);
   if(name==='completed')assert(JSON.stringify(read.value).includes(canary));
  }
  assert.equal(posts,before);result.cases.push({name,status:'PASS',additional_commit_posts:posts-before});
 }
 for(const kind of ['body','body-rehashed','proof','foreign-workspace']){
  const modified=structuredClone(completed),row=Object.values(modified.guard_time_action_intents)[0];
  if(kind==='body'||kind==='body-rehashed')row.body.title='tampered';
  if(kind==='body-rehashed')row.input_hash=await secureHash(Object.fromEntries(
   ['workspace_id','operation_id','actor_id','action_id','instance_id','body','exact_refs'].map(k=>[k,row[k]])));
  if(kind==='proof')row.proof.payload.admitted_at_ms++;
  if(kind==='foreign-workspace')row.workspace_id=secureToken();
  const dir=snapshot('legacy-bad-'+kind,modified),bound=inputs('bad-'+kind,dir,metadata),before=posts;
  const response=await command(['secure','owner-attach',bound.config,bound.input],false);assert.equal(response.error.code,'SOURCE_GUARD_TIME_INVALID');
  const history=await command(['secure','owner-attachments',bound.config]);assert.equal(history.value.length,0);assert.equal(posts,before);
  result.cases.push({name:kind,status:'PASS',additional_commit_posts:0});
 }
 agent=await SecureAgentClient.open({baseUrl:origin,privateKey,statePath:state,intentDbPath:intentDb});
 const recovered=await agent.resumeGuardTimeAction(metadata.workspace,pendingOperation);
 assert.equal(posts,beforeRecovery+1);const afterRecovery=posts;
 await agent.resumeGuardTimeAction(metadata.workspace,pendingOperation);assert.equal(posts,afterRecovery);
 const recoveredState=structuredClone(agent.state);await agent.close();agent=null;
 const dir=snapshot('legacy-recovered',recoveredState),bound=inputs('recovered',dir,metadata);
 const attached=await command(['secure','owner-attach',bound.config,bound.input]);assert.equal(attached.value.status,'ATTACHED');
 renameSync(dir,dir+'-removed');
 const read=await command(['secure','owner-read',bound.config,metadata.workspace]);assert(JSON.stringify(read.value).includes('Recovered timed action'));
 assert.equal(read.value.sequence,recovered.checkpoint.sequence);assert.equal(posts,afterRecovery);
 result.cases.push({name:'original-operation-recovery-then-migration',status:'PASS',recovery_commit_posts:1,migration_commit_posts:0});
 const actionId=secureToken(),actionFile=join(out,'native-action.json');
 writeFileSync(actionFile,JSON.stringify({command_id:actionId,instance_id:instance.id,action_id:'wiki.create',
  body_json:JSON.stringify({title:'Native after source removal',body:'Existing Owner retained'})}),{mode:0o600});
 let submitted=await command(['secure','owner-private-action-submit',bound.config,metadata.workspace,actionFile,'--operation-id',secureToken()]);
 if(submitted.value.status!=='ACCEPTED')submitted=await command(['secure','owner-private-action-status',bound.config,metadata.workspace,actionId]);
 assert.equal(submitted.value.status,'ACCEPTED');const afterNative=posts;
 const retried=await command(['secure','owner-private-action-retry',bound.config,metadata.workspace,actionId]);
 assert.equal(retried.value.status,'ACCEPTED');assert.equal(posts,afterNative);
 const finalRead=await command(['secure','owner-read',bound.config,metadata.workspace]);assert(JSON.stringify(finalRead.value).includes('Native after source removal'));
 result.cases.push({name:'native-write-reconcile-after-source-removal',status:'PASS',accepted_retry_new_commit_posts:0});
 result.status='PASS';
}catch(e){result.status='FAIL';result.error={name:e.name,message:String(e.message).slice(0,1600)};process.exitCode=1;}
finally{await agent?.close();server.closeAllConnections();await new Promise(r=>server.close(r));db.close();
 writeFileSync(join(out,'verification.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(result));}
