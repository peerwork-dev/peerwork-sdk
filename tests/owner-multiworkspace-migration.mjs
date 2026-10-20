// Same Owner: preserve workspace A while attaching and exercising workspace B.
// All keys and workspaces are freshly created test data on an isolated service.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,cpSync,renameSync,chmodSync,readFileSync,readdirSync,statSync} from 'node:fs';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {execFile as execCallback} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(execCallback),[referenceArg,cliArg,outArg,baselineArg]=process.argv.slice(2);
assert(referenceArg&&cliArg&&outArg);const reference=resolve(referenceArg),cli=resolve(cliArg),out=resolve(outArg);
mkdirSync(out,{mode:0o700});const require=createRequire(join(reference,'package.json'));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server')));
const load=n=>import(pathToFileURL(join(reference,'dist-workspace/src',n+'.js')));
const {openKernel,WorkspaceKernel}=await load('workspace-kernel');
const {createWorkspaceControlApp}=await load('workspace-http');
const {SecureAgentClient}=await load('workspace-secure-agent');const {secureToken}=await load('workspace-secure-client');
const db=openKernel(join(out,'control.sqlite'),'coordination-migration');const kernel=new WorkspaceKernel(db,'coordination-migration',Buffer.alloc(32,83));
const app=createWorkspaceControlApp(kernel);let posts=0;const reads=[];
const server=serve({hostname:'127.0.0.1',port:0,fetch:(req,env,ctx)=>{if(req.method==='POST')posts++;if(req.method==='GET')reads.push(new URL(req.url).pathname);return app.fetch(req,env,ctx);}});
await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port;
const clients=[];const report={status:'RUNNING',cases:[],synthetic_only:true,workflow_acceptance:'SCRIPTED_NOT_NATURAL_AGENT_TRIAL'};let count=0;
async function open(name){const dir=join(out,name);mkdirSync(dir,{mode:0o700});const privateKey=generateKeyPairSync('ed25519').privateKey;
 const pem=join(dir,'owner.pem'),state=join(dir,'agent.state'),intents=join(dir,'intents.sqlite');
 writeFileSync(pem,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 const agent=await SecureAgentClient.open({baseUrl:origin,privateKey,statePath:state,intentDbPath:intents});clients.push(agent);return {agent,pem,state,intents};}
async function command(args,expect=true,executable=cli){let run;try{run=await execFile(executable,args,{timeout:90000,maxBuffer:8*1024*1024});}catch(e){run=e;}
 const bytes=run.stdout?.trim()||run.stderr?.trim();assert(bytes,'No JSON from '+args[1]);const parsed=JSON.parse(bytes);
 const value=Object.hasOwn(parsed,'code')?{ok:false,error:parsed}:{ok:true,value:parsed};
 writeFileSync(join(out,'command-'+String(++count).padStart(3,'0')+'.json'),JSON.stringify({verb:args[1],response:value},null,2)+'\n',{mode:0o600});
 if(expect)assert(value.ok,JSON.stringify(value));return value;}
try{
 const owner=await open('original-owner'),member=await open('member');const agent=owner.agent;
 const {workspaceId:workspace}=await agent.create('Coordination migration proof','PRIVATE',{structure:true,coordination:true,coordination_version:2});
 await agent.publishIdentity();await member.agent.publishIdentity();await agent.trustIdentity(member.agent.identity.actorId);await member.agent.trustIdentity(agent.identity.actorId);
 const journal=await agent.journal(workspace),coord=journal.policy.payload.structure.coordination;
 const offer=await agent.inviteActor(workspace,member.agent.identity.actorId,[{instance_id:coord.instance_id,
  actions:['coordination.send','coordination.reply','coordination.ack','coordination.disposition','coordination.cancel','coordination.remind'],
  protocol_roles:['COLLABORATOR'],capabilities:['COORDINATE']}],'Synthetic member');
 await member.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');await agent.deliverAdmission(offer.payload.invite_id);await member.agent.receiveAdmission(offer.payload.invite_id);
 const items=[];
 for(let i=0;i<21;i++){const sent=await member.agent.sendCoordination(workspace,[agent.identity.actorId],'Synthetic task '+i);items.push(sent.items.find(v=>v.recipient===agent.identity.actorId));assert(items.at(-1));}
 async function stopAfterCommitted(call){const original=agent.action.bind(agent);let stopped=false;
  agent.action=async(...args)=>{await original(...args);stopped=true;throw Error('TEST_AFTER_SIGNED_COMMIT');};
  try{await assert.rejects(call(),/TEST_AFTER_SIGNED_COMMIT/);}finally{agent.action=original;}assert(stopped);}
 for(const item of items.slice(0,2)){await stopAfterCommitted(()=>agent.acknowledge(workspace,item.id));
  await stopAfterCommitted(()=>agent.disposition(workspace,item.id,'IN_PROGRESS',0,'Synthetic accepted work'));}
 for(const item of items.slice(2))await agent.acknowledge(workspace,item.id);
 const original=agent.action.bind(agent),orphanId=secureToken();agent.action=async()=>{throw Error('TEST_BEFORE_PACKET');};
 try{await assert.rejects(agent.sendCoordination(workspace,[member.agent.identity.actorId],'Unsent synthetic send',{request_id:orphanId}),/TEST_BEFORE_PACKET/);}finally{agent.action=original;}
 const {workspaceId:workspaceB}=await agent.create('Second existing workspace','PRIVATE',{structure:true});
 let bj=await agent.journal(workspaceB);const bwiki=bj.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki');
 await agent.action(workspaceB,bwiki.id,'wiki.create',{title:'Existing canary ticket',body:'Preserve this ticket'});
 const aj=await agent.journal(workspace),discovery=agent.transport.discovery;
 await agent.enableGuardTime(workspace,{expectedPolicyHash:aj.checkpoint.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW'});
 const aj2=await agent.journal(workspace),awiki=aj2.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki');
 await agent.action(workspace,awiki.id,'wiki.create',{title:'Completed timed A action',body:'A history'},[],secureToken());
 await agent.journal(workspace);const state=structuredClone(agent.state);
 assert.equal(Object.keys(state.inbox_receipts).length,21);
 const request=agent.request.bind(agent);agent.request=async(path,options)=>{if(path.endsWith('/commits')&&options?.method==='POST')throw Error('TEST_BEFORE_POST');return request(path,options);};
 try{await assert.rejects(agent.action(workspace,awiki.id,'wiki.create',{title:'Accepted A response retained',body:'Recover with original operation'},[],secureToken()),/TEST_BEFORE_POST/);}finally{agent.request=request;}
 const verification=agent.verifyGuardTimeCommitPost.bind(agent);agent.verifyGuardTimeCommitPost=async()=>{throw Error('TEST_AFTER_POST_BEFORE_GUARD_READBACK');};
 const [pendingId,packet]=Object.entries(agent.state.pending)[0];
 try{await assert.rejects(agent.post(packet.path,packet.body,pendingId),/TEST_AFTER_POST_BEFORE_GUARD_READBACK/);}finally{agent.verifyGuardTimeCommitPost=verification;}
 const pendingState=structuredClone(agent.state);assert.equal(Object.keys(pendingState.pending).length,1);assert.equal(Object.keys(pendingState.guard_time_post_responses).length,1);
assert.equal(Object.keys(state.coordination_intents).length,5);assert.deepEqual(Object.keys(state.pending),[]);
 const actor=agent.identity.actorId,key=agent.identity.keyId,orphanKey=workspace+'.send.'+orphanId;
 await agent.close();await member.agent.close();
 function snapshot(name,value=state){const dir=join(out,name);mkdirSync(dir,{mode:0o700});cpSync(owner.pem,join(dir,'owner.pem'));cpSync(owner.intents,join(dir,'intents.sqlite'));chmodSync(join(dir,'intents.sqlite'),0o600);writeFileSync(join(dir,'agent.state'),JSON.stringify(value),{mode:0o600});return dir;}
 function bind(name,dir,target=workspace,nativeName=name){const config=join(out,name+'-config.json'),input=join(out,name+'-input.json'),native=join(out,nativeName+'-native');mkdirSync(native,{mode:0o700,recursive:true});
  writeFileSync(config,JSON.stringify({origin,state_dir:native,allow_loopback_http:true}),{mode:0o600});
  writeFileSync(input,JSON.stringify({workspace_id:target,protected_ts_state_path:join(dir,'agent.state'),protected_owner_pkcs8_path:join(dir,'owner.pem'),protected_ts_intent_db_path:join(dir,'intents.sqlite'),expected_owner_actor_id:actor,expected_owner_key_id:key}),{mode:0o600});return {config,input};}
 const before=posts;
 const digest=path=>createHash('sha256').update(readFileSync(path)).digest('hex');
 function tree(dir){return Object.fromEntries(readdirSync(dir,{recursive:true}).filter(name=>statSync(join(dir,name)).isFile()).sort().map(name=>[name,digest(join(dir,name))]));}
 function sourceDigests(dir){return ['agent.state','owner.pem','intents.sqlite'].map(name=>digest(join(dir,name)));}
 const dir=snapshot('mixed-source'),a=bind('native-a',dir),b=bind('native-b',dir,workspaceB,'native-a');
 const attachedA=(await command(['secure','owner-attach',a.config,a.input],true,baselineArg?resolve(baselineArg):cli)).value;
 assert.equal(attachedA.status,'ATTACHED');assert.equal(attachedA.coordination_intents.length,5);
 const aRead=(await command(['secure','owner-read',a.config,workspace])).value;
 const identity=join(out,'native-a-native','identity.state'),aDir=join(out,'native-a-native','workspaces',workspace);
 const identityBefore=digest(identity),aFiles=tree(aDir),sourceBefore=sourceDigests(dir);
 if(baselineArg){const rejected=await command(['secure','owner-attach',b.config,b.input],false,resolve(baselineArg));assert.equal(rejected.error.code,'SOURCE_UNRESOLVED');report.baseline='EXACT_PUBLISHED_016_MULTIWORKSPACE_REFUSAL';}
 const readStart=reads.length;const attachedB=(await command(['secure','owner-attach',b.config,b.input])).value;
 assert.equal(attachedB.status,'ATTACHED');assert.deepEqual(attachedB.coordination_intents,[]);
 assert(!reads.slice(readStart).some(path=>path.includes('/workspaces/'+workspace+'/')),'B attachment queried A journal');
 assert.deepEqual(tree(aDir),aFiles);assert.equal(digest(identity),identityBefore);assert.deepEqual(sourceDigests(dir),sourceBefore);
 assert.equal((await command(['secure','owner-attach',b.config,b.input])).value.attach_id,attachedB.attach_id);
 const history=(await command(['secure','owner-attachments',b.config])).value;assert.equal(history.length,2);
 assert.deepEqual(history.find(x=>x.workspace_id===workspace),attachedA);
 assert.deepEqual((await command(['secure','owner-read',a.config,workspace])).value,aRead);
 assert(JSON.stringify((await command(['secure','owner-read',b.config,workspaceB])).value).includes('Existing canary ticket'));
 assert.equal(posts,before);report.cases.push({name:'existing-A-21-receipts-5-markers-attach-B-retry-fresh-A-B',status:'PASS',mutation_posts:0,A_profile_unchanged:true,identity_unchanged:true,source_unchanged:true,A_journal_reads_during_B_attach:0});
 const otherPending=structuredClone(pendingState);otherPending.workspaces[workspace].pending_keyring=structuredClone(otherPending.workspaces[workspace].keyring);
 otherPending.field_policy_intents={[workspace]:'a'.repeat(64)};
 const pendingDir=snapshot('foreign-pending-source',otherPending),pbound=bind('foreign-pending',pendingDir,workspaceB),pendingHashes=sourceDigests(pendingDir);
 assert.equal((await command(['secure','owner-attach',pbound.config,pbound.input])).value.status,'ATTACHED');
 assert.deepEqual(sourceDigests(pendingDir),pendingHashes);assert.equal(posts,before);report.cases.push({name:'foreign-A-signed-pending-guard-response-keyring-preserved',status:'PASS',mutation_posts:0});
 for(const kind of ['receipt-scope-conflict','marker-scope-conflict','unknown-pending','identity-pending','selected-B-invalid-marker','guard-scope-conflict','response-scope-conflict','selected-B-guard-pending']){
  const modified=structuredClone(state);let expected='SOURCE_SCOPE_CONFLICT';
  if(kind==='receipt-scope-conflict')Object.values(modified.inbox_receipts)[0].workspace_id=workspaceB;
  if(kind==='marker-scope-conflict'){const key=Object.keys(modified.coordination_intents).find(k=>k.includes('.coordination.ack.'));const changed=key.replace('.coordination.ack.'+workspace,'.coordination.ack.'+workspaceB);modified.coordination_intents[changed]=modified.coordination_intents[key];delete modified.coordination_intents[key];}
  if(kind==='unknown-pending'){modified.pending[secureToken()]={path:'/api/workspace/v1/secure/identity-keys',body:{}};expected='SOURCE_SCOPE_UNRESOLVED';}
  if(kind==='identity-pending'){modified.identity_key_intents={unknown:{state:'PREPARED'}};expected='SOURCE_UNRESOLVED';}
  if(kind==='selected-B-invalid-marker'){modified.coordination_intents[workspaceB+'.send.'+secureToken()]='invalid';expected='SOURCE_COORDINATION_INVALID';}
  if(kind==='response-scope-conflict'){modified.pending=structuredClone(pendingState.pending);modified.guard_time_post_responses=structuredClone(pendingState.guard_time_post_responses);Object.values(modified.guard_time_post_responses)[0].checkpoint.workspace_id=workspaceB;}
  if(kind==='guard-scope-conflict')Object.values(modified.guard_time_action_intents)[0].workspace_id=workspaceB;
  if(kind==='selected-B-guard-pending'){const operation=secureToken();modified.guard_time_action_intents[JSON.stringify([workspaceB,operation])]={workspace_id:workspaceB,operation_id:operation,actor_id:actor,status:'PREPARING'};expected='SOURCE_GUARD_TIME_PENDING';}
  const badDir=snapshot(kind+'-source',modified),bound=bind(kind,badDir,workspaceB),hashes=sourceDigests(badDir);
  assert.equal((await command(['secure','owner-attach',bound.config,bound.input],false)).error.code,expected);
  assert.deepEqual((await command(['secure','owner-attachments',bound.config])).value,[]);assert.deepEqual(sourceDigests(badDir),hashes);assert.equal(posts,before);report.cases.push({name:kind,status:'PASS',mutation_posts:0});
 }
 if(process.env.PEERWORK_MIGRATION_PYTHON&&process.env.PEERWORK_MIGRATION_NODE_CONSUMER){
  const meta=join(out,'lease-metadata.json');writeFileSync(meta,JSON.stringify({workspace_a:workspace,workspace_b:workspaceB,audience:discovery.audience,service_key:discovery.receipt_public_key}),{mode:0o600});
  for(const facade of ['node','python'].filter(f=>!process.env.PEERWORK_MIGRATION_FACADE||f===process.env.PEERWORK_MIGRATION_FACADE)){
   const facadeDir=snapshot('facade-'+facade),fa=bind('facade-'+facade+'-a',facadeDir,workspace,'facade-'+facade),fb=bind('facade-'+facade+'-b',facadeDir,workspaceB,'facade-'+facade);
   await command(['secure','owner-attach',fa.config,fa.input],true,baselineArg?resolve(baselineArg):cli);const expected=sourceDigests(facadeDir),pre=posts;
   const runner=new URL('owner-multiworkspace-consumer.'+(facade==='python'?'py':'mjs'),import.meta.url);
   const args=facade==='python'?[runner.pathname,fb.config,fb.input,meta]:[runner.pathname,process.env.PEERWORK_MIGRATION_NODE_CONSUMER,fb.config,fb.input,meta];
   const ran=await execFile(facade==='python'?process.env.PEERWORK_MIGRATION_PYTHON:process.execPath,args,{timeout:180000,maxBuffer:1048576});const value=JSON.parse(ran.stdout);assert.equal(value.status,'PASS');
   if(facade==='node')assert.equal(posts,pre);else assert(value.lease&&value.lease.generation===2);
   assert.deepEqual(sourceDigests(facadeDir+'-removed'),expected);report.cases.push({name:facade+'-installed-multiworkspace'+(facade==='python'?'-guard-enable-real-bounded-leases':''),status:'PASS',result:value});
  }
 }
 report.status='PASS';report.A_receipts=21;report.A_markers=5;report.source_scope='workspace-selected';
}catch(error){if(error.stderr)writeFileSync(join(out,'consumer-error.stderr'),error.stderr,{mode:0o600});report.status='FAIL';report.error={name:error.name,message:String(error.message).slice(0,1800),stack:String(error.stack).split('\n').slice(0,8)};process.exitCode=1;}
finally{for(const client of clients)try{await client.close();}catch{}server.closeAllConnections();await new Promise(r=>server.close(r));db.close();writeFileSync(join(out,'verification.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(report));}
