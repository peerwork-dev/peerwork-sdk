// Reproduce two completed ACKs, two completed dispositions and a packetless send.
// All keys and workspaces are freshly created test data on an isolated service.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,cpSync,renameSync,chmodSync} from 'node:fs';
import {generateKeyPairSync} from 'node:crypto';
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
const app=createWorkspaceControlApp(kernel);let posts=0;
const server=serve({hostname:'127.0.0.1',port:0,fetch:(req,env,ctx)=>{if(req.method==='POST'&&new URL(req.url).pathname.endsWith('/commits'))posts++;return app.fetch(req,env,ctx);}});
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
 for(let i=0;i<2;i++){const sent=await member.agent.sendCoordination(workspace,[agent.identity.actorId],'Synthetic task '+i);items.push(sent.items.find(v=>v.recipient===agent.identity.actorId));assert(items.at(-1));}
 async function stopAfterCommitted(call){const original=agent.action.bind(agent);let stopped=false;
  agent.action=async(...args)=>{await original(...args);stopped=true;throw Error('TEST_AFTER_SIGNED_COMMIT');};
  try{await assert.rejects(call(),/TEST_AFTER_SIGNED_COMMIT/);}finally{agent.action=original;}assert(stopped);}
 for(const item of items){await stopAfterCommitted(()=>agent.acknowledge(workspace,item.id));
  await stopAfterCommitted(()=>agent.disposition(workspace,item.id,'IN_PROGRESS',0,'Synthetic accepted work'));}
 const original=agent.action.bind(agent),orphanId=secureToken();agent.action=async()=>{throw Error('TEST_BEFORE_PACKET');};
 try{await assert.rejects(agent.sendCoordination(workspace,[member.agent.identity.actorId],'Unsent synthetic send',{request_id:orphanId}),/TEST_BEFORE_PACKET/);}finally{agent.action=original;}
 await agent.journal(workspace);const state=structuredClone(agent.state);assert.equal(Object.keys(state.coordination_intents).length,5);assert.deepEqual(Object.keys(state.pending),[]);
 const actor=agent.identity.actorId,key=agent.identity.keyId,orphanKey=workspace+'.send.'+orphanId;
 await agent.close();await member.agent.close();
 function snapshot(name,value=state){const dir=join(out,name);mkdirSync(dir,{mode:0o700});cpSync(owner.pem,join(dir,'owner.pem'));cpSync(owner.intents,join(dir,'intents.sqlite'));chmodSync(join(dir,'intents.sqlite'),0o600);writeFileSync(join(dir,'agent.state'),JSON.stringify(value),{mode:0o600});return dir;}
 function bind(name,dir){const config=join(out,name+'-config.json'),input=join(out,name+'-input.json'),native=join(out,name+'-native');mkdirSync(native,{mode:0o700});
  writeFileSync(config,JSON.stringify({origin,state_dir:native,allow_loopback_http:true}),{mode:0o600});
  writeFileSync(input,JSON.stringify({workspace_id:workspace,protected_ts_state_path:join(dir,'agent.state'),protected_owner_pkcs8_path:join(dir,'owner.pem'),protected_ts_intent_db_path:join(dir,'intents.sqlite'),expected_owner_actor_id:actor,expected_owner_key_id:key}),{mode:0o600});return {config,input};}
 const before=posts;
 if(baselineArg){const dir=snapshot('baseline-source'),bound=bind('baseline',dir);const rejected=await command(['secure','owner-attach',bound.config,bound.input],false,resolve(baselineArg));assert.equal(rejected.error.code,'SOURCE_UNRESOLVED');report.baseline='EXACT_PRIOR_CANDIDATE_REPRODUCED';}
 for(const name of ['malformed-hash','foreign-workspace','pending-packet']){
  const value=structuredClone(state);
  if(name==='malformed-hash')value.coordination_intents[orphanKey]='invalid';
  if(name==='foreign-workspace'){value.coordination_intents[secureToken()+'.send.'+orphanId]=value.coordination_intents[orphanKey];delete value.coordination_intents[orphanKey];}
  if(name==='pending-packet')value.pending[secureToken()]={path:'/original/saved',body:{}};
  const dir=snapshot(name+'-source',value),bound=bind(name,dir),rejected=await command(['secure','owner-attach',bound.config,bound.input],false);
  assert.equal(rejected.error.code,name==='pending-packet'?'SOURCE_COORDINATION_PENDING':name==='foreign-workspace'?'SOURCE_SCOPE_UNRESOLVED':'SOURCE_COORDINATION_INVALID');
  assert.deepEqual((await command(['secure','owner-attachments',bound.config])).value,[]);assert.equal(posts,before);report.cases.push({name,status:'PASS',new_commit_posts:0});
 }
 const dir=snapshot('valid-source'),bound=bind('valid',dir),attached=(await command(['secure','owner-attach',bound.config,bound.input])).value;
 assert.equal(attached.status,'ATTACHED');const markers=attached.coordination_intents;
 assert.equal(markers.filter(v=>v.status==='ARCHIVED_COMPLETED').length,4);assert.equal(markers.filter(v=>v.status==='RETAINED_UNRESOLVED').length,1);
 assert.equal(markers.find(v=>v.marker_key===orphanKey).status,'RETAINED_UNRESOLVED');
 for(const marker of markers.filter(v=>v.status==='ARCHIVED_COMPLETED')){assert(marker.proof_sequence>0);assert.match(marker.proof_commit_hash,/^[a-f0-9]{64}$/);}
 renameSync(dir,dir+'-removed');const reopened=(await command(['secure','owner-attach-resume',bound.config,attached.attach_id])).value;assert.deepEqual(reopened.coordination_intents,markers);
 const read=(await command(['secure','owner-read',bound.config,workspace])).value;assert.equal(read.workspace_id,workspace);assert.equal(posts,before);
 report.cases.push({name:'four-archived-one-retained-source-removed-reopen',status:'PASS',new_commit_posts:0});
 const selected=markers.find(v=>v.marker_key===orphanKey),file=join(out,'retire.json');
 writeFileSync(file,JSON.stringify({attach_id:attached.attach_id,marker_key:orphanKey,expected_input_hash:'0'.repeat(64)}),{mode:0o600});
 assert.equal((await command(['secure','owner-coordination-marker-retire',bound.config,file],false)).error.code,'ATTACH_CONFLICT');
 const archived=markers.find(v=>v.status==='ARCHIVED_COMPLETED');
 writeFileSync(file,JSON.stringify({attach_id:attached.attach_id,marker_key:archived.marker_key,expected_input_hash:archived.input_hash}),{mode:0o600});
 assert.equal((await command(['secure','owner-coordination-marker-retire',bound.config,file],false)).error.code,'ATTACH_CONFLICT');
 writeFileSync(file,JSON.stringify({attach_id:attached.attach_id,marker_key:orphanKey,expected_input_hash:selected.input_hash}),{mode:0o600});
 for(let i=0;i<2;i++){const retired=(await command(['secure','owner-coordination-marker-retire',bound.config,file])).value;assert.equal(retired.coordination_intents.find(v=>v.marker_key===orphanKey).status,'RETIRED_LOCAL');}
 assert.equal(posts,before);report.cases.push({name:'hash-pinned-local-retire-idempotent',status:'PASS',new_commit_posts:0});
 if(process.env.PEERWORK_MIGRATION_PYTHON&&process.env.PEERWORK_MIGRATION_NODE_CONSUMER){
  for(const facade of ['python','node']){const dir=snapshot('facade-'+facade),bound=bind('facade-'+facade,dir);
   const runner=new URL('owner-migration-facade-consumer.'+(facade==='python'?'py':'mjs'),import.meta.url);
   const args=facade==='python'?[runner.pathname,bound.config,bound.input]:[runner.pathname,process.env.PEERWORK_MIGRATION_NODE_CONSUMER,bound.config,bound.input];
   args.push('--remove-synthetic-source','--check-coordination');const ran=await execFile(facade==='python'?process.env.PEERWORK_MIGRATION_PYTHON:process.execPath,args,{timeout:90000,maxBuffer:1048576});
   const result=JSON.parse(ran.stdout);assert.equal(result.status,'ATTACHED');assert.equal(result.coordination.retired,1);assert.equal(posts,before);report.cases.push({name:facade+'-installed-archive-retain-retire-reopen',status:'PASS',new_commit_posts:0});}
 }
 report.status='PASS';report.archived=4;report.retained_before_explicit_retire=1;report.new_commit_posts=posts-before;
}catch(error){report.status='FAIL';report.error={name:error.name,message:String(error.message).slice(0,1800)};process.exitCode=1;}
finally{for(const client of clients)try{await client.close();}catch{}server.closeAllConnections();await new Promise(r=>server.close(r));db.close();writeFileSync(join(out,'verification.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(report));}
