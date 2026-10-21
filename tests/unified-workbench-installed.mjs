// Installed artifacts against an isolated real product service; synthetic data only.
// Usage: node TEST PRODUCT_WORKTREE INSTALLED_CLI NEW_OUTPUT_DIR
// Env: PEERWORK_WORKBENCH_NODE_CONSUMER, PEERWORK_WORKBENCH_PYTHON,
//      PEERWORK_WORKBENCH_OLD_CLI (released 0.1.8, for a real malformed journal).
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,createPrivateKey} from 'node:crypto';
import {execFile as callback} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(callback),[referenceArg,cliArg,outArg]=process.argv.slice(2);
assert(referenceArg&&cliArg&&outArg,'product, installed CLI and new output directory required');
const nodeRoot=process.env.PEERWORK_WORKBENCH_NODE_CONSUMER||process.env.PEERWORK_MIGRATION_NODE_CONSUMER;
const python=process.env.PEERWORK_WORKBENCH_PYTHON||process.env.PEERWORK_MIGRATION_PYTHON;
const oldCli=process.env.PEERWORK_WORKBENCH_OLD_CLI;
assert(nodeRoot&&python&&oldCli,'all three installed consumers and released old CLI are required');
const reference=resolve(referenceArg),cli=resolve(cliArg),out=resolve(outArg);mkdirSync(out,{mode:0o700});
const sdk=createRequire(join(resolve(nodeRoot),'package.json'))('@peerwork/agent-sdk');
const save=(name,v)=>{const path=join(out,name);writeFileSync(path,JSON.stringify(v),{mode:0o600});return path;};
const started=performance.now();
const report={status:'RUNNING',cases:[],synthetic_only:true,workflow_acceptance:'SCRIPTED_NOT_NATURAL_AGENT_TRIAL'};
const pass=(name,extra={})=>{report.cases.push({name,status:'PASS',elapsed_ms:Math.round(performance.now()-started),...extra});save('verification.json',report);};
const hash=p=>createHash('sha256').update(readFileSync(p)).digest('hex');
const readNativeState=path=>{const bytes=readFileSync(path),magic=Buffer.from('PEERWORK-NATIVE-SECURE-STATE\n1\n');assert(bytes.subarray(0,magic.length).equals(magic),'native protected state header');return JSON.parse(bytes.subarray(magic.length).toString('utf8'));};
let commandNo=0,server,db,requests=0,posts=0,finalizePosts=0,dropFinalize=false,dropped=0,journalInterleave=null;const clients=[],actionPosts=new Map();
async function command(args,{executable=cli,ok=true}={}){
 let run;try{run=await execFile(executable,args,{timeout:180000,maxBuffer:16*1024*1024});}catch(e){run=e;}
 const raw=run.stdout?.trim()||run.stderr?.trim();assert(raw,'empty CLI output');let result;
 try{result=JSON.parse(raw);}catch{throw new Error('CLI did not return JSON: '+raw.slice(0,1000));}
 save('command-'+(++commandNo)+'.json',{verb:args.slice(0,2),exit_code:run.code??0,result});
 if(ok)assert(!result.code&&result.ok!==false,JSON.stringify(result));
 return result.ok===true?result.value:result;
}
async function cliWorkbench(mode,request){return command(['protocol',mode,save('request-'+(++commandNo)+'.json',request)]);}
async function expectCode(fn,code,step){await assert.rejects(fn,e=>{assert.equal(e.code,code);if(step!==undefined)assert.equal(e.step,step);return true;});}
const clone=v=>JSON.parse(JSON.stringify(v));
const counter=()=>({name:'test.counter',display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],record_schemas:{},initial_state:{count:0},actions:[{id:'set',reads:[['count']],writes:[['count']],revisionEffects:{control:true,contentEntities:[]},variants:[{when:[{op:'eq',left:{from:'state',path:['count']},right:{from:'literal',value:0}}],effects:[{op:'set',path:['count'],value:{from:'literal',value:1}}]}]}]});
async function offline(){
 const producers=['protocol.action','workspace.invitation.finalize'];
 const coverage=await sdk.protocolCompatibility({requiredProducers:producers});assert.equal(coverage.supported,true);assert.equal(coverage.service_verified,false);
 const unknown=await sdk.protocolCompatibility({requiredProducers:[...producers,'unqualified.maintenance']});assert.equal(unknown.supported,false);assert.equal(unknown.producers.at(-1).status,'unknown');
 assert.deepEqual(await cliWorkbench('compatibility',{required_producers:producers}),coverage);
 pass('declared-producer-coverage-refuses-unknown-support');
 const a=counter();a.name='test.ticket';a.record_schemas={ticket:{type:'object',fields:{title:'string'},required:['title'],max_bytes:4096}};
 a.actions=[{id:'create',reads:[],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[],effects:[{op:'append',schema:'ticket',value:{from:'body',path:[]}}]}]}];
 const b=clone(a);b.display_version='2';b.record_schemas.ticket.fields.source='json';b.record_schemas.ticket.required.push('source');
 const ref={from:'ref',source:'body',path:['source'],schema:'ticket',scope:'WORKSPACE'};
 b.actions=[{id:'import',reads:[],writes:[],revisionEffects:{control:false,contentEntities:[]},variants:[{when:[{op:'exact_ref',ref}],effects:[{op:'append',schema:'ticket',value:{from:'object',fields:{title:{from:'resolved_payload',ref,path:['title']},source:{from:'body',path:['source']}}}}]}]}];
 const source={record_id:'R'.repeat(43),revision:1},steps=[{instance_id:'old',action_id:'create',body:{title:'Original \ud800'},allocations:[{record_id:source.record_id,entity_id:'E'.repeat(43)}]},{instance_id:'new',action_id:'import',body:{source},exact_input_refs:[source]}];
 const protocols=[{instance_id:'old',manifest:a},{instance_id:'new',manifest:b}],seed='installed-parity',time_ms=0;
 const fixture=await sdk.buildProtocolFixture({protocols,seed,timeMs:time_ms}),before=JSON.stringify(fixture);
 const result=await sdk.simulateProtocol({fixture,steps,seed}),plan=await sdk.planProtocolActions({fixture,steps,seed});
 assert.equal(result.simulated,true);assert.equal(result.authoritative,false);assert(!result.receipt);
 assert.deepEqual(result.steps[1].effects[0].value.payload,{title:'Original \ud800',source});
 assert.notEqual(result.steps[0].effects[0].id,result.steps[1].effects[0].id);
 const cliFixture=await cliWorkbench('fixture',{schema:'peerwork.protocol-fixture.v1',protocols,seed,time_ms});assert.deepEqual(cliFixture,fixture);
 const input={schema:'peerwork.protocol-simulation.v1',fixture,steps,seed};
 assert.deepEqual(await cliWorkbench('simulate',input),result);assert.deepEqual(await cliWorkbench('plan',input),plan);
 const py=await execFile(python,[new URL('unified-workbench-consumer.py',import.meta.url).pathname,save('python-offline.json',{protocols,steps,seed,time_ms})],{timeout:120000,maxBuffer:16*1024*1024});
 assert.deepEqual(JSON.parse(py.stdout),{fixture,result,plan});
 pass('offline-v1-v2-conversion-utf16-and-installed-node-python-cli-parity',{service_started:false});
 const bad=clone(steps);bad[1].exact_input_refs[0].revision=2;
 await expectCode(()=>sdk.simulateProtocol({fixture,steps:bad,seed}),'REFERENCE_NOT_FOUND',1);
 assert.equal(JSON.stringify(fixture),before);assert.deepEqual(await sdk.simulateProtocol({fixture,steps,seed}),result);
 const roles=counter();roles.protocol_roles=['reviewer'];roles.actions[0].variants[0].when=[{op:'has_protocol_role',role:'reviewer'}];
 const rf=await sdk.buildProtocolFixture({protocols:[{instance_id:'counter',manifest:roles}]});
 await expectCode(()=>sdk.simulateProtocol({fixture:rf,steps:[{instance_id:'counter',action_id:'set'}]}),'CONSTRAINT_FAILED',0);
 const timed=counter();timed.actions[0].variants[0].when=[{op:'gte',left:{from:'time'},right:{from:'literal',value:5}},{op:'lt',left:{from:'time'},right:{from:'literal',value:9}}];
 const tf=await sdk.buildProtocolFixture({protocols:[{instance_id:'counter',manifest:timed}],timeMs:0});
 for(const time_ms of [5,8])assert.equal((await sdk.simulateProtocol({fixture:tf,steps:[{instance_id:'counter',action_id:'set',time_ms}]})).steps[0].output_state.count,1);
 for(const time_ms of [4,9])await expectCode(()=>sdk.simulateProtocol({fixture:tf,steps:[{instance_id:'counter',action_id:'set',time_ms}]}),'CONSTRAINT_FAILED',0);
 pass('offline-missing-role-exact-ref-time-boundaries-sequence-rollback');
 return plan;
}
try{
 const syntheticPlan=await offline();
 const require=createRequire(join(reference,'package.json')),load=n=>import(pathToFileURL(join(reference,'dist-workspace/src',n+'.js')));
 const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server'))),{openKernel,WorkspaceKernel}=await load('workspace-kernel');
 const {createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent'),{secureToken}=await load('workspace-secure-client');
 db=openKernel(join(out,'control.sqlite'),'unified-workbench');const kernel=new WorkspaceKernel(db,'unified-workbench',Buffer.alloc(32,85)),app=createWorkspaceControlApp(kernel);
 server=serve({hostname:'127.0.0.1',port:0,fetch:async(req,env,ctx)=>{
  requests++;let finalize=false;if(req.method==='POST'){posts++;try{const body=await req.clone().json();finalize=body.commit?.payload?.action_id==='secure.invite.finalize';if(['wiki.create','discussion.post'].includes(body.commit?.payload?.action_id)){const actor=body.commit.payload.actor_id;actionPosts.set(actor,(actionPosts.get(actor)||0)+1);}}catch{}if(finalize)finalizePosts++;}
  const response=await app.fetch(req,env,ctx);
  if(journalInterleave&&req.method==='GET'&&new URL(req.url).pathname.endsWith('/journal')&&response.ok){const insert=journalInterleave;journalInterleave=null;await insert();}
  if(dropFinalize&&finalize&&response.ok){dropFinalize=false;dropped++;env.outgoing.destroy();}
  return response;
 }});
 await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port+(process.env.PEERWORK_WORKBENCH_TRAILING_SLASH==='1'?'/':'');
 async function open(name){const dir=join(out,name);mkdirSync(dir,{mode:0o700});const privateKey=generateKeyPairSync('ed25519').privateKey,pem=join(dir,'signer.pem'),state=join(dir,'agent.state'),intents=join(dir,'intents.sqlite');writeFileSync(pem,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});const agent=await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey,statePath:state,intentDbPath:intents});clients.push(agent);return {agent,dir,pem,state,intents};}
 const owner=await open('owner'),workers=[await open('worker-one'),await open('worker-two'),await open('worker-legacy')];
 await owner.agent.publishIdentity();for(const w of workers){await w.agent.publishIdentity();await owner.agent.trustIdentity(w.agent.identity.actorId);await w.agent.trustIdentity(owner.agent.identity.actorId);}
 const {workspaceId:ws}=await owner.agent.create('Unified installed acceptance','PRIVATE',{structure:true});
 let journal=await owner.agent.journal(ws);const wiki=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki').id,discussion=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='discussion').id;
 const discovery=owner.agent.transport.discovery;
 await owner.agent.enableGuardTime(ws,{expectedPolicyHash:journal.checkpoint.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW'});
 const offers=[];for(const w of workers){const offer=await owner.agent.inviteActor(ws,w.agent.identity.actorId,[{instance_id:wiki,actions:['wiki.create'],protocol_roles:['EDITOR'],capabilities:['EDIT']},{instance_id:discussion,actions:['discussion.post'],protocol_roles:['CONTRIBUTOR'],capabilities:['POST']}],'Synthetic installed worker');await w.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');offers.push(offer.payload.invite_id);}
 await owner.agent.close();const sourceHashes=[hash(owner.pem),hash(owner.state),hash(owner.intents)];
 const attachment={workspaceId:ws,protectedTsStatePath:owner.state,protectedTsIntentDbPath:owner.intents,protectedOwnerPkcs8Path:owner.pem,expectedOwnerActorId:owner.agent.identity.actorId,expectedOwnerKeyId:owner.agent.identity.keyId};
 // The released 0.1.8 producer needs a canonical origin. Independently verify
 // new SDK no-slash attach/bind/read against the same original identity using
 // a read-only profile; neither profile nor journals are copied or rewritten.
 const rawOrigin=new URL(origin).origin,probeRoot=join(out,'native-origin-probe'),beforeProbe=posts;
 const probe=sdk.openSecureOwnerWorkspaces({origin:rawOrigin,stateDir:probeRoot,allowLoopbackHttp:true});await probe.attach(attachment);
 const probeProfile=save('origin-probe-profile.json',{origin:rawOrigin,state_dir:join(probeRoot,'workspaces',ws),identity_path:join(probeRoot,'identity.state'),workspace_id:ws,owner_actor_id:owner.agent.identity.actorId,owner_key_id:owner.agent.identity.keyId,allow_loopback_http:true});
 await sdk.bindContext({profilePath:join(out,'origin-probe-context.json'),expectedActor:owner.agent.identity.actorId,expectedService:rawOrigin,workspaceProfiles:[probeProfile]});
 assert.equal((await probe.read(ws)).workspace_id,ws);assert.equal(posts,beforeProbe,'read-only origin probe submitted a business operation');
 pass('raw-no-slash-owner-attach-context-bind-read-original-identity');
 const nativeOrigin=new URL(origin).href,nativeRoot=join(out,'native-owner'),ownerOptions={origin:nativeOrigin,stateDir:nativeRoot,allowLoopbackHttp:true},native=sdk.openSecureOwnerWorkspaces(ownerOptions);
 await native.attach(attachment);
 const config=save('owner-config.json',{origin:nativeOrigin,state_dir:nativeRoot,allow_loopback_http:true});
 const profile={origin:nativeOrigin,stateDir:join(nativeRoot,'workspaces',ws),identityPath:join(nativeRoot,'identity.state'),workspaceId:ws,ownerActorId:owner.agent.identity.actorId,ownerKeyId:owner.agent.identity.keyId,allowLoopbackHttp:true};
 const snake={origin:nativeOrigin,state_dir:profile.stateDir,identity_path:profile.identityPath,workspace_id:ws,owner_actor_id:profile.ownerActorId,owner_key_id:profile.ownerKeyId,allow_loopback_http:true};
 const profilePath=join(out,'context.json'),workspaceProfile=save('workspace-profile.json',snake);
 let ctx=await sdk.bindContext({profilePath,expectedActor:profile.ownerActorId,expectedService:origin,workspaceProfiles:[workspaceProfile]});
 const beforeCoverage=requests;
 await expectCode(()=>native.guardTime(ws).enable({expectedPolicyHash:journal.checkpoint.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW',requiredProducers:['unqualified.maintenance']}),'PRODUCER_UNSUPPORTED');
 assert.equal(requests,beforeCoverage,'unsupported producer activation contacted service');
 pass('guard-time-enable-refuses-unqualified-producer-before-network');
 const beforeLegacy=await native.read(ws);
 const old=await command(['secure','owner-private-admit-deliver',config,ws,offers[2]],{executable:oldCli,ok:false});assert(old.code||old.ok===false,'released producer unexpectedly succeeded');
 const pending=await command(['secure','owner-private-admit-pending-deliveries',config,ws],{executable:oldCli});assert.equal(pending.length,1);const oldGrant=pending[0].grant_id;
 const admissionFile=join(profile.stateDir,'admission-intents.state'),oldRow=readNativeState(admissionFile).rows[oldGrant];
 const oldRequest=JSON.parse(Buffer.from(oldRow.request_b64,'base64url').toString());assert(oldRequest.policy.payload.guard_time);assert.equal(oldRequest.commit.payload.guard_time,undefined);
 assert.equal((await native.read(ws)).head,beforeLegacy.head);pass('released-018-persists-authentic-inadmissible-packet');
 const normalId='finalize-normal',normal=await ctx.operate(ws,{kind:'workspace.invitation.finalize',invite_id:offers[0]},normalId);assert.equal(normal.status,'verified');
 pass('guarded-private-invitation-finalize');
 const lostId='finalize-lost-response',beforeLost=finalizePosts;dropFinalize=true;
 try{await ctx.operate(ws,{kind:'workspace.invitation.finalize',invite_id:offers[1]},lostId);}catch(e){save('lost-response-error.json',{code:e.code,message:e.message});}
 assert.equal(dropped,1,'fault did not drop a successful finalize response');
 ctx=await sdk.openContext({profilePath,expectedActor:profile.ownerActorId,expectedService:origin});
 const lost=await ctx.recover(ws,{operationId:lostId});assert.equal(lost.status,'verified');assert.equal(finalizePosts-beforeLost,1,'recovery resubmitted a committed finalize');
 pass('committed-response-lost-restart-reconcile-without-post');
 const repairedId='finalize-malformed',beforeClassify=posts;
 const diagnosis=await ctx.operate(ws,{kind:'workspace.invitation.finalize',invite_id:offers[2],saved_grant_id:oldGrant},repairedId);
 assert.equal(diagnosis.result.status,'REPLACEMENT_SAFE');assert.equal(posts,beforeClassify,'diagnosis submitted a replacement');
 const beforeReplacement=finalizePosts;
 const repaired=await ctx.recover(ws,{operationId:repairedId,recovery:{mode:'safe',maxSubmissions:1}});assert.equal(finalizePosts-beforeReplacement,1,'safe recovery exceeded one submission');assert.equal(repaired.status,'verified');assert.equal(repaired.result.attempt,1);assert.equal(repaired.result.closed_attempts.length,1);
 const retained=readNativeState(admissionFile).rows[oldGrant];assert.equal(retained.request_b64,oldRow.request_b64);assert.equal(retained.request_sha256,oldRow.request_sha256);
 const beforeRetry=posts;assert.equal((await ctx.recover(ws,{operationId:repairedId})).status,'verified');assert.equal(posts,beforeRetry);
 assert.deepEqual([hash(owner.pem),hash(owner.state),hash(owner.intents)],sourceHashes);
 pass('old-malformed-guard-packet-replacement-after-intervening-commits-original-preserved');
 // Recipient verification uses the same original signing and invitation keys.
 // No second ACCEPT, replacement identity or state-file editing is involved.
 for(const [index,w] of workers.entries()){
  await w.agent.close();const dir=join(out,'native-worker-'+index);mkdirSync(dir,{mode:0o700});
  await command(['identity','import-legacy-pem',join(dir,'identity.state'),w.pem]);
  await sdk.openSecureRecipientEnrollment({origin,stateDir:dir,allowLoopbackHttp:true}).importLegacyKeys({protectedTsStatePath:w.state,expectedActorId:w.agent.identity.actorId,expectedSigningKeyId:w.agent.identity.keyId,expectedSourceDigest:hash(w.state)});
  const recipient=await sdk.readSecurePrivateWorkspace({...profile,stateDir:dir,identityPath:join(dir,'identity.state')});
  assert.equal(recipient.workspace_id,ws);assert(recipient.objects.some(o=>o.kind==='instances'&&o.id===wiki));
 }
 pass('all-original-recipients-decrypt-native-history-without-reaccept');
 const timeMs=1000,fixture=await sdk.exportProtocolFixture({profile,instanceIds:[wiki],timeMs});
 assert.equal(fixture.provenance.kind,'verified-export');
 assert.deepEqual(await ctx.exportFixture(ws,{instanceIds:[wiki],timeMs,cached:true}),fixture);
 const exportRequest={profile:snake,instance_ids:[wiki],time_ms:timeMs,cached:true};
 const beforeCached=requests;assert.deepEqual(await cliWorkbench('export',exportRequest),fixture);
 const py=await execFile(python,[new URL('unified-workbench-consumer.py',import.meta.url).pathname,save('python-export.json',{mode:'export',...exportRequest})],{timeout:120000,maxBuffer:16*1024*1024});assert.deepEqual(JSON.parse(py.stdout),fixture);const cachedExportRequests=requests-beforeCached;
 pass('verified-real-snapshot-export-node-python-cli-parity');
 await expectCode(()=>sdk.applyProtocolPlan({profile,plan:syntheticPlan,operationId:'reject-synthetic'}),'SYNTHETIC_PLAN');
 const steps=[{instance_id:wiki,action_id:'wiki.create',body:{title:'Planned installed ticket',body:'Local validation before submission'}}];
 const plan=await sdk.planProtocolActions({fixture,steps,seed:'real-plan'}),operationId='apply-installed-plan';
 let applied=await sdk.applyProtocolPlan({profile,plan,operationId});assert.equal(applied.status,'PENDING');
 const listed=await ctx.operations(ws),savedPlan=listed.result.find(r=>r.kind==='protocol.plan.apply'&&r.operation_id===operationId);
 assert(savedPlan);assert.equal(savedPlan.plan_saved,true);assert(!JSON.stringify(savedPlan).includes('Planned installed ticket'));
 ctx=await sdk.openContext({profilePath,expectedActor:profile.ownerActorId,expectedService:origin});
 const beforePlanRecover=requests,local=await ctx.recover(ws,{operationId});
 assert.equal(local.status,'pending');assert.equal(local.result.status,'PLAN_LOCAL_PROGRESS');assert.equal(local.result.verification,'pending');assert.equal(local.result.effect_certainty,'unknown');assert.equal(requests,beforePlanRecover,'default plan recovery contacted service');
 await expectCode(()=>ctx.recover(ws,{operationId,recovery:{mode:'safe',maxSubmissions:1}}),'RECOVERY_MODE_UNSUPPORTED');assert.equal(requests,beforePlanRecover);
 await expectCode(()=>ctx.operate(ws,{kind:'workspace.invitation.finalize',invite_id:offers[0]},operationId),'INTENT_CONFLICT');
 for(let i=0;i<4;i++){applied=await ctx.resumePlan(ws,operationId);if(applied.status==='VERIFIED')break;assert.equal(applied.status,'PENDING');}
 pass('pending-plan-discovery-restart-readonly-recover-explicit-resume-without-plan');
 assert.equal(applied.status,'VERIFIED');assert.equal(applied.completed_steps,1);assert.equal(applied.atomic,false);
 const beforeApplyRetry=posts;assert.deepEqual(await ctx.applyPlan(ws,plan,operationId),applied);
 assert.deepEqual(await cliWorkbench('apply',{profile:snake,operation_id:operationId}),applied);
 const pyResume=await execFile(python,[new URL('unified-workbench-consumer.py',import.meta.url).pathname,save('python-resume.json',{mode:'resume',profile:snake,operation_id:operationId})],{timeout:120000,maxBuffer:16*1024*1024});assert.deepEqual(JSON.parse(pyResume.stdout),applied);assert.equal(posts,beforeApplyRetry);
 assert.equal((await native.read(ws)).objects.filter(o=>o.kind==='records'&&o.value?.payload?.title==='Planned installed ticket').length,1);
 pass('real-export-plan-apply-retry-idempotent-signed-history');
 const staleFixture=await sdk.exportProtocolFixture({profile,instanceIds:[wiki],timeMs}),stalePlan=await sdk.planProtocolActions({fixture:staleFixture,steps:[{...steps[0],body:{title:'Must never submit',body:'stale'}}],seed:'stale-plan'});
 const actions=native.privateActions(ws),write=await actions.submit('wiki.create',wiki,{title:'Intervening action',body:'Makes plan stale'},{operationId:secureToken()});assert.equal((await actions.reconcile(write.command_id)).status,'ACCEPTED');
 const beforeStale=posts;await expectCode(()=>sdk.applyProtocolPlan({profile,plan:stalePlan,operationId:'stale-plan'}),'PLAN_STALE');assert.equal(posts,beforeStale);
 pass('intervening-state-rejects-stale-plan-before-post');
 // Freeze an old, authentic journal response, commit a content-only action by
 // another original actor, then deliver that old response to the precheck.
 // The author must detect its newer checkpoint before preparing any packet.
 const w=workers[0],writer=await SecureAgentClient.open({baseUrl:new URL(origin).origin,privateKey:createPrivateKey(readFileSync(w.pem)),statePath:w.state,intentDbPath:w.intents});clients.push(writer);
 await writer.receiveAdmission(offers[0]);
 const raceFixture=await sdk.exportProtocolFixture({profile,instanceIds:[discussion],timeMs}),racePlan=await sdk.planProtocolActions({fixture:raceFixture,steps:[{instance_id:discussion,action_id:'discussion.post',body:{message:'Race must never submit'}}],seed:'race-plan'});
 const beforeInstance=raceFixture.objects.find(o=>o.kind==='instances'&&o.id===discussion).value;
 const ownerPosts=actionPosts.get(profile.ownerActorId)||0,workerPosts=actionPosts.get(w.agent.identity.actorId)||0;let inserted=false;
 journalInterleave=async()=>{await writer.action(ws,discussion,'discussion.post',{message:'Same control revision, newer checkpoint'},[],secureToken());inserted=true;};
 await expectCode(()=>sdk.applyProtocolPlan({profile,plan:racePlan,operationId:'checkpoint-race'}),'PLAN_STALE');
 assert(inserted,'race hook did not run');assert.equal(journalInterleave,null);assert.equal(actionPosts.get(profile.ownerActorId)||0,ownerPosts);assert.equal((actionPosts.get(w.agent.identity.actorId)||0)-workerPosts,1);
 const afterRace=await native.read(ws),afterInstance=afterRace.objects.filter(o=>o.kind==='instances'&&o.id===discussion).sort((a,b)=>b.revision-a.revision)[0].value;
 assert.equal(afterInstance.revision,beforeInstance.revision);assert(afterInstance.event_revision>beforeInstance.event_revision);assert(afterRace.sequence>raceFixture.sequence);
 assert(afterRace.objects.some(o=>o.kind==='records'&&o.value?.actor_id===w.agent.identity.actorId&&o.value?.payload?.message==='Same control revision, newer checkpoint'));
 assert(!afterRace.objects.some(o=>o.kind==='records'&&o.value?.payload?.message==='Race must never submit'));
 pass('content-only-change-between-precheck-and-author-refuses-before-owner-post');
 assert.equal(cachedExportRequests,0,'cached export contacted the service');pass('cached-export-zero-http');report.status='PASS';
}catch(error){report.status='FAIL';report.error={code:error.code,message:String(error.message).slice(0,2500),stack:String(error.stack).split('\n').slice(0,10)};if(error.stderr)writeFileSync(join(out,'consumer-error.stderr'),error.stderr,{mode:0o600});process.exitCode=1;}
finally{for(const c of clients)try{await c.close();}catch{}if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}db?.close();report.elapsed_ms=Math.round(performance.now()-started);save('verification.json',report);console.log(JSON.stringify(report));}
