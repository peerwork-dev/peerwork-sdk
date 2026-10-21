// Real isolated service + installed native Node/Python/CLI. Synthetic data only.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {generateKeyPairSync,createHash,createPrivateKey} from 'node:crypto';
import {execFile as callback} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(callback),[productArg,cliArg,outArg]=process.argv.slice(2);
assert(productArg&&cliArg&&outArg);const product=resolve(productArg),cli=resolve(cliArg),out=resolve(outArg);
const consumer=process.env.PEERWORK_SCOPES_NODE_CONSUMER,python=process.env.PEERWORK_SCOPES_PYTHON;assert(consumer&&python);
mkdirSync(out,{mode:0o700});const sdk=createRequire(join(resolve(consumer),'package.json'))('@peerwork/agent-sdk');
const require=createRequire(join(product,'package.json')),load=n=>import(pathToFileURL(join(product,'dist-workspace/src',n+'.js')));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server'))),{openKernel,WorkspaceKernel}=await load('workspace-kernel');
const {createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent');
const {secureToken,secureEqual}=await load('workspace-secure-client');
const save=(name,v)=>{const path=join(out,name);writeFileSync(path,JSON.stringify(v),{mode:0o600});return path;};
const report={status:'RUNNING',synthetic_only:true,cases:[]};const pass=name=>{report.cases.push({name,status:'PASS'});save('verification.json',report);};
const db=openKernel(join(out,'control.sqlite'),'member-scope-native'),kernel=new WorkspaceKernel(db,'member-scope-native',Buffer.alloc(32,93));
const app=createWorkspaceControlApp(kernel);let posts=0,scopePosts=0,drop=false,deny=false,lastPacket,server;const clients=[];
server=serve({hostname:'127.0.0.1',port:0,fetch:async(req,env,ctx)=>{
 let scopes=false;if(req.method==='POST'){posts++;try{const v=await req.clone().json();scopes=v.commit?.payload?.action_id==='secure.member.scopes';if(scopes){scopePosts++;lastPacket=v;}}catch{}}
 if(scopes&&deny)return new Response(JSON.stringify({error:{code:'SECURE_CHECKPOINT_CONFLICT',message:'PRIVATE_CANARY_MUST_NOT_ESCAPE'}}),{status:409});
 const response=await app.fetch(req,env,ctx);if(scopes&&drop&&response.ok){drop=false;env.outgoing.destroy();}return response;
}});
await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port;
async function open(name){const dir=join(out,name);mkdirSync(dir,{mode:0o700});const privateKey=generateKeyPairSync('ed25519').privateKey,pem=join(dir,'owner.pem'),state=join(dir,'agent.state'),intents=join(dir,'intents.sqlite');writeFileSync(pem,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});const agent=await SecureAgentClient.open({baseUrl:origin,privateKey,statePath:state,intentDbPath:intents});clients.push(agent);return {agent,pem,state,intents};}
async function code(fn,wanted){await assert.rejects(fn,e=>{assert.equal(e.code,wanted);return true;});}
try {
 const owner=await open('source-owner'),member=await open('source-member');
 for(const p of [owner,member])await p.agent.publishIdentity();await owner.agent.trustIdentity(member.agent.identity.actorId);await member.agent.trustIdentity(owner.agent.identity.actorId);
 const {workspaceId:ws}=await owner.agent.create('Member scope acceptance','PRIVATE',{structure:true});
 let before=await owner.agent.journal(ws);const discovery=owner.agent.transport.discovery;
 await owner.agent.enableGuardTime(ws,{expectedPolicyHash:before.checkpoint.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW'});
 before=await owner.agent.journal(ws);const wiki=before.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki').id;
 const initial=[{instance_id:wiki,actions:['wiki.create'],protocol_roles:['EDITOR'],capabilities:['EDIT']}];
 const offer=await owner.agent.inviteActor(ws,member.agent.identity.actorId,initial,'synthetic acceptance');await member.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');await owner.agent.deliverAdmission(offer.payload.invite_id);
 await member.agent.receiveAdmission(offer.payload.invite_id);await member.agent.journal(ws);
 const actor=member.agent.identity.actorId;await owner.agent.close();
 const config={origin:new URL(origin).href,stateDir:join(out,'native-owner'),allowLoopbackHttp:true};
 let native=sdk.openSecureOwnerWorkspaces(config);await native.attach({workspaceId:ws,protectedTsStatePath:owner.state,protectedTsIntentDbPath:owner.intents,protectedOwnerPkcs8Path:owner.pem,expectedOwnerActorId:owner.agent.identity.actorId,expectedOwnerKeyId:owner.agent.identity.keyId});
 let access=native.memberScopes(ws);const inspected=await access.inspect(actor);assert.deepEqual(inspected.scopes,initial);assert.equal(inspected.read,true);assert(inspected.instances.some(i=>i.instance_id===wiki&&i.actions.includes('wiki.create')));
 assert((await sdk.protocolCompatibility({requiredProducers:['secure.member.scopes']})).supported);assert(sdk.capabilities().owner_member_scopes);pass('guarded-owner-inspection-and-decrypted-permission-catalog');
 const beforePosts=posts;
 await code(()=>access.set(actor,{expectedPolicyHash:'0'.repeat(64),scopes:[],operationId:secureToken()}),'MEMBER_SCOPE_POLICY_CHANGED');
 await code(()=>access.set(secureToken(),{expectedPolicyHash:inspected.policy_hash,scopes:[],operationId:secureToken()}),'MEMBER_NOT_FOUND');
 await code(()=>access.set(actor,{expectedPolicyHash:inspected.policy_hash,scopes:[{...initial[0],actions:['undeclared.action']}],operationId:secureToken()}),'MEMBER_SCOPE_UNDECLARED_PERMISSION');
 await code(()=>access.set(actor,{expectedPolicyHash:inspected.policy_hash,scopes:[{...initial[0],actions:['wiki.create','wiki.create']}],operationId:secureToken()}),'MEMBER_SCOPES_INVALID');
 assert.equal(posts,beforePosts);pass('stale-hash-unknown-member-undeclared-duplicate-permission-no-post');
 const unchanged=await access.set(actor,{expectedPolicyHash:inspected.policy_hash,scopes:initial,operationId:secureToken()});assert.equal(unchanged.status,'UNCHANGED');assert.equal(posts,beforePosts);pass('unchanged-grants-no-post');
 const id=secureToken();before=await member.agent.journal(ws);const updated=await access.set(actor,{expectedPolicyHash:inspected.policy_hash,scopes:[],operationId:id});assert.equal(updated.status,'ACCEPTED');
 assert.deepEqual(lastPacket.commit.payload.guard_time,{v:1,lower_ms:0,upper_ms:9007199254740991});assert.equal(lastPacket.commit.payload.body.alg,'A256GCM');
 const after=await member.agent.journal(ws);assert.equal(after.checkpoint.sequence,before.checkpoint.sequence+1);assert.equal(after.policy.payload.epoch,before.policy.payload.epoch);
 assert(secureEqual(after.policy.payload.members,before.policy.payload.members.map(m=>m.actor_id===actor?{...m,scopes:[]}:m)));assert.equal(after.policy.payload.owner_id,before.policy.payload.owner_id);assert.equal(after.policy.payload.signing_key,before.policy.payload.signing_key);
 await assert.rejects(()=>member.agent.action(ws,wiki,'wiki.create',{title:'blocked',body:'blocked'},[],secureToken()),/UNAUTHORIZED|DENIED|FORBIDDEN|SCOPE|PERMISSION/);pass('encrypted-guarded-scope-only-revocation-preserves-membership-certificates-keys-read');
 const count=scopePosts;assert.equal((await access.recover(id)).status,'ACCEPTED');assert.equal((await access.retrySaved(id)).status,'ACCEPTED');assert.equal(scopePosts,count);pass('accepted-recovery-and-explicit-retry-do-not-resubmit');
 await code(()=>access.set(actor,{expectedPolicyHash:inspected.policy_hash,scopes:initial,operationId:id}),'MEMBER_SCOPE_OPERATION_CONFLICT');assert.equal(scopePosts,count);pass('same-operation-different-intent-refused');
 let fresh=await access.inspect(actor),lost=secureToken();drop=true;
 await assert.rejects(()=>access.set(actor,{expectedPolicyHash:fresh.policy_hash,scopes:initial,operationId:lost}),e=>e.effect_certainty==='unknown');
 native=sdk.openSecureOwnerWorkspaces(config);access=native.memberScopes(ws);const lostCount=scopePosts;
 assert.equal((await access.recover(lost)).status,'ACCEPTED');assert.equal(scopePosts,lostCount);assert.deepEqual((await access.inspect(actor)).scopes,initial);
 await member.agent.journal(ws);await member.agent.action(ws,wiki,'wiki.create',{title:'Existing member after grant','body':'No key rotation or identity replacement'},[],secureToken());pass('lost-response-restart-reconciles-exact-accepted-packet-and-existing-member-can-write');
 fresh=await access.inspect(actor);const pending=secureToken();deny=true;
 await assert.rejects(()=>access.set(actor,{expectedPolicyHash:fresh.policy_hash,scopes:[],operationId:pending}),e=>e.code==='SECURE_CHECKPOINT_CONFLICT'&&e.diagnostic.effect_certainty==='unknown'&&!JSON.stringify(e.diagnostic).includes('PRIVATE_CANARY'));
 const pendingPacket=createHash('sha256').update(JSON.stringify(lastPacket)).digest('hex'),pendingCount=scopePosts;
 assert.equal((await access.recover(pending)).status,'PENDING');assert.equal(scopePosts,pendingCount);deny=false;
 assert.equal((await access.retrySaved(pending)).status,'ACCEPTED');assert.equal(scopePosts,pendingCount+1);assert.equal(createHash('sha256').update(JSON.stringify(lastPacket)).digest('hex'),pendingPacket);pass('sanitized-refusal-read-only-recover-and-explicit-exact-packet-retry');
 fresh=await access.inspect(actor);const staleId=secureToken();deny=true;
 await code(()=>access.set(actor,{expectedPolicyHash:fresh.policy_hash,scopes:initial,operationId:staleId}),'SECURE_CHECKPOINT_CONFLICT');deny=false;
 await native.privateActions(ws).submit('wiki.create',wiki,{title:'Concurrent owner action',body:'Occupies the old sequence'},{operationId:secureToken()});
 const staleCount=scopePosts;assert.equal((await access.recover(staleId)).status,'SUPERSEDED');assert.equal((await access.retrySaved(staleId)).status,'SUPERSEDED');assert.equal(scopePosts,staleCount);
 pass('signed-competing-transaction-supersedes-packet-without-post-or-history-loss');
 const statePath=join(config.stateDir,'workspaces',ws,'owner-member-scopes.state'),original=readFileSync(statePath),magic=Buffer.from('PEERWORK-NATIVE-SECURE-STATE\n1\n');
 assert(original.subarray(0,magic.length).equals(magic));const forged=JSON.parse(original.subarray(magic.length));forged.rows[id].commit_hash='0'.repeat(64);
 writeFileSync(statePath,Buffer.concat([magic,Buffer.from(JSON.stringify(forged))]),{mode:0o600});
 try{await code(()=>access.recover(id),'MEMBER_SCOPE_PACKET_INVALID');assert.equal(scopePosts,staleCount);}finally{writeFileSync(statePath,original,{mode:0o600});}
 pass('cached-accepted-result-reproves-saved-signature-context-ciphertext-and-commit-hash');
 const snake={origin:config.origin,state_dir:config.stateDir,allow_loopback_http:true};
 const req=save('cli-inspect.json',{config:snake,input:{workspace_id:ws,actor_id:actor}}),run=await execFile(cli,['member-scopes','inspect',req]);assert.deepEqual(JSON.parse(run.stdout).value,await access.inspect(actor));pass('installed-cli-inspection-parity');
 const request=save('python-request.json',{config:snake,workspace_id:ws,actor_id:actor,scopes:initial});
 const py=await execFile(python,[new URL('member-scopes-consumer.py',import.meta.url).pathname,request],{timeout:120000,maxBuffer:1048576});assert.equal(JSON.parse(py.stdout).status,'PASS');pass('installed-python-sync-async-update-and-read-only-recovery');
 // A separate attached workspace must have independent pending/history state.
 assert((await access.history()).every(r=>r.workspace_id===ws));
 const alien=sdk.openSecureOwnerWorkspaces({origin:config.origin,stateDir:join(out,'unbound-member'),allowLoopbackHttp:true});
 await code(()=>alien.memberScopes(ws).inspect(actor),'MEMBER_SCOPE_OWNER_PROFILE_REQUIRED');pass('unbound-profile-cannot-author-owner-policy');
 const sourceAgain=await SecureAgentClient.open({baseUrl:origin,privateKey:createPrivateKey(readFileSync(owner.pem)),statePath:owner.state,intentDbPath:owner.intents});clients.push(sourceAgain);
 const second=await sourceAgain.create('Independent scope history','PRIVATE',{structure:true});const wsB=second.workspaceId;await sourceAgain.close();
 await native.attach({workspaceId:wsB,protectedTsStatePath:owner.state,protectedTsIntentDbPath:owner.intents,protectedOwnerPkcs8Path:owner.pem,expectedOwnerActorId:owner.agent.identity.actorId,expectedOwnerKeyId:owner.agent.identity.keyId});
 const ownerActor=owner.agent.identity.actorId,bClient=native.memberScopes(wsB),bBefore=await bClient.inspect(ownerActor),aHistory=await access.history();
 const bSet=await bClient.set(ownerActor,{expectedPolicyHash:bBefore.policy_hash,scopes:[],operationId:secureToken()});assert.equal(bSet.status,'ACCEPTED');assert.equal(lastPacket.commit.payload.guard_time,undefined);
 const bCurrent=await bClient.inspect(ownerActor),enabled=await native.guardTime(wsB).enable({expectedPolicyHash:bCurrent.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW',operationId:secureToken(),requiredProducers:['secure.member.scopes']});
 if(enabled.status==='PENDING')assert.equal((await native.guardTime(wsB).resume(enabled.operation_id)).status,'ACCEPTED');
 const bGuarded=await bClient.inspect(ownerActor);assert.equal((await bClient.set(ownerActor,{expectedPolicyHash:bGuarded.policy_hash,scopes:bBefore.scopes,operationId:secureToken()})).status,'ACCEPTED');
 assert(lastPacket.commit.payload.guard_time);assert.deepEqual(await access.history(),aHistory);assert.equal((await bClient.history()).length,2);
 pass('same-owner-independent-workspace-history-unguarded-then-native-guard-enable-and-scope-update');
 report.status='PASS';save('verification.json',report);console.log(JSON.stringify(report));
} catch(e){report.status='FAIL';report.error={name:e.name,code:e.code,message:e.message};save('verification.json',report);throw e;}
finally {for(const c of clients)await c.close();await new Promise(r=>server.close(r));db.close();}
