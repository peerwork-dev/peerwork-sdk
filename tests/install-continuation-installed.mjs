// Released BEGIN producer + candidate continuation against an isolated real service.
// Synthetic state only. No private production fixture or identity is copied.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,readFileSync,symlinkSync,copyFileSync,existsSync} from 'node:fs';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {execFile as callback} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(callback),[productArg,oldConsumerArg,cliArg,outArg]=process.argv.slice(2);
assert(productArg&&oldConsumerArg&&cliArg&&outArg);
const product=resolve(productArg),cli=resolve(cliArg),out=resolve(outArg),root=resolve(new URL('..',import.meta.url).pathname);
mkdirSync(out,{mode:0o700});
const sdk=createRequire(join(resolve(oldConsumerArg),'package.json'))('@peerwork/agent-sdk');
const currentRoot=process.env.PEERWORK_INSTALL_CANDIDATE_NODE_CONSUMER;
const currentSdk=currentRoot?createRequire(join(resolve(currentRoot),'package.json'))('@peerwork/agent-sdk'):null;
const pythonPath=process.env.PEERWORK_INSTALL_CANDIDATE_PYTHONPATH;
async function python(mode,config,ws,arg){const run=await execFile('python3',[new URL('install-recovery-consumer.py',import.meta.url).pathname,mode,config,ws,arg],{timeout:180000,maxBuffer:1048576,env:{...process.env,PYTHONPATH:pythonPath}});return JSON.parse(run.stdout);}

const require=createRequire(join(product,'package.json')),load=n=>import(pathToFileURL(join(product,'dist-workspace/src',n+'.js')));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server'))),{openKernel,WorkspaceKernel}=await load('workspace-kernel');
const {createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent'),{secureToken}=await load('workspace-secure-client');
const save=(name,v)=>{const path=join(out,name);writeFileSync(path,JSON.stringify(v),{mode:0o600});return path;};
const hash=p=>createHash('sha256').update(readFileSync(p)).digest('hex');
const report={status:'RUNNING',synthetic_only:true,cases:[]};const pass=name=>{report.cases.push({name,status:'PASS'});save('verification.json',report);};
const db=openKernel(join(out,'control.sqlite'),'install-continuation'),kernel=new WorkspaceKernel(db,'install-continuation',Buffer.alloc(32,94));
const app=createWorkspaceControlApp(kernel);let posts=0,dropAction=null,beginPosts=0,hideObjectSource=false,hideRecoveryCapability=false,denyRecovery=false; const seen=[];
const server=serve({hostname:'127.0.0.1',port:0,fetch:async(req,env,ctx)=>{
 let action;if(req.method==='POST'){posts++;try{const p=(await req.clone().json()).commit?.payload;action=p?.action_id;if(action){seen.push({action,command_id:p.command_id});if(action==='secure.structure.begin')beginPosts++;}}catch{}}
 if(action==='secure.recover'&&denyRecovery)return Response.json({error:{code:'SECURE_CHECKPOINT_CONFLICT',message:'Synthetic refusal'}},{status:409});
 if(hideRecoveryCapability&&new URL(req.url).pathname==='/api/workspace/v1/install-capabilities')return Response.json({error:{code:'NOT_FOUND'}},{status:404});
 const response=await app.fetch(req,env,ctx);
 if(hideObjectSource&&new URL(req.url).pathname==='/api/workspace/v1/discovery'){const value=await response.json();value.protocol_features=value.protocol_features.filter(f=>f!=='signed-protocol-object-source-v1');return Response.json(value);}
 if(action==='secure.recover'&&!response.ok){const body=await response.clone().json();const code=body.error?.code??body.code;report.refusals??=[];report.refusals.push({action,status:response.status,code});save('verification.json',report);}
 if(action===dropAction&&response.ok){dropAction=null;env.outgoing.destroy();}
 return response;
}});
await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port;
let agent;
async function command(verb,path,ws,argument,{ok=true}={}){
 let run;try{run=await execFile(cli,['secure',verb,path,ws,...(argument?[argument]:[])],{timeout:180000,maxBuffer:1048576});}catch(e){run=e;}
 const value=JSON.parse(run.stdout||run.stderr);
 if(ok&&value.code&&verb==='owner-private-install-recover'){
  const diagnostic=await command('owner-private-install-diagnose',path,ws,JSON.parse(readFileSync(argument)).begin_command_id,{ok:false});
  report.recovery_verification=diagnostic;save('verification.json',report);
 }
 if(ok)assert((!value.code||verb==='owner-private-install-diagnose')&&value.ok!==false,JSON.stringify(value));return value.ok===true?value.value:value;
}
try {
 const source=join(out,'source');mkdirSync(source,{mode:0o700});const privateKey=generateKeyPairSync('ed25519').privateKey,pem=join(source,'owner.pem'),state=join(source,'agent.state'),intents=join(source,'intents.sqlite');writeFileSync(pem,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 agent=await SecureAgentClient.open({baseUrl:origin,privateKey,statePath:state,intentDbPath:intents});await agent.publishIdentity();
 const {workspaceId:ws}=await agent.create('Existing structured install recovery','PRIVATE',{structure:true});
 await agent.enableFormatTwo(ws);let journal=await agent.journal(ws),discovery=agent.transport.discovery;
 await agent.enableGuardTime(ws,{expectedPolicyHash:journal.checkpoint.policy_hash,audience:discovery.audience,serviceKey:discovery.receipt_public_key,disclosure:'GUARD_WINDOW',commandId:secureToken()});
 journal=await agent.journal(ws);const wiki=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki').id;
 for(let i=0;i<3;i++)await agent.action(ws,wiki,'wiki.create',{title:'Retained '+i,body:'Encrypted historical body '+i},[],secureToken());
 const before=await agent.journal(ws),config={origin,stateDir:join(out,'native-owner'),allowLoopbackHttp:true};let native=sdk.openSecureOwnerWorkspaces(config);
 await native.attach({workspaceId:ws,protectedTsStatePath:state,protectedTsIntentDbPath:intents,protectedOwnerPkcs8Path:pem,expectedOwnerActorId:agent.identity.actorId,expectedOwnerKeyId:agent.identity.keyId});
 const configPath=save('owner-config.json',{origin,state_dir:config.stateDir,allow_loopback_http:true});
 const identity=join(config.stateDir,'identity.state');const identityHash=hash(identity);
 const vector=JSON.parse(readFileSync(join(root,'conformance/private-direct-format-two.json'))),instance=secureToken();
 const selected={closureJson:JSON.stringify(vector.closure),expectedRootPackageDigest:vector.root_package_digest,expectedProtocolDigest:vector.protocol_digest,instanceId:instance,entrypoint:'lease_canary',grantsJson:'[]'};
 if(currentSdk&&pythonPath){
  const mixed=join(out,'mixed-node');mkdirSync(join(mixed,'node_modules','@peerwork'),{recursive:true,mode:0o700});
  copyFileSync(join(root,'bindings/node/index.cjs'),join(mixed,'index.cjs'));copyFileSync(join(root,'bindings/node/package.json'),join(mixed,'package.json'));
  symlinkSync(join(resolve(oldConsumerArg),'node_modules/@peerwork/agent-sdk-linux-x64-gnu'),join(mixed,'node_modules/@peerwork/agent-sdk-linux-x64-gnu'));
  const mixedSdk=createRequire(join(mixed,'package.json'))('./index.cjs'),mixedConfig={...config,stateDir:join(out,'mixed-unused-profile')};const mixedPosts=posts;
  await assert.rejects(()=>mixedSdk.openSecureOwnerWorkspaces(mixedConfig).privatePackageInstaller(ws).beginDirect(selected),e=>e.code==='SDK_NATIVE_VERSION_MISMATCH');assert(!existsSync(mixedConfig.stateDir));assert.equal(posts,mixedPosts);
  const pyRoot=join(out,'mixed-python');mkdirSync(join(pyRoot,'peerwork'),{recursive:true,mode:0o700});copyFileSync(join(root,'bindings/python/peerwork/__init__.py'),join(pyRoot,'peerwork/__init__.py'));
  const oldPython=join(resolve(oldConsumerArg),'..','python','peerwork');symlinkSync(join(oldPython,'_peerwork_native.abi3.so'),join(pyRoot,'peerwork/_peerwork_native.abi3.so'));
  const pyConfig=save('mixed-python-config.json',{origin,state_dir:mixedConfig.stateDir,allow_loopback_http:true}),pySelection=save('mixed-python-selection.json',{closure_json:selected.closureJson,expected_root_package_digest:selected.expectedRootPackageDigest,expected_protocol_digest:selected.expectedProtocolDigest,instance_id:selected.instanceId,entrypoint:selected.entrypoint,grants_json:selected.grantsJson});
  const result=await execFile('python3',[new URL('install-recovery-consumer.py',import.meta.url).pathname,'mismatch',pyConfig,ws,pySelection],{timeout:120000,env:{...process.env,PYTHONPATH:pyRoot},maxBuffer:1048576});assert.equal(JSON.parse(result.stdout).code,'SDK_NATIVE_VERSION_MISMATCH');assert.equal(posts,mixedPosts);
  pass('new-wrappers-reject-old-native-components-before-profile-creation-or-POST');
 }
 const begin=await native.privatePackageInstaller(ws).beginDirect(selected),id=begin.begin_command_id;assert.equal(begin.step_action_id,'secure.structure.begin');
 const originalPosts=beginPosts;assert.equal(originalPosts,1);pass('released-0.1.10-original-BEGIN-on-existing-guarded-structured-history');
 const writes=posts,diagnostic=await command('owner-private-install-diagnose',configPath,ws,id);assert.equal(diagnostic.submitted,false);assert.equal(posts,writes);assert(diagnostic.verified,JSON.stringify(diagnostic));assert(diagnostic.begin_in_verified_history);pass('read-only-diagnostic-verifies-candidate-and-preserves-ACTIVE');
 if(currentSdk){assert(currentSdk.capabilities().private_install_auto_transport);assert(currentSdk.capabilities().private_install_reviewed_recovery);assert.deepEqual(await currentSdk.openSecureOwnerWorkspaces(config).privatePackageInstaller(ws).diagnose(id),diagnostic);}
 if(pythonPath)assert.deepEqual(await python('diagnose',configPath,ws,id),diagnostic);
 if(currentSdk&&pythonPath)pass('installed-Node-Python-sync-async-CLI-redacted-diagnostic-parity');
 dropAction='secure.structure.page';let progress=await command('owner-private-install-continue',configPath,ws,id);
 for(let i=0;i<12&&progress.status!=='ACCEPTED';i++)progress=await command('owner-private-install-continue',configPath,ws,id);
 assert.equal(progress.status,'ACCEPTED');assert.equal(progress.begin_command_id,id);assert.equal(beginPosts,originalPosts);assert.equal(hash(identity),identityHash);pass('same-BEGIN-completes-PAGE-END-through-lost-response-and-process-restart');
 const after=await agent.journal(ws);assert.equal(after.structure.state,'ACTIVE');assert(after.objects.some(o=>o.kind==='instances'&&o.id===instance));
 for(const old of before.objects)assert(after.objects.some(o=>o.kind===old.kind&&o.id===old.id&&o.revision===old.revision&&JSON.stringify(o)===JSON.stringify(old)));
 assert.equal(new Set(seen.map(x=>x.command_id)).size,seen.length);pass('ACTIVE-restored-with-all-old-objects-signatures-identity-and-no-duplicate-commit');
 const count=posts;assert.equal((await command('owner-private-install-continue',configPath,ws,id)).status,'ACCEPTED');assert.equal(posts,count);pass('accepted-original-BEGIN-recovery-does-not-POST');
 // Genuine supported author/compiler flow builds a >98,304-byte protocol object.
 const {createLegacyObjectInstallMaterial}=await import('./legacy-owner-install-object-material.mjs');
 const material=await createLegacyObjectInstallMaterial(product);
 const {compilePackageMaterial}=await load('workspace-protocol-package-source'),compiled=compilePackageMaterial(material);
 const large={closureJson:JSON.stringify(material.closure),expectedRootPackageDigest:material.closure.root_package_digest,expectedProtocolDigest:compiled.protocolDigest,instanceId:secureToken(),entrypoint:'large_protocol',grantsJson:'[]'};
 const envelope=save('large-selection.json',{closure_json:large.closureJson,expected_root_package_digest:large.expectedRootPackageDigest,expected_protocol_digest:large.expectedProtocolDigest,instance_id:large.instanceId,entrypoint:large.entrypoint,grants_json:large.grantsJson});
 const prePosts=posts,preBegins=beginPosts;
 dropAction='secure.protocol-object.stage';
 let automatic=await command('owner-private-install-begin-direct',configPath,ws,envelope);
 assert.equal(automatic.step_action_id,'secure.protocol-object.stage');assert.equal(beginPosts,preBegins);
 const automaticId=automatic.begin_command_id;
 assert((await command('owner-private-install-list',configPath,ws)).some(x=>x.begin_command_id===automaticId&&x.phase==='OBJECT_STAGING'));
 for(let i=0;i<16&&automatic.status!=='ACCEPTED';i++)automatic=await command('owner-private-install-continue',configPath,ws,automaticId);
 assert.equal(automatic.status,'ACCEPTED');assert.equal(automatic.begin_command_id,automaticId);assert.equal(beginPosts,preBegins+1);
 const staged=await agent.journal(ws);assert.equal(staged.structure.state,'ACTIVE');assert(staged.objects.some(o=>o.kind==='instances'&&o.id===large.instanceId));
 assert(staged.installations.some(x=>x.instance_id===large.instanceId&&x.object_source));
 pass('oversized-direct-install-automatically-stages-exact-parts-and-survives-response-loss-and-restart');
 // Show the released producer's exact defect on synthetic data, then refuse to
 // turn the immutable invalid packet into accepted history by relaxing replay.
 const invalidMaterial=await createLegacyObjectInstallMaterial(product,7),invalidCompiled=compilePackageMaterial(invalidMaterial);
 const invalidSelection={...large,closureJson:JSON.stringify(invalidMaterial.closure),expectedRootPackageDigest:invalidMaterial.closure.root_package_digest,expectedProtocolDigest:invalidCompiled.protocolDigest,instanceId:secureToken(),grantsJson:JSON.stringify([{actor_id:agent.identity.actorId,actions:['discussion.post'],protocol_roles:['CONTRIBUTOR'],capabilities:['POST']}])};
 const withoutConfig={...config,stateDir:join(out,'without-object-source')};hideObjectSource=true;
 const without=sdk.openSecureOwnerWorkspaces(withoutConfig),withoutSpace=await without.create({name:'Missing object-source capability',visibility:'PRIVATE',structured:true});assert.equal(withoutSpace.status,'CREATED');
 const unsupportedConfig=save('without-source-config.json',{origin,state_dir:withoutConfig.stateDir,allow_loopback_http:true});
 const unsupportedEnvelope=save('without-source-selection.json',{closure_json:invalidSelection.closureJson,expected_root_package_digest:invalidSelection.expectedRootPackageDigest,expected_protocol_digest:invalidSelection.expectedProtocolDigest,instance_id:secureToken(),entrypoint:'unsupported_large',grants_json:'[]'});
 const unsupportedPosts=posts;assert.equal((await command('owner-private-install-begin-direct',unsupportedConfig,withoutSpace.workspace_id,unsupportedEnvelope,{ok:false})).code,'INSTALL_OBJECT_SOURCE_UNSUPPORTED');assert.equal(posts,unsupportedPosts);hideObjectSource=false;
 pass('service-without-source-capability-gets-actionable-preflight-refusal-and-zero-POSTs');
 const oversized=await native.privatePackageInstaller(ws).beginDirect(invalidSelection);assert.equal(oversized.step_action_id,'secure.structure.begin');
 const invalidId=oversized.begin_command_id,profile=join(config.stateDir,'workspaces',ws,'read.profile'),floorHash=hash(profile),invalidPosts=posts;
 const invalid=await command('owner-private-install-diagnose',configPath,ws,invalidId);assert.equal(invalid.verified,false);assert.equal(invalid.check,'object.size');assert.equal(invalid.stage,'install.fresh');assert.equal(posts,invalidPosts);assert.equal(hash(profile),floorHash);assert.equal(hash(identity),identityHash);
 pass('released-oversized-BEGIN-reproduces-1058-class-failure-without-leaking-content-or-replacing-ACTIVE');
 const refused=await command('owner-private-install-continue',configPath,ws,invalidId,{ok:false});assert.equal(refused.code,'VERIFICATION_FAILED');assert.match(refused.message,/object.size/);assert.equal(posts,invalidPosts);assert.equal(hash(profile),floorHash);
 pass('immutable-invalid-BEGIN-cannot-be-completed-with-signature-or-size-bypass');
 const planPosts=posts;hideRecoveryCapability=true;
 assert.equal((await command('owner-private-install-recovery-plan',configPath,ws,invalidId,{ok:false})).code,'INSTALL_RECOVERY_SERVICE_UNSUPPORTED');assert.equal(posts,planPosts);hideRecoveryCapability=false;
 pass('older-service-capability-is-diagnosed-before-any-recovery-write');
 const plan=await command('owner-private-install-recovery-plan',configPath,ws,invalidId);
 if(currentSdk)assert.deepEqual(await currentSdk.openSecureOwnerWorkspaces(config).privatePackageInstaller(ws).recoveryPlan(invalidId),plan);
 if(pythonPath)assert.deepEqual(await python('plan',configPath,ws,invalidId),plan);
 if(currentSdk&&pythonPath)pass('installed-Node-Python-sync-async-CLI-review-plan-parity');
 assert.equal(posts,planPosts);assert.equal(plan.original_begin_id,invalidId);assert.equal(plan.recovery.through.sequence-plan.recovery.base.sequence,1);
 assert.equal(plan.new_begin_required,true);assert.equal(plan.submitted,false);pass('read-only-native-recovery-plan-binds-exact-original-BEGIN-and-single-invalid-suffix');
 const operation=secureToken(),request=save('reviewed-recovery.json',{begin_command_id:invalidId,expected_review_hash:plan.review_hash,operation_id:operation});
 const wrong=save('wrong-recovery.json',{begin_command_id:invalidId,expected_review_hash:'0'.repeat(64),operation_id:secureToken()});
 assert.equal((await command('owner-private-install-recover',configPath,ws,wrong,{ok:false})).code,'INSTALL_RECOVERY_REVIEW_CONFLICT');assert.equal(posts,planPosts);pass('wrong-review-hash-refused-before-any-POST');
 const beforeRecovery=await agent.inspectRecovery(ws);
 const currentPolicy=JSON.parse(db.prepare('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?').get(ws,beforeRecovery.recovery.through.policy_hash).artifact);
 const basePolicy=JSON.parse(db.prepare('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?').get(ws,beforeRecovery.recovery.base.policy_hash).artifact);
 const firstInvalid=JSON.parse(db.prepare('SELECT artifact FROM secure_commits WHERE workspace_id=? AND sequence=?').get(ws,beforeRecovery.recovery.through.sequence).artifact);
 const {validateInstallRecoveryPolicy}=await load('workspace-secure-recovery');
 const target=structuredClone(currentPolicy);target.payload.structure=basePolicy.payload.structure;
 validateInstallRecoveryPolicy(currentPolicy,target,basePolicy,firstInvalid,beforeRecovery.recovery);
 const changedAuthority=structuredClone(target);changedAuthority.payload.members=[];
 assert.throws(()=>validateInstallRecoveryPolicy(currentPolicy,changedAuthority,basePolicy,firstInvalid,beforeRecovery.recovery),/RECOVERY_INSTALL_POLICY_AUTHORITY_CHANGED/);
 const changedStructure=structuredClone(target);changedStructure.payload.structure=before.policy.payload.structure;
 assert.throws(()=>validateInstallRecoveryPolicy(currentPolicy,changedStructure,basePolicy,firstInvalid,beforeRecovery.recovery),/RECOVERY_INSTALL_POLICY_TARGET_INVALID/);
 const wide=structuredClone(beforeRecovery.recovery);wide.base.sequence--;
 assert.throws(()=>validateInstallRecoveryPolicy(currentPolicy,target,basePolicy,firstInvalid,wide),/RECOVERY_INSTALL_POLICY_RANGE_INVALID/);
 assert.equal(posts,planPosts);pass('recovery-policy-cannot-change-membership-target-structure-or-widen-the-excluded-range');
 denyRecovery=true;
 await command('owner-private-install-recover',configPath,ws,request,{ok:false});
 const pendingPlan=await command('owner-private-install-recovery-plan',configPath,ws,invalidId);assert.equal(pendingPlan.operation_id,operation);assert.equal(pendingPlan.review_hash,plan.review_hash);
 const recoveryState=join(config.stateDir,'workspaces',ws,'private-install-recoveries.state'),savedRecovery=readFileSync(recoveryState),stateMagic=Buffer.from('PEERWORK-NATIVE-SECURE-STATE\n1\n');
 const corrupt=JSON.parse(savedRecovery.subarray(stateMagic.length));corrupt.rows[operation].request_b64=Buffer.from('{}').toString('base64url');
 writeFileSync(recoveryState,Buffer.concat([stateMagic,Buffer.from(JSON.stringify(corrupt))]),{mode:0o600});const beforeCorrupt=posts;
 try{assert.equal((await command('owner-private-install-recover',configPath,ws,request,{ok:false})).code,'INSTALL_PLAN_FAILED');assert.equal(posts,beforeCorrupt);}finally{writeFileSync(recoveryState,savedRecovery,{mode:0o600});}
 denyRecovery=false;pass('pending-recovery-discovery-and-corrupt-saved-packet-refusal-before-POST');
 dropAction='secure.recover';
 let recovered=currentSdk?await currentSdk.openSecureOwnerWorkspaces(config).privatePackageInstaller(ws).recoverInvalid(invalidId,{expectedReviewHash:plan.review_hash,operationId:operation}):await command('owner-private-install-recover',configPath,ws,request);
 if(pythonPath&&recovered.status!=='ACCEPTED')recovered=await python('recover',configPath,ws,request);
 for(let i=0;i<16&&recovered.status!=='ACCEPTED';i++)recovered=await command('owner-private-install-recover',configPath,ws,request);
 assert.equal(recovered.status,'ACCEPTED');assert.equal(recovered.operation_id,operation);assert.equal(hash(identity),identityHash);
 const restored=await agent.journal(ws);assert.equal(restored.structure.state,'ACTIVE');
 assert.equal(restored.recoveries.at(-1).excluded_count,1);assert.equal(restored.recoveries.at(-1).through.head,beforeRecovery.recovery.through.head);
 for(const old of staged.objects)assert(restored.objects.some(o=>o.kind===old.kind&&o.id===old.id&&o.revision===old.revision&&JSON.stringify(o)===JSON.stringify(old)));
 const policyAtInvalid=JSON.parse(db.prepare('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?').get(ws,beforeRecovery.recovery.through.policy_hash).artifact);
 assert.deepEqual(restored.policy.payload.members,policyAtInvalid.payload.members);assert.equal(restored.policy.payload.epoch,policyAtInvalid.payload.epoch);assert.deepEqual(restored.policy.payload.guard_time,policyAtInvalid.payload.guard_time);
 pass('reviewed-native-recovery-survives-response-loss-and-restores-ACTIVE-with-membership-keys-and-old-records');
 const recoveredPosts=posts;assert.equal((await command('owner-private-install-recover',configPath,ws,request)).status,'ACCEPTED');assert.equal(posts,recoveredPosts);
 assert.equal((await command('owner-private-install-continue',configPath,ws,invalidId,{ok:false})).code,'INSTALL_RECOVERED_NEW_BEGIN_REQUIRED');
 assert((await command('owner-private-install-list',configPath,ws)).some(r=>r.begin_command_id===invalidId&&r.recovered_by===operation));pass('original-BEGIN-retained-as-terminal-history-and-accepted-recovery-does-not-repost');
 const replacement=save('replacement-selection.json',{closure_json:invalidSelection.closureJson,expected_root_package_digest:invalidSelection.expectedRootPackageDigest,expected_protocol_digest:invalidSelection.expectedProtocolDigest,instance_id:invalidSelection.instanceId,entrypoint:invalidSelection.entrypoint,grants_json:invalidSelection.grantsJson});
 let installed=await command('owner-private-install-begin-direct',configPath,ws,replacement);const newBegin=installed.begin_command_id;assert.notEqual(newBegin,invalidId);
 for(let i=0;i<16&&installed.status!=='ACCEPTED';i++)installed=await command('owner-private-install-continue',configPath,ws,newBegin);
 assert.equal(installed.status,'ACCEPTED');const final=await agent.journal(ws);assert.equal(final.structure.state,'ACTIVE');assert(final.objects.some(o=>o.kind==='instances'&&o.id===invalidSelection.instanceId));assert.equal(hash(identity),identityHash);
 pass('replacement-BEGIN-uses-automatic-fragmentation-and-completes-with-original-identity-history-and-keys');
 report.status='PASS';save('verification.json',report);console.log(JSON.stringify(report));
} catch(e){report.status='FAIL';report.error={code:e.code,message:e.message};save('verification.json',report);throw e;}
finally{if(agent)await agent.close();await new Promise(r=>server.close(r));db.close();}
