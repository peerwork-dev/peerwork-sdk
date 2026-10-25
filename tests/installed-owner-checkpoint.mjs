// Real installed Node + wheel + CLI. All keys and legacy data are generated;
// candidate source/dist hashes are pinned exactly as in the other acceptance.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash,createPublicKey,sign as cryptoSign} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {performance} from 'node:perf_hooks';

const exec=promisify(execFile),root=resolve(process.env.PEERWORK_STRUCTURE_REFERENCE_ROOT),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX);
const reference=JSON.parse(readFileSync(process.env.PEERWORK_STRUCTURE_REFERENCE_MANIFEST,'utf8'));
assert.equal(reference.format,'peerwork.structure-candidate.v1');
for(const [file,expected]of Object.entries(reference.files))assert.equal(createHash('sha256').update(readFileSync(join(root,file))).digest('hex'),expected,`frozen reference changed: ${file}`);
const product=async path=>import(pathToFileURL(join(root,path)).href);
const {serve}=await import(pathToFileURL(join(root,'node_modules/@hono/node-server/dist/index.mjs')).href);
const {PostgresStore}=await product('dist-workspace/src/workspace-postgres-store.js');
const {PostgresKernel}=await product('dist-workspace/src/workspace-postgres-kernel.js');
const {createPostgresControlApp}=await product('dist-workspace/src/workspace-postgres-http.js');
const {importSqliteArchive}=await product('dist-workspace/src/workspace-postgres-import.js');
const {importOwnerCheckpoint,activateOwnerCheckpoints}=await product('dist-workspace/src/workspace-postgres-owner-checkpoint.js');
const {ownerCheckpointSource,nodeIdentityFromNative}=await product('dist-workspace/tests/fixtures/workspace-owner-checkpoint-fixture.js');
const {verifyKernelJws,signKernelJws}=await product('dist-workspace/src/workspace-jws.js');
const {RECEIPT_TYPE,COMMAND_TYPE,hash,canonicalStructured}=await product('dist-workspace/src/workspace-contract.js');
const {checkpointSeed,checkpointAdvance}=await product('dist-workspace/src/workspace-owner-checkpoint.js');
const sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');
const directory=mkdtempSync(join(resolve(process.env.TMPDIR),'installed-checkpoint-'));let source,server,store,ready=false,tamper=false,tamperSelected=false,dropped=0,journalReads=0;
const schema='installed_checkpoint_'+createHash('sha256').update(directory).digest('hex').slice(0,20),timings={};
try{
 const ownerDir=join(directory,'owner'),workerDir=join(directory,'worker');mkdirSync(ownerDir,{mode:0o700});mkdirSync(workerDir,{mode:0o700});
 const identityPath=join(ownerDir,'identity.state'),owner=await sdk.createIdentity(identityPath),before=readFileSync(identityPath);
 const previous=process.cwd();process.chdir(root);try{source=await ownerCheckpointSource(directory,17,nodeIdentityFromNative(identityPath));}finally{process.chdir(previous);}
 assert.equal(source.actor,owner.actor_id);
 store=new PostgresStore({connectionString:process.env.PEERWORK_POSTGRES_TEST_URL,schema});
 const kernel=new PostgresKernel(store,'checkpoint-test',Buffer.alloc(32,7),Date.now,{afterCommit(response){
  const author=response.result.author_intent;
  if(dropped===0&&author&&JSON.parse(Buffer.from(author.split('.')[1],'base64url')).action_id==='structure.action'){dropped++;throw new Error('synthetic lost action response');}
 }});
 await store.initialize('checkpoint-test',kernel.discovery().receipt_public_key,{importing:true});
 const app=createPostgresControlApp(kernel);
 server=serve({hostname:'127.0.0.1',port:0,fetch:async(request,env)=>{
  if(new URL(request.url).pathname.endsWith('/journal'))journalReads++;
  if(!ready)return new Response('isolated conversion target',{status:503});
  const response=await app.fetch(request,env);
  if((!tamper&&!tamperSelected)||request.method!=='POST'||!response.ok)return response;
  const data=await response.clone().json();
  if(tamperSelected&&data.result?.source?.legacy_source)data.result.source.legacy_source.record_actor_id='A'.repeat(43);
  else if(tamper&&data.result?.records?.length)data.result.records[0].structure.status='forged by service';
  else return response;
  const receipt=verifyKernelJws(data.receipt,RECEIPT_TYPE).payload;receipt.result_digest=hash(canonicalStructured(data.result));data.receipt=signKernelJws(receipt,RECEIPT_TYPE,kernel.receiptKey);
  const headers=new Headers(response.headers);headers.delete('content-length');return new Response(JSON.stringify(data),{status:200,headers});
 }});await new Promise(resolve=>server.once('listening',resolve));const origin=`http://127.0.0.1:${server.address().port}/`;
 const outputPath=join(ownerDir,'checkpoint.jsonl');let start=performance.now();
 const prepared=await sdk.prepareOwnerCheckpoint({identityPath,expectedActor:owner.actor_id,origin,audience:'checkpoint-test',sourcePath:source.sourcePath,planPath:source.planPath,outputPath,allowLoopbackHttp:true});
 timings.offline_prepare_ms=Math.round(performance.now()-start);assert.equal(prepared.pages,4);assert.equal(prepared.records,17);assert.equal(prepared.network_requests,0);
 const frozen=readFileSync(outputPath);const reused=await sdk.prepareOwnerCheckpoint({identityPath,expectedActor:owner.actor_id,origin,audience:'checkpoint-test',sourcePath:source.sourcePath,planPath:source.planPath,outputPath,allowLoopbackHttp:true});assert.equal(reused.reused,true);assert.deepEqual(readFileSync(outputPath),frozen);
 // Peers may sign valid JSON in any member order. Re-sign this synthetic
 // Owner's same statements in reverse member order, leaving body AAD/keys
 // unchanged; the installed verifier must compare JSON values canonically.
 const reverse=value=>Array.isArray(value)?value.map(reverse):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).reverse().map(([key,child])=>[key,reverse(child)])):value;
 const signCommand=command=>{const header=Buffer.from(JSON.stringify({alg:'EdDSA',typ:COMMAND_TYPE,kid:createPublicKey(source.privateKey).export({format:'jwk'}).x})).toString('base64url'),payload=Buffer.from(JSON.stringify(reverse(command))).toString('base64url'),input=`${header}.${payload}`;return `${input}.${cryptoSign(null,Buffer.from(input),source.privateKey).toString('base64url')}`;};
 const packets=frozen.toString('utf8').trimEnd().split('\n').map(line=>JSON.parse(line).jws),begin=JSON.parse(Buffer.from(packets[0].split('.')[1],'base64url'));let chain=checkpointSeed(begin.body.source,begin.body.mapping_digest,begin.body.conversion_id);const reordered=[];
 for(let index=0;index<packets.length-1;index++){const command=JSON.parse(Buffer.from(packets[index+1].split('.')[1],'base64url'));command.body.previous_digest=chain;const jws=signCommand(command);reordered.push(jws);chain=checkpointAdvance(chain,index,jws);}
 begin.body.final_digest=chain;const importPath=join(ownerDir,'interoperable-checkpoint.jsonl');writeFileSync(importPath,[signCommand(begin),...reordered].map(jws=>JSON.stringify({jws})+'\n').join(''),{mode:0o600});
 start=performance.now();await importSqliteArchive(store,{snapshotPath:source.snapshot,expectedSha256:source.snapshotSha,batchRows:32});timings.raw_archive_ms=Math.round(performance.now()-start);
 start=performance.now();await assert.rejects(importOwnerCheckpoint(kernel,importPath,{afterPage({next_page}){if(next_page===2)throw new Error('synthetic conversion transport loss');}}),/synthetic conversion transport loss/);
 const converted=await importOwnerCheckpoint(kernel,importPath);assert.equal(converted.pages_this_run,2);assert.equal(converted.records,17);assert.equal(converted.status,'CONVERTED');assert.ok(converted.bytes_read<readFileSync(importPath).length);
 await activateOwnerCheckpoints(kernel,source.snapshotSha);timings.convert_resume_activate_ms=Math.round(performance.now()-start);ready=true;
 assert.equal((await importOwnerCheckpoint(kernel,importPath)).pages_this_run,0);assert.equal((await activateOwnerCheckpoints(kernel,source.snapshotSha)).already_applied,true);
 const context=await sdk.bindStructureContext({profilePath:join(ownerDir,'context.json'),expectedActor:owner.actor_id,expectedService:'checkpoint-candidate',origin,identityPath,journalPath:join(ownerDir,'operations.sqlite'),workspaceIds:[source.workspace],authority:source.authority,allowLoopbackHttp:true});
 const selection={action:'structure.records.read',instance_id:source.instance,protocol_digest:source.protocol,body:{limit:32}};
 const read=await context.executeStructureIntent(source.workspace,selection);assert.equal(read.status,'verified');assert.equal(read.result.records.length,17);assert.equal(read.opened_contents.length,17);
 assert.equal(read.result.records[0].structure.source_created_at,'2001-02-03T04:05:06.123456789+08:00');
 for(const content of read.opened_contents){assert.equal(content.state,'OPENED');assert.equal(content.text,'Converted private body 🚀');}
 assert.equal(JSON.stringify(read.result).includes('Converted private body'),false);assert.equal(JSON.stringify(read.result).includes('NEVER DISCLOSE'),false);
 tamper=true;const forged=await context.executeStructureIntent(source.workspace,selection);assert.equal(forged.status,'pending');assert.equal(forged.result.code,'VERIFICATION_FAILED');assert.equal(forged.result.records,undefined);tamper=false;
 const worker=await sdk.createIdentity(join(workerDir,'identity.state'));
 const admitted=await context.operate(source.workspace,{kind:'structure.intent',request:{action:'structure.member.set',expected_workspace_revision:1,body:{actor_id:worker.actor_id,state:'ACTIVE',expected_membership_id:null}}},'admit-worker');assert.equal(admitted.status,'verified');
 const grant=await context.operate(source.workspace,{kind:'structure.intent',request:{action:'structure.grant.set',instance_id:source.instance,protocol_digest:source.protocol,body:{actor_id:worker.actor_id,membership_id:admitted.result.membership_id,expected_grant_revision:null,actions:['lease.claim','lease.renew','lease.use'],protocol_roles:source.manifest.protocol_roles,capabilities:source.manifest.capabilities}}},'grant-worker');assert.equal(grant.status,'verified');
 const input=join(directory,'worker.json');writeFileSync(input,JSON.stringify({origin,workspace:source.workspace,instance:source.instance,protocol:source.protocol,worker:worker.actor_id,worker_dir:workerDir}),{mode:0o600});
 const python=await exec(process.env.PEERWORK_TEST_PYTHON??'python3',[new URL('./installed-owner-checkpoint.py',import.meta.url).pathname,input],{env:{...process.env,PYTHONPATH:join(prefix,'python')},timeout:60000,maxBuffer:262144});assert.equal(JSON.parse(python.stdout).status,'PASS');
 const current=await context.describe(source.workspace,{instanceId:source.instance,protocolDigest:source.protocol});assert.equal(current.result.state.holder,worker.actor_id);assert.equal(current.result.state.last_result,'Converted work delivered');
 // The installed client must verify the original signed business intent of
 // a valid program larger than an ordinary action, including durable reopen.
 const largeManifest=structuredClone(source.manifest),fields=Object.fromEntries(Array.from({length:12},(_,n)=>['field'+n,'string']));
 for(let n=0;n<60;n++)largeManifest.record_schemas['metadata'+n]={type:'object',fields,required:Object.keys(fields),max_bytes:2048};
 const largeIntent={kind:'structure.intent',request:{action:'structure.adopt',body:{manifest:largeManifest,bootstrap_grant:{actions:['lease.claim'],protocol_roles:source.manifest.protocol_roles,capabilities:source.manifest.capabilities}}}};
 const large=await context.operate(source.workspace,largeIntent,'installed-large-adopt');assert.equal(large.status,'verified');
 const largeAgain=await context.operate(source.workspace,largeIntent,'installed-large-adopt');assert.equal(largeAgain.status,'verified');assert.equal(largeAgain.command_id,large.command_id);
 const recoveredLarge=await context.recover(source.workspace,{operationId:'installed-large-adopt'});assert.equal(recoveredLarge.status,'verified');assert.equal(recoveredLarge.command_id,large.command_id);
 const request=join(directory,'cli.json');writeFileSync(request,JSON.stringify({workspace_id:source.workspace,expected_fingerprint:context.descriptor.fingerprint,intent:{...selection,body:{limit:1}}}),{mode:0o600});
 const cli=await exec(join(prefix,'bin/peerwork'),['context','execute-structure',join(ownerDir,'context.json'),owner.actor_id,'checkpoint-candidate',request],{timeout:30000,maxBuffer:262144});const cliResult=JSON.parse(cli.stdout);assert.equal(cliResult.ok,true);assert.equal(cliResult.value.opened_contents[0].text,'Converted private body 🚀');
 const scope={instance_id:source.instance,protocol_digest:source.protocol},selectedRecord=read.result.records[0],metadata=await context.executeStructureIntent(source.workspace,{action:'structure.workspace.get',body:{}});
 const view=await context.executeStructureIntent(source.workspace,{action:'structure.publication.set',expected_workspace_revision:metadata.result.workspace_revision,body:{state:'PUBLIC',expected_publication_revision:0,title:'Converted historical notes',description:'Synthetic conversion qualification',disclosure:'PUBLISH_SELECTED_CONTENT'}});assert.equal(view.status,'verified');
 const publicationSelection={...scope,record_id:selectedRecord.record_id,revision:selectedRecord.revision,idempotency_key:'converted-public-entry',title:'Original converted note',disclosure:'PUBLISH_SELECTED_CONTENT',body:{from:'RECORD'}};
 tamperSelected=true;const forgedAttribution=await context.publishSelectedRecord(source.workspace,publicationSelection);assert.equal(forgedAttribution.status,'pending');assert.equal(forgedAttribution.result.code,'VERIFICATION_FAILED');assert.equal(forgedAttribution.result.phase,'PREPARATION');assert.equal(forgedAttribution.result.effect_certainty,'NOT_SUBMITTED');assert.equal(forgedAttribution.result.retryable,false);assert.ok(forgedAttribution.command_id);tamperSelected=false;
 const snapshotStart=performance.now(),publication=await context.publishSelectedRecord(source.workspace,publicationSelection);assert.equal(publication.status,'verified');timings.converted_publication_ms=Math.round(performance.now()-snapshotStart);
 const publicOrigin=origin.replace(/\/$/,''),reader=new sdk.PublicationReader({controlOrigin:publicOrigin,browserOrigin:publicOrigin,workspaceId:source.workspace,ownerActorId:owner.actor_id,ownerKeyId:owner.key_id,allowLoopbackHttp:true}),entry=(await reader.get(selectedRecord.record_id)).result.entries[0];
 assert.equal(entry.text,'Converted private body 🚀');assert.equal(entry.source.actor_id,owner.actor_id);assert.equal(entry.source.attribution.assurance,'OWNER_ATTESTED_CONVERSION');assert.equal(entry.source.attribution.actor_id,selectedRecord.source.legacy_source.record_actor_id??null);assert.equal(entry.source.attribution.created_at,selectedRecord.source.legacy_source.created_at??null);assert.deepEqual(entry.source.attribution.legacy_source,selectedRecord.source.legacy_source);
 const changelog=await new sdk.ChangelogClient({source:{origin:publicOrigin,browser_origin:publicOrigin,control_origin:publicOrigin,workspace_id:source.workspace,owner_actor_id:owner.actor_id,owner_key_id:owner.key_id,instance_id:source.instance,allow_loopback_http:true}}).read();assert.equal(changelog.entries[0].attribution_assurance,'OWNER_ATTESTED_CONVERSION');assert.equal(changelog.entries[0].source_signer_actor_id,owner.actor_id);assert.equal(changelog.entries[0].created_at,selectedRecord.source.legacy_source.created_at??null);
 assert.deepEqual(readFileSync(identityPath),before);assert.equal(journalReads,0);assert.equal(dropped,1);
 console.log(JSON.stringify({status:'PASS',installed:{node:true,python_wheel:true,cli:true},profile:'backend-structure-v1',legacy_mode:'PRIVATE_ENCRYPTED',converted_records:17,prepared_pages:4,resumed_pages:2,identities_preserved:true,journal_reads:journalReads,lost_action_replies:dropped,forged_service_projection:'REJECTED_BY_OWNER_SIGNATURE',checks:['explicit-field-mapping','offline-body-encryption','automatic-page-splitting','exact-artifact-reuse','archive-preserved','committed-offset-resume','separate-activation','source-verified-body-opening','narrow-worker-grant','claim-renew-deliver','exact-action-recovery','CLI-source-verification','native-converted-publication','historical-attribution-service-forgery-rejected','anonymous-historical-changelog'],timings}));
}finally{
 if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 if(source)source.close();if(store){try{await store.pool.query(`DROP SCHEMA IF EXISTS "${schema}_archive" CASCADE;DROP SCHEMA IF EXISTS "${schema}" CASCADE`);}finally{await store.close();}}
 rmSync(directory,{recursive:true,force:true});
}
