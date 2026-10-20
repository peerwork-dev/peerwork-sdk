// Self-generated old members; no real workspace, key or production service is used.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join,resolve} from 'node:path';
import {mkdirSync,writeFileSync,readFileSync,renameSync} from 'node:fs';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {execFile as callback} from 'node:child_process';
import {promisify} from 'node:util';
const execFile=promisify(callback),[referenceArg,cliArg,outArg]=process.argv.slice(2);
assert(referenceArg&&cliArg&&outArg);assert(process.env.PEERWORK_MIGRATION_PYTHON&&process.env.PEERWORK_MIGRATION_NODE_CONSUMER,'installed Python/Node consumer paths are required');const reference=resolve(referenceArg),cli=resolve(cliArg),out=resolve(outArg);mkdirSync(out,{mode:0o700});
const require=createRequire(join(reference,'package.json')),load=n=>import(pathToFileURL(join(reference,'dist-workspace/src',n+'.js')));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server'))),{openKernel,WorkspaceKernel}=await load('workspace-kernel');
const {createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent'),{secureToken,secureHash}=await load('workspace-secure-client');
const db=openKernel(join(out,'control.sqlite'),'legacy-member-migration'),kernel=new WorkspaceKernel(db,'legacy-member-migration',Buffer.alloc(32,85));
const app=createWorkspaceControlApp(kernel);let posts=0,tamperNextInvitation=false;
const server=serve({hostname:'127.0.0.1',port:0,fetch:async(req,env,ctx)=>{if(req.method==='POST')posts++;
 const response=await app.fetch(req,env,ctx);
 if(tamperNextInvitation&&req.method==='GET'&&new URL(req.url).pathname.startsWith('/api/workspace/v1/secure/invitations/')){
  tamperNextInvitation=false;const item=await response.json();item.decision.signature='invalid';return new Response(JSON.stringify(item),{status:200,headers:{'content-type':'application/json'}});
 }
 return response;}});
await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port,clients=[],report={status:'RUNNING',cases:[],synthetic_only:true};
const hash=p=>createHash('sha256').update(readFileSync(p)).digest('hex');const save=(p,v)=>writeFileSync(p,JSON.stringify(v),{mode:0o600});let commandNo=0;
async function command(args,ok=true){let run;try{run=await execFile(cli,args,{timeout:120000,maxBuffer:8*1024*1024});}catch(e){run=e;}
 const text=run.stdout?.trim()||run.stderr?.trim();assert(text,'Empty command result');const result=JSON.parse(text);save(join(out,'command-'+(++commandNo)+'.json'),{verb:args[1],value:result});if(ok)assert(!result.code,JSON.stringify(result));return result;}
async function open(name){const dir=join(out,name);mkdirSync(dir,{mode:0o700});const key=generateKeyPairSync('ed25519').privateKey,pem=join(dir,'signer.pem'),state=join(dir,'agent.state'),intents=join(dir,'intents.sqlite');writeFileSync(pem,key.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 const agent=await SecureAgentClient.open({baseUrl:origin,privateKey:key,statePath:state,intentDbPath:intents});clients.push(agent);return {dir,pem,state,intents,agent};}
try{
 const help=await command(['secure','recipient-import-legacy-keys','--help']);assert(help.required_input_fields.includes('expected_source_digest'));report.cases.push({name:'cli-import-schema-discovery',status:'PASS'});
 const owner=await open('owner'),workers=[await open('worker-one'),await open('worker-two')],workspaces=[];
 await owner.agent.publishIdentity();for(const w of workers){await w.agent.publishIdentity();await owner.agent.trustIdentity(w.agent.identity.actorId);await w.agent.trustIdentity(owner.agent.identity.actorId);}
 for(const label of ['A','B']){
  const {workspaceId:id}=await owner.agent.create('Member migration '+label,'PRIVATE',{structure:true});let journal=await owner.agent.journal(id);const wiki=journal.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='wiki').id;
  for(const w of workers){const offer=await owner.agent.inviteActor(id,w.agent.identity.actorId,[{instance_id:wiki,actions:['wiki.create'],protocol_roles:['EDITOR'],capabilities:['EDIT']}],'Existing synthetic worker');await w.agent.decideAdmission(offer.payload.invite_id,'ACCEPT');await owner.agent.deliverAdmission(offer.payload.invite_id);await w.agent.receiveAdmission(offer.payload.invite_id);}
  await owner.agent.action(id,wiki,'wiki.create',{title:'Before migration '+label,body:'Encrypted before native import'});workspaces.push({id,wiki,label});
 }
 // Rotate the recipient directory keys, while both workspace grants still use
 // historical certificates. Native reads must recover those historical keys.
 for(const w of workers){await w.agent.updateIdentityKey(secureToken(),{mode:'ROTATE',expected_certificate_hash:await secureHash(w.agent.state.certificate)});await w.agent.close();}
 const sourceHashes=workers.map(w=>[hash(w.pem),hash(w.state),hash(w.intents)]),pins={owner_actor:owner.agent.identity.actorId,owner_key:owner.agent.identity.keyId};
 for(const [index,w] of workers.entries()){
  const profile=join(out,'native-worker-'+index);mkdirSync(profile,{mode:0o700});await command(['identity','import-legacy-pem',join(profile,'identity.state'),w.pem]);
  w.profile=profile;w.input={protected_ts_state_path:w.state,expected_actor_id:w.agent.identity.actorId,expected_signing_key_id:w.agent.identity.keyId,expected_source_digest:hash(w.state)};
  const config={origin,state_dir:profile,identity_path:join(profile,'identity.state'),workspace_id:workspaces[0].id,owner_actor_id:pins.owner_actor,owner_key_id:pins.owner_key,allow_loopback_http:true};w.config=join(out,'worker-'+index+'-read.json');save(w.config,config);
  const before=posts;const fixture=join(out,'worker-'+index+'.json');save(fixture,{origin,profile,input:w.input,workspaces,...pins});
  if(index===0&&process.env.PEERWORK_MIGRATION_NODE_CONSUMER){tamperNextInvitation=true;const ran=await execFile(process.execPath,[new URL('legacy-member-keys-consumer.mjs',import.meta.url).pathname,process.env.PEERWORK_MIGRATION_NODE_CONSUMER,fixture],{timeout:180000,maxBuffer:1048576});assert.equal(JSON.parse(ran.stdout).status,'PASS');assert(!tamperNextInvitation);report.cases.push({name:'tampered-invitation-decision-refuses-before-honest-retry',status:'PASS'});}
  else if(index===1&&process.env.PEERWORK_MIGRATION_PYTHON){const ran=await execFile(process.env.PEERWORK_MIGRATION_PYTHON,[new URL('legacy-member-keys-consumer.py',import.meta.url).pathname,fixture],{timeout:180000,maxBuffer:1048576});assert.equal(JSON.parse(ran.stdout).status,'PASS');}
  else {const input=join(out,'worker-'+index+'-input.json');save(input,w.input);assert.equal((await command(['secure','recipient-import-legacy-keys','--origin='+origin,'--state-dir='+profile,'--input='+input])).status,'IMPORTED');}
  assert.equal(posts,before,'credential import/read caused a mutation POST');
  const input=join(out,'worker-'+index+'-retry.json');save(input,w.input);assert.equal((await command(['secure','recipient-import-legacy-keys','--origin='+origin,'--state-dir='+profile,'--input='+input])).status,'ALREADY_IMPORTED');
  w.profiles={[workspaces[0].id]:profile};
  // Generic read profiles bind one workspace; import the same credentials into
  // the second explicit workspace profile without replacing the first profile.
  const second=join(out,'native-worker-'+index+'-B');mkdirSync(second,{mode:0o700});await command(['identity','import-legacy-pem',join(second,'identity.state'),w.pem]);
  assert.equal((await command(['secure','recipient-import-legacy-keys','--origin='+origin,'--state-dir='+second,'--input='+input])).status,'IMPORTED');w.profiles[workspaces[1].id]=second;assert.equal(posts,before);
  assert.deepEqual([hash(w.pem),hash(w.state),hash(w.intents)],sourceHashes[index]);report.cases.push({name:'worker-'+index+'-installed-import-history-A-B-and-idempotent-cli',status:'PASS',mutation_posts:0});
 }
 // A cross-worker source cannot replace an already imported recipient.
 const request=join(out,'cross-worker.json');save(request,workers[1].input);const target=join(workers[0].profile,'recipient.state'),before=hash(target);
 assert.equal((await command(['secure','recipient-import-legacy-keys','--origin='+origin,'--state-dir='+workers[0].profile,'--input='+request],false)).code,'IDENTITY_CHANGED');assert.equal(hash(target),before);
 report.cases.push({name:'cross-worker-source-refused-without-recipient-change',status:'PASS'});
 for(const w of workers)renameSync(w.dir,w.dir+'-source-unavailable');
 // Fresh CLI reads succeed after all original member files are unavailable.
 for(const [index,w] of workers.entries())for(const ws of workspaces){const config=JSON.parse(readFileSync(w.config));config.workspace_id=ws.id;config.state_dir=w.profiles[ws.id];config.identity_path=join(config.state_dir,'identity.state');const file=join(out,'reopen-'+index+'-'+ws.label+'.json');save(file,config);
  const read=await command(['secure','private-read','--origin='+origin,'--state-dir='+config.state_dir,'--identity='+config.identity_path,'--workspace='+ws.id,'--owner-actor='+pins.owner_actor,'--owner-key='+pins.owner_key,'--allow-loopback-http']);assert(read.objects.some(o=>o.value?.payload?.title==='Before migration '+ws.label));
  const request=join(out,'write-'+index+'-'+ws.label+'.json'),command_id=secureToken();save(request,{action_id:'wiki.create',instance_id:ws.wiki,body_json:JSON.stringify({title:'Native worker '+index+' '+ws.label,body:'Original identity after source removal'}),exact_input_refs_json:null,allocations_json:null,command_id,issued_at_ms:null});
  const result=await command(['secure','private-action-submit',file,request]);assert.equal(result.status,'PENDING');const accepted=await command(['secure','private-action-status',file,command_id]);assert.equal(accepted.status,'ACCEPTED');assert.equal(accepted.receipt.actor_id,w.input.expected_actor_id);report.cases.push({name:'worker-'+index+'-source-free-'+ws.label+'-read-and-write',status:'PASS'});
 }
 report.status='PASS';report.workers=2;report.workspaces=2;
}catch(error){if(error.stderr)writeFileSync(join(out,'consumer-error.stderr'),error.stderr,{mode:0o600});report.status='FAIL';report.error={message:String(error.message).slice(0,1800),stack:String(error.stack).split('\n').slice(0,8)};process.exitCode=1;}
finally{for(const c of clients)try{await c.close();}catch{}server.closeAllConnections();await new Promise(r=>server.close(r));db.close();save(join(out,'verification.json'),report);console.log(JSON.stringify(report));}
