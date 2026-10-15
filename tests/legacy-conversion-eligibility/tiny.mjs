// Exact official PUBLIC-v1 writer/conversion path; size preflight only.
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash}from'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,readdirSync}from'node:fs';
import {join,resolve}from'node:path';
import {createRequire}from'node:module';
import {pathToFileURL}from'node:url';
import {execFileSync}from'node:child_process';
const ref=resolve(process.argv[2]),out=resolve(process.argv[3]);mkdirSync(out,{mode:0o700});
assert.equal(execFileSync('git',['-C',ref,'rev-parse','HEAD'],{encoding:'utf8'}).trim(),'f828b6c50a0a58d1e718af90f653b214adcc3328');execFileSync('git',['-C',ref,'diff','--quiet','HEAD','--','src','package.json','package-lock.json']);
const files=[];function scan(d){for(const e of readdirSync(d,{withFileTypes:true})){const p=join(d,e.name);if(e.isDirectory())scan(p);else if(e.name.endsWith('.js'))files.push(p);}}const compiled=join(ref,'dist-workspace/src');scan(compiled);files.sort();const h=createHash('sha256');for(const p of files)h.update(p.slice(compiled.length+1)+'\0'+createHash('sha256').update(readFileSync(p)).digest('hex')+'\n');assert.equal(files.length,204);assert.equal(h.digest('hex'),'6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc');
const require=createRequire(join(ref,'package.json')),load=p=>import(pathToFileURL(join(compiled,p+'.js')).href);
const{serve}=await import(pathToFileURL(require.resolve('@hono/node-server')).href),{openKernel,WorkspaceKernel}=await load('workspace-kernel'),{createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent'),{WorkspaceProjector,initializePublicProjection}=await load('workspace-projector'),{encodeCanonicalJson}=await load('workspace-secure-crypto'),{verifyJournal}=await load('workspace-secure-client'),{validateSecureOperation}=await load('workspace-secure-engine');
const wire=x=>Buffer.from(encodeCanonicalJson(x)),bytes=x=>wire(x).length;const db=openKernel(join(out,'control.sqlite'),'t050'),kernel=new WorkspaceKernel(db,'t050',Buffer.alloc(32,73));

const {WorkspaceClient}=await load('workspace-client');
const server=serve({fetch:createWorkspaceControlApp(kernel).fetch,hostname:'127.0.0.1',port:0});let agent,legacy,projector;const calls=[],snapshots=[];
const save=(name,value)=>writeFileSync(join(out,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
try{
 await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port,key=generateKeyPairSync('ed25519').privateKey;
 initializePublicProjection(join(out,'public.sqlite'));projector=new WorkspaceProjector(join(out,'control.sqlite'),join(out,'public.sqlite'));
 const controlled=async(input,init)=>{const response=await fetch(input,init),path=new URL(input instanceof Request?input.url:String(input)).pathname;if(init?.method==='POST')calls.push({path,status:response.status,body_bytes:typeof init.body==='string'?Buffer.byteLength(init.body):null});if(path.endsWith('/conversion/snapshot')&&response.ok){const page=await response.clone().json();snapshots.push({object_count:page.objects.length,object_kinds:page.objects.map(o=>o.kind),object_wire_bytes:page.objects.map(bytes),fragment_count:page.objects.filter(o=>o.kind==='secure_fragment').length,source_root:page.source_root});}if(path.endsWith('/conversion/pages')&&response.ok)projector.publish(1000);return response;};
 legacy=await WorkspaceClient.open({baseUrl:origin,privateKey:key,intentDbPath:join(out,'legacy.sqlite'),fetch:controlled});
 const command=(action_id,body)=>legacy.submit({workspace_id:null,instance_id:null,protocol_digest:null,action_id,expected_workspace_revision:null,expected_instance_revision:null,exact_input_refs:[],body});
 await command('identity.register',{});const created=await command('workspace.create',{name:'T053 current public legacy source',visibility:'PUBLIC'}),id=created.result.workspace_id;assert.ok(id);assert.equal(db.prepare('SELECT count(*) n FROM secure_commits WHERE workspace_id=?').get(id).n,0);legacy.close();legacy=undefined;
 const rawAccounting=db.prepare('SELECT sum(bytes) bytes,count(*) rows FROM kernel_accounting_entries WHERE scope=?').get(id);
 agent=await SecureAgentClient.open({baseUrl:origin,privateKey:key,statePath:join(out,'writer.json'),intentDbPath:join(out,'intents.sqlite'),fetch:controlled});
 const steps=[];
 for(const target of ['PUBLIC','PRIVATE']){
  const value=await agent.convert(id,target);assert.equal(value.policy.payload.visibility,target);assert.ok(JSON.stringify(value.objects).includes('T053 current public legacy source'));
  const commits=db.prepare('SELECT artifact,response FROM secure_commits WHERE workspace_id=? ORDER BY sequence').all(id),policies=db.prepare('SELECT artifact FROM secure_policies WHERE workspace_id=? ORDER BY version').all(id);
  const input={workspaceId:id,commits:commits.map(r=>JSON.parse(r.artifact)),policies:policies.map(r=>JSON.parse(r.artifact)),checkpoint:value.checkpoint,trustedOwner:{actorId:agent.identity.actorId,key:agent.identity.keyId},keyring:agent.state.workspaces[id].keyring,validateOperation:validateSecureOperation};
  const direct=await verifyJournal(input);assert.equal(direct.checkpoint.head,value.checkpoint.head);assert.deepEqual(direct.objects,value.objects);
  const migrate=direct.operations.filter(o=>o.kind==='MIGRATE');
  const step={target,wire_version:value.policy.payload.v,sequence:value.checkpoint.sequence,direct_verifyJournal:true,legacy:value.legacy,objects:value.objects.length,migrate_operations:migrate.length,migrate_object_counts:migrate.map(o=>o.objects.length),commit_bytes:commits.map(r=>Buffer.byteLength(r.artifact)),response_bytes:commits.map(r=>Buffer.byteLength(r.response)),policy_bytes:policies.map(r=>Buffer.byteLength(r.artifact)),stored_bytes:commits.reduce((n,r)=>n+Buffer.byteLength(r.artifact)+Buffer.byteLength(r.response),0)+policies.reduce((n,r)=>n+Buffer.byteLength(r.artifact),0)};
  steps.push(step);save(target.toLowerCase()+'-signed-snapshot.json',{commits:input.commits,policies:input.policies,checkpoint:input.checkpoint});
 }
 const result={result:'CURRENT_LEGACY_PUBLIC_CREATE_AND_PUBLIC_PRIVATE_CHAIN_PASS',reference:'f828b6c50a0a58d1e718af90f653b214adcc3328',no_seed_or_boundary_override:true,legacy_raw_accounting:rawAccounting,steps,snapshot_pages:snapshots,calls,large_witness:'UNPROVEN; no bulk/projection feasibility claim',default_discovery_unchanged:true};save('result.json',result);console.log(JSON.stringify(result));
}finally{legacy?.close();agent?.close();projector?.close();server.closeAllConnections?.();await new Promise(r=>server.close(r));db.close();save('service-exit.json',{closed:true,waited:true,reference_in_process:true});}
