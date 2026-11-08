// Exact official PUBLIC-v1 writer/conversion path; size preflight only.
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash}from'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,readdirSync}from'node:fs';
import {join,resolve}from'node:path';
import {createRequire}from'node:module';
import {pathToFileURL}from'node:url';
import {execFileSync}from'node:child_process';
const ref=resolve(process.argv[2]),out=resolve(process.argv[3]);assert.ok(readFileSync(join(out,'consumer.py')).length); // host created fresh protected case

assert.equal(execFileSync('git',['-C',ref,'rev-parse','HEAD'],{encoding:'utf8'}).trim(),'f828b6c50a0a58d1e718af90f653b214adcc3328');execFileSync('git',['-C',ref,'diff','--quiet','HEAD','--','src','package.json','package-lock.json']);
const files=[];function scan(d){for(const e of readdirSync(d,{withFileTypes:true})){const p=join(d,e.name);if(e.isDirectory())scan(p);else if(e.name.endsWith('.js'))files.push(p);}}const compiled=join(ref,'dist-workspace/src');scan(compiled);files.sort();const h=createHash('sha256');for(const p of files)h.update(p.slice(compiled.length+1)+'\0'+createHash('sha256').update(readFileSync(p)).digest('hex')+'\n');assert.equal(files.length,204);assert.equal(h.digest('hex'),'6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc');
const require=createRequire(join(ref,'package.json')),load=p=>import(pathToFileURL(join(compiled,p+'.js')).href);
const{serve}=await import(pathToFileURL(require.resolve('@hono/node-server')).href),{openKernel,WorkspaceKernel}=await load('workspace-kernel'),{createWorkspaceControlApp}=await load('workspace-http'),{SecureAgentClient}=await load('workspace-secure-agent'),{WorkspaceProjector,initializePublicProjection}=await load('workspace-projector'),{encodeCanonicalJson}=await load('workspace-secure-crypto'),{verifyJournal}=await load('workspace-secure-client'),{validateSecureOperation}=await load('workspace-secure-engine');
const wire=x=>Buffer.from(encodeCanonicalJson(x)),bytes=x=>wire(x).length;const db=openKernel(join(out,'control.sqlite'),'t050'),kernel=new WorkspaceKernel(db,'t050',Buffer.alloc(32,73));
const discovery=kernel.discovery.bind(kernel);kernel.discovery=()=>{const v=discovery();return{...v,protocol_features:v.protocol_features.filter(x=>x!=='signed-protocol-format-v3')};};
const server=serve({fetch:createWorkspaceControlApp(kernel).fetch,hostname:'127.0.0.1',port:0});let agent,projector;const calls=[];
const save=(name,value)=>writeFileSync(join(out,name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
try{
 await new Promise(r=>server.once('listening',r));const origin='http://127.0.0.1:'+server.address().port;initializePublicProjection(join(out,'public.sqlite'));projector=new WorkspaceProjector(join(out,'control.sqlite'),join(out,'public.sqlite'));
 const controlled=async(input,init)=>{const response=await fetch(input,init),path=new URL(input instanceof Request?input.url:String(input)).pathname;if(init?.method==='POST'){const body=typeof init.body==='string'?JSON.parse(init.body):null;calls.push({path,status:response.status,body_bytes:typeof init.body==='string'?Buffer.byteLength(init.body):null,action:body?.commit?.payload?.action_id??body?.authorization?.payload?.action_id??null});}if(path.endsWith('/conversion/pages')&&response.ok)projector.publish(1000);return response;};
 const selectedKey=generateKeyPairSync('ed25519').privateKey;agent=await SecureAgentClient.open({baseUrl:origin,privateKey:selectedKey,statePath:join(out,'writer.json'),intentDbPath:join(out,'intents.sqlite'),fetch:controlled});
 const created=await agent.create('T068 nested unused input','PUBLIC');let before=await agent.journal(created.workspaceId);const discussion=before.objects.find(o=>o.kind==='instances'&&o.value.origin_entrypoint==='discussion');assert.ok(discussion);
 let nested=null;for(let i=0;i<70;i++)nested={x:nested};const body={message:'T068 depth70 genuine action',unused:nested};
 const final=await agent.action(created.workspaceId,discussion.id,'discussion.post',body);assert.equal(final.checkpoint.sequence,2);
 const commits=db.prepare('SELECT artifact FROM secure_commits WHERE workspace_id=? ORDER BY sequence').all(created.workspaceId).map(r=>JSON.parse(r.artifact)),policies=db.prepare('SELECT artifact FROM secure_policies WHERE workspace_id=? ORDER BY version').all(created.workspaceId).map(r=>JSON.parse(r.artifact));
 const direct=await verifyJournal({workspaceId:created.workspaceId,policies,commits,checkpoint:final.checkpoint,trustedOwner:{actorId:agent.identity.actorId,key:agent.identity.keyId},keyring:agent.state.workspaces[created.workspaceId].keyring,validateOperation:validateSecureOperation});assert.deepEqual(direct.objects,final.objects);assert.equal(direct.checkpoint.head,final.checkpoint.head);
 const depth=x=>x&&typeof x==='object'?1+Math.max(0,...Object.values(x).map(depth)):0;
 save('signed-snapshot.json',{commits,policies,checkpoint:final.checkpoint});save('reference-objects.json',final.objects);save('exported-ts-state.json',agent.state);writeFileSync(join(out,'selected-owner.pem'),selectedKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
 save('fixture.json',{origin,workspace_id:created.workspaceId,owner_actor_id:agent.identity.actorId,owner_key_id:agent.identity.keyId,sequence:2,head:final.checkpoint.head,objects:final.objects.length,unused_nesting:70,action_wire_depth:depth(commits[1]),action_wire_bytes:bytes(commits[1]),direct_TS_verified:true,calls});
 agent.close();agent=undefined;const cmd=JSON.parse(readFileSync(process.argv[4],'utf8'));const {spawnSync}=await import('node:child_process');const r=spawnSync(cmd[0],cmd.slice(1),{encoding:'utf8'});save('consumer-terminal.json',{code:r.status,stdout:r.stdout,stderr:r.stderr});console.log(JSON.stringify({direct_TS_verified:true,native_exit:r.status,stdout:r.stdout,stderr:r.stderr}));
}finally{agent?.close();projector?.close();server.closeAllConnections?.();await new Promise(r=>server.close(r));db.close();save('service-exit.json',{closed:true,waited:true,reference_in_process:true});}
