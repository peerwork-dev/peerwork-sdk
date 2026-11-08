// Actual installed packages must refuse unsupported large bodies before any
// key initialization, command submission or durable outbox entry.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash,randomBytes} from 'node:crypto';
const exec=promisify(execFile),prefix=resolve('.build-target/access-installed');
const previous=JSON.parse(readFileSync('.test-data/access-installed-current.json','utf8'));assert.equal(previous.exit_code,0);
const state=resolve('.test-data/body-capability-'+Date.now()+'-'+randomBytes(4).toString('hex'));mkdirSync(state,{mode:0o700});
const metadata=JSON.parse((await exec('/usr/local/bin/python3',['-c',"import sqlite3,sys; db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(db.execute('SELECT discovery_wire FROM pinned_discovery WHERE id=1').fetchone()[0].decode())",join(previous.state,'owner/operations.sqlite')])).stdout);
assert.ok(metadata.protocol_features.includes('chunked-content-bodies-v1'));metadata.protocol_features=metadata.protocol_features.filter(f=>f!=='chunked-content-bodies-v1');
const requests=[],server=createServer((req,res)=>{requests.push({method:req.method,path:req.url});res.setHeader('Content-Type','application/json');if(req.method==='GET'&&req.url==='/api/workspace/v1/discovery'){res.end(JSON.stringify(metadata));return;}res.statusCode=503;res.end(JSON.stringify({error:{code:'UNEXPECTED_REQUEST'}}));});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
try{
 const origin='http://127.0.0.1:'+server.address().port,sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');
 const identity=join(state,'identity.state'),info=await sdk.createIdentity(identity),journal=join(state,'operations.sqlite'),workspace='W'.repeat(43);
 const kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true});
 const intent={action:'structure.action',workspace_id:workspace,instance_id:'I'.repeat(43),protocol_digest:'a'.repeat(64),expected_instance_revision:1,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text:'L'.repeat(65536)}]};
 await assert.rejects(kernel.executeStructureIntent(intent),e=>e.code==='CAPABILITY_UNAVAILABLE');
 const {plaintext_contents,...sealed}=intent;sealed.body={...intent.body,contents:[{record_index:0,body:{algorithm:'A256GCM',key_id:'K'.repeat(43),nonce:'A'.repeat(16),aad_digest:'a'.repeat(64),ciphertext_chunks:['A'.repeat(8192),'AAAA']}}]};
 await assert.rejects(kernel.executeStructureIntent(sealed),e=>e.code==='CAPABILITY_UNAVAILABLE');
 const context=await sdk.bindStructureContext({profilePath:join(state,'context.json'),expectedActor:info.actor_id,expectedService:'body-capability',origin,identityPath:identity,journalPath:journal,workspaceIds:[workspace],allowLoopbackHttp:true});
 const {workspace_id,...contextIntent}=intent;await assert.rejects(context.executeStructureIntent(workspace,contextIntent),e=>e.code==='CAPABILITY_UNAVAILABLE');
 const selection=join(state,'selection.json');writeFileSync(selection,JSON.stringify(intent),{mode:0o600});
 await assert.rejects(exec(join(prefix,'bin/peerwork'),['kernel','intent',origin,join(state,'cli.sqlite'),identity,selection,'--allow-loopback-http']),e=>String(e.stderr).includes('CAPABILITY_UNAVAILABLE'));
 const python=`import json,sys,peerwork\nk=peerwork.KernelClient(origin=sys.argv[1],identity_path=sys.argv[2],journal_path=sys.argv[3],allow_loopback_http=True)\ntry:\n k.execute_structure_intent(json.load(open(sys.argv[4])))\nexcept peerwork.KernelError as e:\n assert e.code=='CAPABILITY_UNAVAILABLE',e.code\nelse:\n raise AssertionError('unsupported large body accepted')\nassert not k.pending_page()['items']\nprint('PASS')\n`;
 assert.equal((await exec(join(prefix,'python/bin/python'),['-c',python,origin,identity,join(state,'python.sqlite'),selection])).stdout.trim(),'PASS');
 assert.equal((await kernel.pendingPage()).items.length,0);assert.ok(requests.length);assert.ok(requests.every(r=>r.method==='GET'&&r.path==='/api/workspace/v1/discovery'));
 const artifacts={};for(const name of ['peerwork-agent-sdk-0.1.11.tgz','peerwork-agent-sdk-linux-x64-gnu-0.1.11.tgz','peerwork_sdk-0.1.11-cp311-abi3-manylinux_2_38_x86_64.whl'])artifacts[name]=createHash('sha256').update(readFileSync(join(prefix,'packages',name))).digest('hex');
 const result={status:'PASS',missing_capability:'chunked-content-bodies-v1',node:true,python:true,cli:true,context:true,presealed:true,non_discovery_requests:0,pending_operations:0,artifacts};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');writeFileSync('.test-data/body-capability-current.json',JSON.stringify({state,result}));console.log(JSON.stringify({state,...result}));
}finally{await new Promise(resolve=>server.close(resolve));}
