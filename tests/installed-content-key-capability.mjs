// Old-service capability refusal from actual installed packages. All identities
// and cached discovery used here belong to synthetic acceptance fixtures.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {randomBytes,createHash} from 'node:crypto';
const exec=promisify(execFile),prefix=resolve('.build-target/access-installed');
const previous=JSON.parse(readFileSync('.test-data/access-installed-current.json','utf8'));assert.equal(previous.exit_code,0);
const state=resolve('.test-data/key-capability-'+Date.now()+'-'+randomBytes(4).toString('hex'));mkdirSync(state,{mode:0o700});
const metadata=JSON.parse((await exec('/usr/local/bin/python3',['-c',"import sqlite3,sys; db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(db.execute('SELECT discovery_wire FROM pinned_discovery WHERE id=1').fetchone()[0].decode())",join(previous.state,'owner/operations.sqlite')])).stdout);
const missing=process.env.PEERWORK_MISSING_KEY_CAPABILITY??'canonical-content-key-epochs-v1';assert.ok(['canonical-content-key-epochs-v1','owner-current-key-delivery-v1'].includes(missing));assert.ok(metadata.protocol_features.includes(missing));metadata.protocol_features=metadata.protocol_features.filter(x=>x!==missing);
const requests=[];const server=createServer((req,res)=>{requests.push({method:req.method,path:req.url});res.setHeader('Content-Type','application/json');if(req.method==='GET'&&req.url==='/api/workspace/v1/discovery'){res.end(JSON.stringify(metadata));return;}res.statusCode=503;res.end(JSON.stringify({error:{code:'UNEXPECTED_REQUEST_BEFORE_CAPABILITY_CHECK'}}));});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
try{
 const origin='http://127.0.0.1:'+server.address().port,sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');
 const identity=join(state,'identity.state'),info=await sdk.createIdentity(identity),journal=join(state,'operations.sqlite');
 const kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true}),workspace='W'.repeat(43);
 await assert.rejects(kernel.rotateContentKey({workspace_id:workspace,idempotency_key:'unsupported-key-operation'}),e=>e.code==='CAPABILITY_UNAVAILABLE');
 await assert.rejects(kernel.coordinateContentKeys({workspace_id:workspace}),e=>e.code==='CAPABILITY_UNAVAILABLE');
 if(missing==='canonical-content-key-epochs-v1'){
 await assert.rejects(kernel.executeStructureIntent({action:'structure.content-key.set',workspace_id:workspace,body:{key_id:'K'.repeat(43),expected_epoch:0,expected_head_revision:null}}),e=>e.code==='CAPABILITY_UNAVAILABLE');
 await assert.rejects(kernel.executeStructureIntent({action:'structure.action',workspace_id:workspace,instance_id:'I'.repeat(43),protocol_digest:'a'.repeat(64),expected_instance_revision:1,body:{action_id:'post',structure:{}},plaintext_contents:[{record_index:0,text:'Must not be submitted'}]}),e=>e.code==='CAPABILITY_UNAVAILABLE');
 }
 const context=await sdk.bindStructureContext({profilePath:join(state,'context.json'),expectedActor:info.actor_id,expectedService:'capability-refusal',origin,identityPath:identity,journalPath:journal,workspaceIds:[workspace],allowLoopbackHttp:true});
 await assert.rejects(context.rotateContentKey(workspace,{idempotency_key:'unsupported-context-operation'}),e=>e.code==='CAPABILITY_UNAVAILABLE');
 assert.equal((await kernel.pendingPage()).items.length,0);
 const selection={workspace_id:workspace,origin,identity_path:identity,journal_path:join(state,'python.sqlite')},selectionPath=join(state,'selection.json');writeFileSync(selectionPath,JSON.stringify(selection),{mode:0o600});
 const python=join(prefix,'python/bin/python'),code=`import json,sys,peerwork\ns=json.load(open(sys.argv[1]))\nk=peerwork.KernelClient(origin=s['origin'],identity_path=s['identity_path'],journal_path=s['journal_path'],allow_loopback_http=True)\ntry:\n k.rotate_content_key({'workspace_id':s['workspace_id'],'idempotency_key':'python-unsupported'})\nexcept peerwork.KernelError as e:\n assert e.code=='CAPABILITY_UNAVAILABLE',e.code\nelse:\n raise AssertionError('Python did not reject unsupported key epochs')\nassert not k.pending_page()['items']\nprint('PASS')\n`;
 assert.equal((await exec(python,['-c',code,selectionPath])).stdout.trim(),'PASS');
 const cliSelection=join(state,'rotation.json');writeFileSync(cliSelection,JSON.stringify({workspace_id:workspace,idempotency_key:'cli-unsupported'}),{mode:0o600});
 await assert.rejects(exec(join(prefix,'bin/peerwork'),['kernel','rotate-content-key',origin,join(state,'cli.sqlite'),identity,cliSelection,'--allow-loopback-http']),e=>String(e.stderr).includes('CAPABILITY_UNAVAILABLE'));
 assert.ok(requests.length>0);assert.ok(requests.every(r=>r.method==='GET'&&r.path==='/api/workspace/v1/discovery'),JSON.stringify(requests));
 const artifacts={};for(const name of ['peerwork-agent-sdk-0.1.11.tgz','peerwork-agent-sdk-linux-x64-gnu-0.1.11.tgz','peerwork_sdk-0.1.11-cp311-abi3-manylinux_2_38_x86_64.whl'])artifacts[name]=createHash('sha256').update(readFileSync(join(prefix,'packages',name))).digest('hex');
 const result={status:'PASS',missing_capability:missing,node:true,python:true,cli:true,context:true,non_discovery_requests:0,pending_operations:0,artifacts};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');writeFileSync('.test-data/key-capability-current.json',JSON.stringify({state,result}));console.log(JSON.stringify({state,...result}));
}finally{await new Promise(resolve=>server.close(resolve));}
