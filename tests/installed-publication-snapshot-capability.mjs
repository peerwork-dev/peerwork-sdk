// Existing publication support alone must not enable the selected-snapshot producer.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile),prefix=resolve(process.env.PEERWORK_INSTALLED_PREFIX),state=resolve(process.env.PEERWORK_ACCESS_TEST_STATE),sdk=createRequire(join(prefix,'node/package.json'))('@peerwork/agent-sdk');
const metadata=await(await fetch(process.env.PEERWORK_ACCESS_TEST_ORIGIN+'/api/workspace/v1/discovery')).json();metadata.protocol_features=metadata.protocol_features.filter(f=>f!=='selected-publication-snapshot-v1');assert.ok(metadata.protocol_features.includes('owner-selected-publication-v1'));
const requests=[],server=createServer((req,res)=>{requests.push({method:req.method,path:req.url});res.setHeader('Content-Type','application/json');if(req.method==='GET'&&req.url==='/api/workspace/v1/discovery'){res.end(JSON.stringify(metadata));return;}res.statusCode=503;res.end('{}');});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try{
 const origin='http://127.0.0.1:'+server.address().port,identity=join(state,'identity'),info=await sdk.createIdentity(identity),journal=join(state,'operations.sqlite'),kernel=await sdk.openKernel({origin,identityPath:identity,journalPath:journal,allowLoopbackHttp:true}),workspace='W'.repeat(43);
 const selection={workspace_id:workspace,instance_id:'I'.repeat(43),record_id:'R'.repeat(43),protocol_digest:'a'.repeat(64),revision:1,idempotency_key:'must-refuse',title:'Explicit public note',disclosure:'PUBLISH_SELECTED_CONTENT',body:{from:'TEXT',text:'Must not be submitted'}};
 await assert.rejects(kernel.publishSelectedRecord(selection),e=>e.code==='CAPABILITY_UNAVAILABLE');const context=await sdk.bindStructureContext({profilePath:join(state,'context.json'),expectedActor:info.actor_id,expectedService:'snapshot-capability',origin,identityPath:identity,journalPath:journal,workspaceIds:[workspace],allowLoopbackHttp:true});const {workspace_id,...scoped}=selection;await assert.rejects(context.publishSelectedRecord(workspace,scoped),e=>e.code==='CAPABILITY_UNAVAILABLE');
 const file=join(state,'selection.json');writeFileSync(file,JSON.stringify(selection),{mode:0o600});await assert.rejects(exec(join(prefix,'bin/peerwork'),['kernel','publish-record',origin,join(state,'cli.sqlite'),identity,file,'--allow-loopback-http']),e=>String(e.stderr).includes('CAPABILITY_UNAVAILABLE'));
 const python=`import peerwork,json,sys\nk=peerwork.KernelClient(origin=sys.argv[1],identity_path=sys.argv[2],journal_path=sys.argv[3],allow_loopback_http=True)\ntry:\n k.publish_selected_record(json.load(open(sys.argv[4])))\nexcept peerwork.KernelError as e:\n assert e.code=='CAPABILITY_UNAVAILABLE',e.code\nelse:\n raise AssertionError('Missing capability accepted')\np=k.pending_page()\nassert not p['items'] and not p['preparations']['items']\nprint('PASS')\n`;
 assert.equal((await exec(join(prefix,'python/bin/python'),['-c',python,origin,identity,join(state,'python.sqlite'),file])).stdout.trim(),'PASS');const pending=await kernel.pendingPage();assert.equal(pending.items.length,0);assert.equal(pending.preparations.items.length,0);assert.ok(requests.every(r=>r.method==='GET'&&r.path==='/api/workspace/v1/discovery'));
 const result={status:'PASS',missing_capability:'selected-publication-snapshot-v1',node:true,python:true,cli:true,context:true,no_non_discovery_requests:true,no_pending_or_prepared_operations:true};writeFileSync(join(state,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}finally{await new Promise(resolve=>server.close(resolve));}
