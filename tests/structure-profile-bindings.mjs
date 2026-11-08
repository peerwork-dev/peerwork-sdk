import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import vm from 'node:vm';
import {test} from 'node:test';

test('Node exposes verified structure data through submission and cached status without reading workspace history',async()=>{
 const structure={profile:'backend-structure-v1',assurance:'BACKEND_CURRENT_STATE',workspace_id:'workspace',state:{holder:'agent'},sealed_content:{ciphertext:'opaque'}};
 const accepted=()=>({command_id:'command',workspace_id:'workspace',protocol_digest:null,instance_id:null,event_sequence:null,revision:2,produced_record_ids:[],catalog:null,structure_result_json:JSON.stringify(structure)});
 const calls=[];
 const binding={version:()=> 'test',KernelCancelHandle:class{cancel(){}},kernelJson:async (operation,origin,journal,identity,features,loopback,authority,commandJson)=>{calls.push(operation);if(operation==='execute_structure_intent'&&JSON.parse(commandJson).action==='structure.maintenance.rebuild')return JSON.stringify({state:'COMPLETED',command_id:'original-admission',result:accepted()});return JSON.stringify(operation==='open'?{actor_id:'agent',key_id:'key',origin:'https://example.invalid'}:['status','execute_structure_intent','resume_structure_intent'].includes(operation)?{state:'ACCEPTED',result:accepted()}:operation==='submit_saved'?accepted():[]);}};
 const realRequire=createRequire(import.meta.url),require=name=>name==='native-test'?binding:realRequire(name);require.resolve=()=> 'native-test';
 const exports={};vm.runInNewContext(readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'),{exports,require,process:{platform:'linux',arch:'x64',report:{getReport:()=>({header:{glibcVersionRuntime:'2.36'}})}},Buffer});
 const session=await exports.openKernel({origin:'https://example.invalid',journalPath:'/selected/journal',identityPath:'/selected/identity'});
 const result=await session.submitSaved('command');assert.equal(JSON.stringify(result.structure),JSON.stringify(structure));assert(!Object.hasOwn(result,'structure_result_json'));
 const cached=await session.status('command');assert.equal(JSON.stringify(cached.result.structure),JSON.stringify(structure));
 const intent=await session.executeStructureIntent(Object.assign(Object.create(null),{action:'structure.workspace.create',idempotency_key:'create-once',body:Object.assign(Object.create(null),{name:'test'})}));assert.equal(JSON.stringify(intent.result.structure),JSON.stringify(structure));
 const resumed=await session.resumeStructureIntent('command');assert.equal(JSON.stringify(resumed.result.structure),JSON.stringify(structure));
 assert.deepEqual(calls,['open','submit_saved','status','execute_structure_intent','resume_structure_intent'],'binding must not read or replay workspace history');
 const completed=await session.executeStructureIntent(Object.assign(Object.create(null),{action:'structure.maintenance.rebuild',body:Object.create(null)}));assert.equal(completed.state,'COMPLETED');assert.equal(completed.command_id,'original-admission');assert.equal(completed.result.command_id,'command');assert.equal(JSON.stringify(completed.result.structure),JSON.stringify(structure));
});

test('Node Context v2 binds explicit selectors and transports bounded requests through the shared native boundary',async()=>{
 const calls=[];
 const binding={version:()=> 'test',KernelCancelHandle:class{cancel(){}},agentContextJson:async(operation,profile,actor,service,wire)=>{
  const request=wire===undefined?undefined:JSON.parse(wire);calls.push({operation,profile,actor,service,request});
  return JSON.stringify({ok:true,value:{context:{schema:'peerwork.agent-context.v2',fingerprint:'selected',actor_id:actor},status:'ready'}});
 }};
 const realRequire=createRequire(import.meta.url),require=name=>name==='native-test'?binding:realRequire(name);require.resolve=()=> 'native-test';
 const exports={},sandbox=vm.createContext({exports,require,process:{platform:'linux',arch:'x64',report:{getReport:()=>({header:{glibcVersionRuntime:'2.36'}})}},Buffer});
 vm.runInContext(readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'),sandbox);
 const ctx=await vm.runInContext("exports.bindStructureContext({profilePath:'/selected/context',expectedActor:'worker',expectedService:'service',origin:'https://example.invalid',identityPath:'/selected/identity',journalPath:'/selected/journal',workspaceIds:['space']})",sandbox);
 await ctx.discover('space',{limit:1});await ctx.describe('space',{instanceId:'instance',protocolDigest:'digest'});
 await ctx.executeStructureIntent('space',Object.assign(Object.create(null),{action:'structure.events.read',body:Object.create(null)}));
 await ctx.recover('space',{operationId:'same-operation'});
 await ctx.operations('space',{scope:'WORKSPACE',view:'HISTORY',limit:1});
 await ctx.followOperation('space',Object.assign(Object.create(null),{job_id:'job',workspace_id:'space',instance_id:'instance',protocol_digest:'digest'}));
 assert.deepEqual(calls.map(c=>c.operation),['bind.structure','open','discover','describe','execute.structure','recover','operations','follow.operation']);
 assert.equal(calls[0].request.execution_profile,'backend-structure-v1');assert.equal(calls[0].request.allow_loopback_http,false);
 assert(!Object.hasOwn(calls[0].request,'workspace_profiles'));assert.equal(calls[3].request.query.protocol_digest,'digest');
 assert.equal(calls[6].request.query.scope,'WORKSPACE');assert.equal(calls[7].request.intent.body.job_id,'job');
 for(const c of calls.slice(2))assert.equal(c.request.expected_fingerprint,'selected');
});

test('Node local pending APIs preserve pagination and explicit maintenance through native transport',async()=>{
 const calls=[];
 const binding={KernelCancelHandle:class{cancel(){}},kernelJson:async(operation,...args)=>{
  calls.push({operation,request:args[6]===undefined?undefined:JSON.parse(args[6])});
  return JSON.stringify(operation==='open'?{actor_id:'selected',key_id:'key'}:operation==='ensure_local_content_key'?{workspace_id:'space',key_id:'local-key'}:operation==='build_pending_index'?
   {complete:false,scanned_rows:2048}:{items:[{command_id:'pending'}],next_after:'pending',consistency:'LIVE_KEYSET'});
 }};
 const realRequire=createRequire(import.meta.url),require=name=>name==='native-test'?binding:realRequire(name);require.resolve=()=> 'native-test';
 const exports={};vm.runInNewContext(readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'),{exports,require,process:{platform:'linux',arch:'x64',report:{getReport:()=>({header:{glibcVersionRuntime:'2.36'}})}},Buffer});
 const kernel=await exports.openKernel({origin:'https://example.invalid',journalPath:'/selected/journal',identityPath:'/selected/identity'});
 const first=await kernel.pendingPage();assert.equal(first.next_after,'pending');
 await kernel.pendingPage({after:first.next_after,limit:1});
 const progress=await kernel.buildPendingIndex();assert.equal(progress.complete,false);assert.equal(progress.scanned_rows,2048);
 assert.equal((await kernel.ensureLocalContentKey('space')).key_id,'local-key');
 assert.deepEqual(calls.map(c=>c.operation),['open','pending_page','pending_page','build_pending_index','ensure_local_content_key']);
 assert.deepEqual(calls[1].request,{after:null,preparations_after:null,limit:32});assert.deepEqual(calls[2].request,{after:'pending',preparations_after:null,limit:1});
 assert.deepEqual(calls[4].request,{workspace_id:'space'});
});

test('verified storage notices are surfaced once per level and reset after capacity recovery',async()=>{
 let level='WARNING';const notices=[];
 const binding={KernelCancelHandle:class{cancel(){}},kernelJson:async operation=>JSON.stringify(operation==='open'?{actor_id:'selected',key_id:'key'}:{state:'ACCEPTED',result:{workspace_id:'space',structure_result_json:JSON.stringify({capacity:{status:level,percent_used:level==='OK'?9:level==='CRITICAL'?96:81,remaining_write_bytes:100},...(level==='OK'?{}:{warnings:[{code:'WORKSPACE_STORAGE_NEAR_LIMIT',severity:level}]})})}})};
 const realRequire=createRequire(import.meta.url),require=name=>name==='native-test'?binding:realRequire(name);require.resolve=()=> 'native-test';const exports={};
 vm.runInNewContext(readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'),{exports,require,process:{platform:'linux',arch:'x64',report:{getReport:()=>({header:{glibcVersionRuntime:'2.36'}})},emitWarning:(message,options)=>notices.push({message,code:options.code})},Buffer});
 const client=await exports.openKernel({origin:'https://example.invalid',journalPath:'/selected/journal',identityPath:'/selected/identity'});
 const call=()=>client.executeStructureIntent(Object.assign(Object.create(null),{action:'structure.workspace.get',workspace_id:'space',body:Object.create(null)}));
 const first=await call();assert.equal(first.result.warnings[0].code,'WORKSPACE_STORAGE_NEAR_LIMIT');await call();assert.equal(notices.length,1);
 level='CRITICAL';await call();assert.equal(notices.length,2);level='OK';await call();assert.equal(notices.length,2);level='WARNING';await call();assert.equal(notices.length,3);
});
