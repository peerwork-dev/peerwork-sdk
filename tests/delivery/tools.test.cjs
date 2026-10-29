const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{join}=require('node:path'),{tmpdir}=require('node:os');
const {CodexHost,AntigravityCliHost,createHost}=require('../../bindings/node/delivery/hosts.cjs');
const {DeliveryReceiver,resolveSelftest}=require('../../bindings/node/delivery/receiver.cjs');
const {ReceiverStore}=require('../../bindings/node/delivery/store.cjs');
const fake=[process.execPath,join(__dirname,'fake-host.cjs')];
test('Codex tool binds one thread, starts idle and steers its exact active turn',async()=>{
 const host=new CodexHost({thread_id:'thread-1',command:fake});try{
  await host.start();assert.deepEqual(await host.health(),{ready:true,execution_state:'IDLE'});
  assert.equal((await host.deliver({message_id:'first'})).receipt,'turn-1');
  assert.equal((await host.health()).execution_state,'BUSY');
  assert.equal((await host.deliver({message_id:'second'})).receipt,'turn-1');
 }finally{host.close();}
});
test('agy tool is idle-only and requires actual host activity, not a pipe-write receipt',async()=>{
 const host=new AntigravityCliHost({conversation_id:'agy-1',command:fake});try{
  await host.start();assert.equal((await host.health()).ready,false);
  const pending=host.deliver({message_id:'first'});await new Promise(r=>setImmediate(r));assert.equal((await host.health()).execution_state,'BUSY');
  const receipt=await pending;assert.equal(receipt.state,'HOST_ACCEPTED');assert.equal((await host.health()).ready,false);
  await new Promise(r=>setTimeout(r,50));assert.equal((await host.health()).ready,true);
  assert.equal(host.mode,'IDLE_ONLY');assert.throws(()=>createHost({kind:'agy-app'}),/UNQUALIFIED/);
 }finally{host.close();}
});
function fixture(directory,{loseHost=false,loseAck=false}={}){
 const event={sequence:1,actor_id:'bob',record_refs:[]},binding={workspace_id:'space',expected_actor:'alice'};let checkpoint=0,calls=0,ackLost=false;
 const envelope=value=>({state:'ACCEPTED',result:{structure:value}});
 const client={binding,inbox:async()=>envelope({events:checkpoint?[]:[event],more:false}),ack:async b=>{if(b.stage==='HOST_ACCEPTED'){if(loseAck&&!ackLost){ackLost=true;throw Error('lost reply');}checkpoint=1;}return envelope({});}};
 const host={config:{thread_id:'thread-1'},health:async()=>({ready:true,execution_state:'IDLE'}),deliver:async()=>{calls++;if(loseHost)throw Object.assign(Error('lost host acknowledgement'),{code:'HOST_ACK_UNKNOWN'});return {state:'HOST_ACCEPTED',receipt:'turn-1'};}};
 const receiver=new DeliveryReceiver({client,session:{describe:async()=>({outcome:envelope({})})},host,stateDirectory:directory});receiver.fence={route_id:'route',epoch:1,receiver_id:'receiver'};
 return {receiver,client,host,calls:()=>calls};
}
test('lost backend acknowledgement resumes the saved host receipt without sending another prompt',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-tools-'));const f=fixture(dir,{loseAck:true});
 try{await assert.rejects(f.receiver.drain());assert.equal(f.calls(),1);assert.equal(f.receiver.store.delivery(1).status,'HOST_ACCEPTED');await f.receiver.drain();assert.equal(f.calls(),1);assert.equal(f.receiver.store.delivery(1).status,'ACKED');}finally{f.receiver.store.close();fs.rmSync(dir,{recursive:true,force:true});}
});
test('unknown host effects stay uncertain across restart and require explicit resolution',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-uncertain-'));let f=fixture(dir,{loseHost:true});
 try{await assert.rejects(f.receiver.drain());assert.equal(f.calls(),1);await f.receiver.drain();assert.equal(f.calls(),1);f.receiver.store.close();
  f=fixture(dir);await f.receiver.drain();assert.equal(f.calls(),0);f.receiver.resolve(1,{host_receipt:'verified-turn'});await f.receiver.drain();assert.equal(f.calls(),0);assert.equal(f.receiver.store.delivery(1).status,'ACKED');
 }finally{f.receiver.store.close();fs.rmSync(dir,{recursive:true,force:true});}
});
test('receiver state is private, binding pinned and single-writer locked',()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-state-'));const a=new ReceiverStore(dir,{actor:'a'});
 try{a.lock();assert.throws(()=>new ReceiverStore(dir,{actor:'b'}),/BINDING_MISMATCH/);const b=new ReceiverStore(dir,{actor:'a'});try{assert.throws(()=>b.lock(),/LOCKED/);}finally{b.close();}assert.equal(fs.statSync(join(dir,'receiver.sqlite')).mode&0o077,0);}finally{a.close();fs.rmSync(dir,{recursive:true,force:true});}
});

// A host acknowledgement may take longer than a readiness lease. Periodic
// maintenance must never await that host RPC before renewing the lease.
test('heartbeat renewal continues while the host acknowledgement is pending',async t=>{
 t.mock.timers.enable({apis:['setInterval']});
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-heartbeat-')),f=fixture(dir),stop=new AbortController();
 let pulses=0,sent=0,finishHost,wakeReady;
 const resumed=new Promise(resolve=>{wakeReady=resolve;});
 f.client.claim=async b=>({state:'ACCEPTED',result:{structure:{route:{route_id:b.route_id,epoch:1}}}});
 f.client.pulse=async()=>{pulses++;return {state:'ACCEPTED',result:{structure:{route:{state:'REALTIME_READY',execution_state:'IDLE'}}}};};
 f.client.wakes=async function*({},{signal}){wakeReady();yield {event:'ready'};await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));};
 f.host.start=async()=>{};f.host.close=()=>finishHost?.({state:'HOST_ACCEPTED',receipt:'turn-1'});
 f.host.deliver=async message=>{if(message.format==='peerwork.selftest.v1')return {state:'HOST_ACCEPTED',receipt:'test-turn'};sent++;return new Promise(resolve=>{finishHost=resolve;});};
 const running=f.receiver.run({signal:stop.signal});
 try{
  await resumed;f.receiver.transportReady=true;
  t.mock.timers.tick(4000);await new Promise(r=>setImmediate(r));assert.equal(sent,1);
  const before=pulses;
  for(let i=0;i<5;i++){t.mock.timers.tick(4000);await new Promise(r=>setImmediate(r));}
  assert(pulses>=before+5,'a pending host acknowledgement must not hold heartbeat renewal');assert.equal(sent,1);
 }finally{stop.abort();await running;fs.rmSync(dir,{recursive:true,force:true});}
});

function startupFixture(directory,options={}){
 const f=fixture(directory),statuses=[],pulses=[],order=[],stop=new AbortController();
 f.receiver.onStatus=status=>statuses.push(status);f.receiver.selftestTimeoutMs=options.timeout??1000;
 f.receiver.session.describe=async()=>{order.push('role');return {outcome:{state:'ACCEPTED',result:{structure:{}}}};};
 f.client.claim=async body=>{order.push('claim');return {state:'ACCEPTED',result:{structure:{route:{route_id:body.route_id,epoch:1}}}};};
 f.client.pulse=async body=>{pulses.push(body);return {state:'ACCEPTED',result:{structure:{route:{route_id:body.route_id,state:body.ready?'REALTIME_READY':'DELAYED',execution_state:'IDLE'}}}};};
 f.client.wakes=async function*(_, {signal}){order.push('stream');if(options.stream!==false)yield {event:'ready'};await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));};
 f.host.start=async()=>{order.push('host-start');};f.host.close=()=>{};
 let tests=0;
 f.host.deliver=async message=>{order.push('host-input');assert.equal(message.format,'peerwork.selftest.v1');assert.equal(message.binding,f.client.binding);assert.equal(message.route_id,f.receiver.fence.route_id);tests++;return {state:'HOST_ACCEPTED',receipt:'test-receipt'};};
 return {...f,statuses,pulses,order,stop,tests:()=>tests};
}
test('startup automatically proves role, actual stream, signed inbox and host acceptance before advertising ready',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-')),f=startupFixture(dir);
 let reads=0;f.client.inbox=async body=>{reads++;assert.equal(body.limit,1);return {state:'ACCEPTED',result:{structure:{events:[{sequence:9}],more:false}}};};
 f.host.deliver=async message=>{
  assert.equal(f.pulses.filter(p=>p.ready).length,0);assert.equal(f.receiver.store.get('selftest').status,'SENDING');
  assert.match(message.message_id,/^selftest:/);assert.equal(message.format,'peerwork.selftest.v1');return {state:'HOST_ACCEPTED',receipt:'test-receipt'};
 };
 try{
  const report=await f.receiver.run({signal:f.stop.signal,selftestOnly:true});
  assert.equal(report.status,'PASS');assert.equal(report.model_response,'NOT_ATTESTED');assert.equal(reads,1);
  assert.equal(f.receiver.selftestPassed,true);assert.equal(f.pulses.filter(p=>p.ready).length,1);
  assert.equal(f.statuses.at(-1).connection_state,'CONNECTED');assert.deepEqual(f.order,['role','host-start','claim','stream']);
  assert.equal(f.pulses.at(-1).ready,false,'standalone selftest goes offline after verifying');
  const store=new ReceiverStore(dir,{binding:f.client.binding,host:f.host.config,includeSelf:false});try{assert.equal(store.delivery(9),undefined,'probe must not ACK, persist or skip the business inbox');assert.equal(store.get('selftest').status,'PASS');}finally{store.close();}
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('no SSE ready frame means bounded selftest failure without a host prompt or readiness',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-timeout-')),f=startupFixture(dir,{stream:false,timeout:100});
 try{await assert.rejects(f.receiver.run({signal:f.stop.signal,selftestOnly:true}),{code:'SELFTEST_TIMEOUT'});assert.equal(f.tests(),0);assert.equal(f.pulses.some(p=>p.ready),false);assert.equal(f.statuses.at(-1).selftest.stage,'STREAM');}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('lost probe acknowledgement blocks restart and needs explicit reconciliation instead of another prompt',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-unknown-'));let f=startupFixture(dir),calls=0;
 f.host.deliver=async()=>{calls++;throw Object.assign(Error('lost host response'),{code:'HOST_ACK_UNKNOWN'});};
 try{
  await assert.rejects(f.receiver.run({selftestOnly:true}),{code:'HOST_ACK_UNKNOWN'});assert.equal(calls,1);assert.equal(f.pulses.some(p=>p.ready),false);
  f=startupFixture(dir);await assert.rejects(f.receiver.run({selftestOnly:true}),{code:'SELFTEST_HOST_OUTCOME_UNKNOWN'});assert.equal(f.tests(),0);
  const store=new ReceiverStore(dir,{binding:f.client.binding,host:f.host.config,includeSelf:false});
  try{store.lock();assert.equal(store.get('selftest').status,'UNCERTAIN');assert.throws(()=>resolveSelftest(store,{}),/RESOLUTION_REQUIRED/);resolveSelftest(store,{host_receipt:'confirmed-original-turn'});}finally{store.close();}
  f=startupFixture(dir);assert.equal((await f.receiver.run({selftestOnly:true})).status,'PASS');assert.equal(f.tests(),1,'a new startup runs one new probe after explicit resolution');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('role rejection prevents route creation and host startup',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-role-')),f=startupFixture(dir);
 f.receiver.session.describe=async()=>({outcome:{state:'REJECTED',result:{structure:{error:{code:'PROTOCOL_BUNDLE_NOT_BOUND'}}}}});
 try{await assert.rejects(f.receiver.run({selftestOnly:true}),{code:'PROTOCOL_BUNDLE_NOT_BOUND'});assert.deepEqual(f.order,[]);assert.equal(f.tests(),0);}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('reconnection rechecks transport without injecting another selftest input',async()=>{
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-reconnect-')),f=startupFixture(dir);let streams=0;
 f.client.inbox=async()=>({state:'ACCEPTED',result:{structure:{events:[],more:false}}});
 f.client.wakes=async function*(_, {signal}){streams++;yield {event:'ready'};if(streams>1){f.stop.abort();return;}};
 try{await f.receiver.run({signal:f.stop.signal});assert.equal(streams,2);assert.equal(f.tests(),1);assert(f.pulses.some(p=>p.transport_ready===false));}finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('a pending startup host acknowledgement renews the lease with ready false',async t=>{
 t.mock.timers.enable({apis:['setInterval']});
 const dir=fs.mkdtempSync(join(tmpdir(),'delivery-selftest-heartbeat-')),f=startupFixture(dir);let finish,entered;
 const started=new Promise(resolve=>{entered=resolve;});
 f.host.deliver=async()=>{entered();return new Promise(resolve=>{finish=resolve;});};
 const running=f.receiver.run({signal:f.stop.signal,selftestOnly:true});
 try{
  await started;
  for(let i=0;i<3;i++){t.mock.timers.tick(4000);await new Promise(resolve=>setImmediate(resolve));}
  assert(f.pulses.length>=3);assert(f.pulses.every(p=>!p.ready));
  finish({state:'HOST_ACCEPTED',receipt:'delayed-test-receipt'});assert.equal((await running).status,'PASS');
 }finally{f.stop.abort();await running.catch(()=>{});fs.rmSync(dir,{recursive:true,force:true});}
});
