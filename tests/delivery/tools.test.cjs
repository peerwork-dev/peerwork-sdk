const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{join}=require('node:path'),{tmpdir}=require('node:os');
const {CodexHost,AntigravityCliHost,createHost}=require('../../bindings/node/delivery/hosts.cjs');
const {DeliveryReceiver}=require('../../bindings/node/delivery/receiver.cjs');
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
 const receiver=new DeliveryReceiver({client,session:{},host,stateDirectory:directory});receiver.fence={route_id:'route',epoch:1,receiver_id:'receiver'};
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
 f.client.wakes=async function*({},{signal}){wakeReady();await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));};
 f.host.start=async()=>{};f.host.close=()=>finishHost?.({state:'HOST_ACCEPTED',receipt:'turn-1'});
 f.host.deliver=async()=>{sent++;return new Promise(resolve=>{finishHost=resolve;});};
 const running=f.receiver.run({signal:stop.signal});
 try{
  await resumed;f.receiver.transportReady=true;
  t.mock.timers.tick(4000);await new Promise(r=>setImmediate(r));assert.equal(sent,1);
  const before=pulses;
  for(let i=0;i<5;i++){t.mock.timers.tick(4000);await new Promise(r=>setImmediate(r));}
  assert(pulses>=before+5,'a pending host acknowledgement must not hold heartbeat renewal');assert.equal(sent,1);
 }finally{stop.abort();await running;fs.rmSync(dir,{recursive:true,force:true});}
});
