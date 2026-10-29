'use strict';
// SPDX-License-Identifier: Apache-2.0
const {randomBytes,randomUUID}=require('node:crypto');
const {setTimeout:delay}=require('node:timers/promises');
const {DeliveryError,result}=require('./client.cjs');
const {ReceiverStore,digest}=require('./store.cjs');
const id=()=>randomBytes(32).toString('base64url');
class DeliveryReceiver {
 constructor({client,session,host,stateDirectory,includeSelf=false,onStatus=()=>{},selftestTimeoutMs=30000}){
  if(!Number.isSafeInteger(selftestTimeoutMs)||selftestTimeoutMs<100||selftestTimeoutMs>120000)throw new DeliveryError('SELFTEST_TIMEOUT_INVALID');
  this.client=client;this.session=session;this.host=host;this.onStatus=onStatus;this.includeSelf=includeSelf;
  this.store=new ReceiverStore(stateDirectory,{binding:client.binding,host:host.destination??host.config,includeSelf});this.transportReady=false;this.busy=false;this.blocked=false;this.fence=null;this.selftestPassed=false;this.selftestTimeoutMs=selftestTimeoutMs;
 }
 reportSelftest(stage,extra={}){
  this.testReport={...this.testReport,stage,...extra};this.store.set('selftest',this.testReport);
  this.onStatus({connection_state:'SELF_TESTING',selftest:this.testReport});
 }
 async selftest(signal){
  this.reportSelftest('INBOX');
  // Exercise the actual signed, fenced inbox without consuming or ACKing an
  // event. Existing checkpoints and pending deliveries are never changed.
  result(await this.client.inbox({...this.fence,limit:1},{signal}));
  this.reportSelftest('HOST');
  const health=await this.host.health();if(!health.ready&&!health.can_attempt)throw new DeliveryError('HOST_NOT_READY');
  const nonce=id(),probe={format:'peerwork.selftest.v1',message_id:'selftest:'+nonce,binding:this.client.binding,
   route_id:this.fence.route_id,epoch:this.fence.epoch,nonce,
   purpose:'Connection self-test only. No tools, business actions or reply are requested.'};
  // Persist before the host write: a lost host acknowledgement must never
  // silently inject a second test prompt, including across process restart.
  this.reportSelftest('HOST',{status:'SENDING',message_id:probe.message_id});
  let receipt;
  try{
   receipt=await this.host.deliver(probe);
   if(receipt?.state!=='HOST_ACCEPTED'||typeof receipt.receipt!=='string'||!receipt.receipt)throw new DeliveryError('HOST_ACK_UNKNOWN');
  }catch(error){
   this.reportSelftest('HOST',{status:error.code==='HOST_NOT_READY'?'FAILED':'UNCERTAIN',code:error.code??'HOST_ACK_UNKNOWN'});throw error;
  }
  if(signal.aborted){this.reportSelftest('HOST',{status:'HOST_ACCEPTED',host_receipt:receipt.receipt});throw signal.reason;}
  this.reportSelftest('HOST_ACCEPTED',{status:'HOST_ACCEPTED',host_receipt:receipt.receipt,model_response:'NOT_ATTESTED'});
  this.selftestPassed=true;return this.testReport;
 }
 async claim({signal,replace=false,resumeClosed=false}={}){
  let selection=this.store.get('claim');
  if(!selection){
   const old=this.store.get('route');selection={route_id:old?.route_id??id(),receiver_id:id(),expected_epoch:old?.epoch??null,host:this.host.host,mode:this.host.mode,destination_digest:digest(this.host.destination??this.host.config),include_self:this.includeSelf,replace,resume_closed:resumeClosed,operation_id:randomUUID()};this.store.set('claim',selection);
  }
  const {operation_id,...body}=selection,out=await this.client.claim(body,{operation_id,signal});
  if(out.state==='REJECTED'){this.store.set('claim',null);throw new DeliveryError(out.result?.structure?.error?.code??'DELIVERY_CLAIM_REJECTED',out);}
  const route=result(out).route;this.fence={route_id:route.route_id,epoch:route.epoch,receiver_id:selection.receiver_id};this.store.set('route',{route_id:route.route_id,epoch:route.epoch});this.store.set('claim',null);return route;
 }
 pulse(signal){
  const task=(this.pulseTask??Promise.resolve()).catch(()=>{}).then(()=>this._pulse(signal));this.pulseTask=task;return task;
 }
 async _pulse(signal){
  if(!this.fence)return;
  let health;try{health=await this.host.health();}catch{health={ready:false,execution_state:'OFFLINE'};}
  const uncertain=this.store.pending().some(p=>p.status==='HOST_SENDING'||p.status==='UNCERTAIN');
  const out=await this.client.pulse({...this.fence,ready:this.selftestPassed&&health.ready&&!uncertain&&!this.blocked,execution_state:health.execution_state,transport_ready:this.transportReady},{signal});
  const route=result(out).route;
  this.lastStatus={route_id:route.route_id,state:route.state,execution_state:route.execution_state,
   connection_state:!this.transportReady||health.execution_state==='OFFLINE'?'DISCONNECTED':!this.selftestPassed?'SELF_TESTING':uncertain||this.blocked?'DEGRADED':'CONNECTED',selftest:this.testReport};
  this.onStatus(this.lastStatus);return route;
 }
 async frame(event,signal){
  this.blocked=true;const records=[];let bytes=0;
  for(const reference of event.record_refs){
   const out=await this.session.record(reference,{signal});
   if(out.state==='REJECTED'&&out.result?.structure?.error?.code==='RECORD_WITHDRAWN'){records.push({reference,state:'WITHDRAWN'});continue;}
   const verified=result(out);if(out.result.opened_contents?.some(c=>!['OPENED','NO_CONTENT'].includes(c.state)))throw new DeliveryError('DELIVERY_CONTENT_KEYS_REQUIRED');const item={reference,structure:verified.structure,contents:out.result.opened_contents};
   const size=Buffer.byteLength(JSON.stringify(item));if(bytes+size>32768){records.push({reference,state:'FETCH_EXACT_REFERENCE',reason:'CONTEXT_BYTE_LIMIT'});continue;}bytes+=size;records.push(item);
  }
  this.blocked=false;return {format:'peerwork.incoming.v1',message_id:this.client.binding.workspace_id+':'+this.fence.route_id+':'+event.sequence,binding:this.client.binding,sequence:event.sequence,actor_id:event.actor_id,records};
 }
 async drain(signal){
  if(this.busy)return;this.busy=true;
  try{
   const inbox=result(await this.client.inbox({...this.fence,limit:16},{signal}));this.store.persist(inbox.events);
   for(const event of inbox.events){
    if(signal?.aborted)return;const row=this.store.delivery(event.sequence);
    if(row.status==='ACKED')continue;
    result(await this.client.ack({...this.fence,sequence:event.sequence,stage:'CONNECTOR_RECEIVED'},{signal}));
    if(['HOST_ACCEPTED','HOST_CONFIRMED'].includes(row.status)){
     result(await this.client.ack({...this.fence,sequence:event.sequence,stage:'HOST_ACCEPTED',host_receipt:row.receipt,resolve_uncertain:row.status==='HOST_CONFIRMED'},{signal}));this.store.mark(event.sequence,'ACKED');continue;
    }
    if(row.status==='HOST_SENDING'||row.status==='UNCERTAIN'){
     this.store.mark(event.sequence,'UNCERTAIN');result(await this.client.ack({...this.fence,sequence:event.sequence,stage:'UNCERTAIN'},{signal}));this.onStatus({state:'DELAYED',code:'HOST_ACK_UNKNOWN',sequence:event.sequence});return;
    }
    const health=await this.host.health();if(!health.ready&&!health.can_attempt)return;
    const frame=await this.frame(event,signal),bodyHash=digest(frame);
    if(this.host.mode==='IDLE_ONLY')result(await this.client.pulse({...this.fence,ready:false,transport_ready:this.transportReady,execution_state:'BUSY'},{signal}));
    this.store.mark(event.sequence,'HOST_SENDING',null,bodyHash);
    let receipt;
    try{receipt=await this.host.deliver(frame);}catch(error){
     // A definite local precondition failure did not write a prompt. A lost
     // host response is kept uncertain, never automatically injected again.
     if(error.code==='HOST_NOT_READY'){this.store.mark(event.sequence,'RECEIVED');return;}
     this.store.mark(event.sequence,'UNCERTAIN');await this.client.ack({...this.fence,sequence:event.sequence,stage:'UNCERTAIN'},{signal});throw error;
    }
    if(receipt.state!=='HOST_ACCEPTED'||!receipt.receipt)throw new DeliveryError('HOST_ACK_UNKNOWN');
    this.store.mark(event.sequence,'HOST_ACCEPTED',receipt.receipt);
    result(await this.client.ack({...this.fence,sequence:event.sequence,stage:'HOST_ACCEPTED',host_receipt:receipt.receipt,resolve_uncertain:row.status==='RETRY_CONFIRMED'},{signal}));this.store.mark(event.sequence,'ACKED');this.store.prune();
   }
   return inbox.more;
  }finally{this.busy=false;}
 }
 resolve(sequence,{host_receipt,confirmed_not_sent=false}={}){
  const row=this.store.delivery(sequence);if(!row||!['HOST_SENDING','UNCERTAIN'].includes(row.status))throw new DeliveryError('DELIVERY_NOT_UNCERTAIN');
  if(host_receipt)this.store.mark(sequence,'HOST_CONFIRMED',host_receipt);
  else if(confirmed_not_sent)this.store.mark(sequence,'RETRY_CONFIRMED');else throw new DeliveryError('DELIVERY_RESOLUTION_REQUIRED');
 }
 async run({signal,replace=false,resumeClosed=false,selftestOnly=false}={}){
  const stop=new AbortController();signal=signal?AbortSignal.any([signal,stop.signal]):stop.signal;
  const terminal=error=>{if(['DELIVERY_EPOCH_MISMATCH','FORBIDDEN','ACCESS_EXPIRED','WORKSPACE_DELETED','WORKSPACE_DELETION_IN_PROGRESS'].includes(error.code))stop.abort();};
  this.store.lock();let heartbeating=false,timer,tickTask,drainTask,startupTimer,startupError;
  try{
   const previous=this.store.get('selftest');
   if(['SENDING','UNCERTAIN'].includes(previous?.status))throw new DeliveryError('SELFTEST_HOST_OUTCOME_UNKNOWN');
   this.testStarted=performance.now();this.selftestPassed=false;this.startupComplete=false;
   const previous_probe=previous?Object.fromEntries(['status','message_id','host_receipt','resolved_at','code'].filter(k=>previous[k]!==undefined).map(k=>[k,previous[k]])):undefined;
   this.testReport={status:'RUNNING',started_at:new Date().toISOString(),...(previous_probe?{previous_probe}:{})};this.reportSelftest('ROLE');
   startupTimer=setTimeout(()=>{startupError=new DeliveryError('SELFTEST_TIMEOUT');stop.abort(startupError);this.host.close();},this.selftestTimeoutMs);
   result((await this.session.describe({signal})).outcome);
   signal.throwIfAborted();
   this.reportSelftest('HOST_START');
   await this.host.start();
   signal.throwIfAborted();
   this.reportSelftest('ROUTE');
   for(let attempt=0;;attempt++){
    try{await this.claim({signal,replace,resumeClosed});break;}catch(error){
     if(error.code!=='DELIVERY_RECEIVER_BUSY'||attempt>=2)throw error;
     const previous=this.store.get('route');if(!previous)throw error;
     const current=result(await this.client.get(previous.route_id,{signal})).route;
     await delay(Math.max(100,Math.min(15100,current.lease_until-current.server_time+100)),undefined,{signal});
    }
   }
   const tick=async()=>{if(heartbeating||signal?.aborted)return;heartbeating=true;try{await this.pulse(signal);if(this.selftestPassed&&this.transportReady&&!this.busy)drainTask=this.drain(signal).catch(error=>{terminal(error);this.onStatus({state:'DELAYED',connection_state:'DEGRADED',code:error.code??'DELIVERY_UNAVAILABLE'});});}catch(error){terminal(error);this.onStatus({state:'DELAYED',connection_state:'DEGRADED',code:error.code??'DELIVERY_UNAVAILABLE'});}finally{heartbeating=false;}};
   const hostChanged=()=>{tickTask=tick();void tickTask;};
   this.host.process?.on('approval',hostChanged);
   this.host.process?.on('event',event=>{if(['turn/started','turn/completed','thread/status/changed'].includes(event.method)||event.event==='result')hostChanged();});
   timer=setInterval(hostChanged,4000);let attempt=0;
   this.reportSelftest('STREAM');
   while(!signal?.aborted){
    try{
     for await(const wake of this.client.wakes(this.fence,{signal})){
      if(wake.event!=='ready'&&!this.transportReady)continue;
      this.transportReady=true;attempt=0;
      if(!this.selftestPassed)await this.selftest(signal);
      const route=await this.pulse(signal);
      if(!this.startupComplete){
       if(route.execution_state==='OFFLINE')throw new DeliveryError('HOST_DISCONNECTED');
       clearTimeout(startupTimer);this.startupComplete=true;
       this.testReport={...this.testReport,stage:'COMPLETE',status:'PASS',elapsed_ms:Math.round(performance.now()-this.testStarted)};this.store.set('selftest',this.testReport);
       this.onStatus({...this.lastStatus,selftest:this.testReport});
      }
      if(selftestOnly)return this.testReport;
      while(await this.drain(signal)){if(signal?.aborted)break;}
     }
    }catch(error){if(!this.selftestPassed)throw startupError??error;terminal(error);if(!signal?.aborted)this.onStatus({state:'DELAYED',connection_state:'DISCONNECTED',code:error.code??'DELIVERY_STREAM_UNAVAILABLE'});}
    this.transportReady=false;if(signal?.aborted)break;await this.pulse(signal).catch(()=>{});
    await delay(Math.min(5000,250*2**Math.min(attempt++,5)),undefined,{signal}).catch(()=>{});
   }
   if(startupError)throw startupError;
  }catch(error){
   if(this.testReport&&!this.startupComplete){
    const saved=this.store.get('selftest');this.testReport={...saved,status:['SENDING','UNCERTAIN'].includes(saved?.status)?'UNCERTAIN':'FAILED',code:(startupError??error).code??'SELFTEST_FAILED'};
    this.store.set('selftest',this.testReport);this.onStatus({connection_state:'FAILED',selftest:this.testReport});
   }
   throw startupError??error;
  }finally{
   clearTimeout(startupTimer);clearInterval(timer);this.transportReady=false;stop.abort();this.host.close();
   await drainTask?.catch(()=>{});await tickTask?.catch(()=>{});await this.pulseTask?.catch(()=>{});
   if(this.fence)await this.client.pulse({...this.fence,ready:false,transport_ready:false,execution_state:'OFFLINE'},{signal:AbortSignal.timeout(2000)}).catch(()=>{});
   this.store.close();
  }
 }
}
function resolveSelftest(store,{host_receipt,confirmed_not_sent=false}={}){
 const current=store.get('selftest');
 if(!['SENDING','UNCERTAIN'].includes(current?.status))throw new DeliveryError('SELFTEST_NOT_UNCERTAIN');
 if((typeof host_receipt==='string'&&host_receipt.length>0&&host_receipt.length<=128)!==!confirmed_not_sent)throw new DeliveryError('SELFTEST_RESOLUTION_REQUIRED');
 const resolution=host_receipt?{status:'RESOLVED_HOST_ACCEPTED',host_receipt}:{status:'CONFIRMED_NOT_SENT'};
 store.set('selftest',{...current,...resolution,resolved_at:new Date().toISOString()});return {status:'RESOLUTION_SAVED',next:'RUN_SELFTEST'};
}
module.exports={DeliveryReceiver,resolveSelftest};
