'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),http=require('node:http'),path=require('node:path'),{createHash,timingSafeEqual}=require('node:crypto');
const {DeliveryError}=require('./client.cjs');
function canonical(value){if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));return value;}
const hash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function tokenFile(file){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077)||s.size>512)throw new DeliveryError('BRIDGE_TOKEN_NOT_PRIVATE');const token=fs.readFileSync(file,'utf8').trim();if(!/^[A-Za-z0-9_-]{43}$/.test(token))throw new DeliveryError('BRIDGE_TOKEN_INVALID');return token;}
function endpoint(value){let u;try{u=new URL(value);}catch{throw new DeliveryError('BRIDGE_ENDPOINT_INVALID');}if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port||u.pathname!=='/'||u.username||u.password||u.search||u.hash)throw new DeliveryError('BRIDGE_ENDPOINT_INVALID');return u.origin;}
class BridgeHost{
 constructor(config,{binding}={}){if(!binding||!config.destination||!['CODEX_APP_SERVER','ANTIGRAVITY_APP'].includes(config.destination.host))throw new DeliveryError('BRIDGE_BINDING_REQUIRED');this.config=config;this.binding=binding;this.destination=config.destination;this.host=this.destination.host;this.mode=this.host==='ANTIGRAVITY_APP'?'TOOL_ONLY':'LIVE';this.endpoint=endpoint(config.endpoint);this.alive=false;}
 async call(method,body={}){
  let response;try{response=await fetch(this.endpoint+'/'+method,{method:'POST',redirect:'error',headers:{Authorization:'Bearer '+this.token,'Content-Type':'application/json'},body:JSON.stringify({binding:this.binding,destination:this.destination,...body}),signal:AbortSignal.timeout(this.config.timeoutMs??15000)});}catch{throw new DeliveryError(method==='deliver'?'HOST_ACK_UNKNOWN':'BRIDGE_UNAVAILABLE');}
  const text=await response.text();if(text.length>65536)throw new DeliveryError('BRIDGE_RESPONSE_INVALID');let out;try{out=JSON.parse(text);}catch{throw new DeliveryError('BRIDGE_RESPONSE_INVALID');}
  if(!response.ok||out.error)throw new DeliveryError(out.error??'BRIDGE_REJECTED');return out;
 }
 async start(){this.token=tokenFile(this.config.token_file);const health=await this.call('health');if(hash(health.destination)!==hash(this.destination))throw new DeliveryError('HOST_BINDING_MISMATCH');this.alive=true;return this;}
 async health(){if(!this.alive)return {ready:false,execution_state:'OFFLINE'};return (await this.call('health')).health;}
 deliver(message){return this.call('deliver',{message});}
 async requests(){return (await this.call('requests')).requests;}
 respond(id,result){return this.call('respond',{id,result});}
 reconcile(message_id,body_hash){return this.call('receipt',{message_id,body_hash});}
 resolve(message_id,resolution){return this.call('resolve',{message_id,...resolution});}
 close(){this.alive=false;this.token=null;}
}
async function serveBridge(config){
 const {createHost}=require('./hosts.cjs');if(!['codex','agy-app'].includes(config.host?.kind)||config.host.managed)throw new DeliveryError('BRIDGE_NATIVE_HOST_REQUIRED');
 if(!Array.isArray(config.bindings)||!config.bindings.length||config.bindings.length>32)throw new DeliveryError('BRIDGE_BINDING_REQUIRED');
 const token=tokenFile(config.token_file),allowed=new Set(config.bindings.map(hash)),host=createHost(config.host),directory=config.state_directory;
 if(typeof directory!=='string'||!path.isAbsolute(directory))throw new DeliveryError('ABSOLUTE_STATE_DIRECTORY_REQUIRED');
 fs.mkdirSync(directory,{recursive:true,mode:0o700});const stat=fs.lstatSync(directory);if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o077))throw new DeliveryError('BRIDGE_STATE_NOT_PRIVATE');
 const {ReceiverStore}=require('./store.cjs'),lock=new ReceiverStore(directory,{host:host.destination,bindings:config.bindings});lock.lock();
 const file=path.join(directory,'deliveries.json');if(fs.existsSync(file)){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077)||s.size>1048576)throw new DeliveryError('BRIDGE_STATE_NOT_PRIVATE');}
 let ledger=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):[];if(!Array.isArray(ledger)||ledger.length>256)throw new DeliveryError('BRIDGE_STATE_INVALID');
 const save=()=>{fs.writeFileSync(file+'.new',JSON.stringify(ledger),{mode:0o600,flag:'w'});fs.renameSync(file+'.new',file);};
 const inflight=new Map();try{await host.start();}catch(error){host.close();lock.close();throw error;}
 const server=http.createServer(async(req,res)=>{
  const fail=code=>{if(!res.writableEnded){res.writeHead(400,{'Content-Type':'application/json'});res.end(JSON.stringify({error:code}));}};
  try{
   const auth=Buffer.from(req.headers.authorization??''),expected=Buffer.from('Bearer '+token);
   if(req.method!=='POST'||auth.length!==expected.length||!timingSafeEqual(auth,expected)||req.headers.origin)throw new DeliveryError('BRIDGE_FORBIDDEN');
   const method=req.url?.slice(1);if(!['health','deliver','requests','respond','resolve','receipt'].includes(method))throw new DeliveryError('BRIDGE_METHOD_REJECTED');
   const chunks=[];let bytesRead=0;for await(const bytes of req){bytesRead+=bytes.length;if(bytesRead>131072)throw new DeliveryError('HOST_INPUT_TOO_LARGE');chunks.push(bytes);}
   const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));if(!allowed.has(hash(body.binding))||hash(body.destination)!==hash(host.destination))throw new DeliveryError('HOST_BINDING_MISMATCH');
   let result;
   if(method==='health')result={health:await host.health(),destination:host.destination};
   if(method==='requests')result={requests:await host.requests()};
   if(method==='respond'){if(config.allow_permission_responses!==true)throw new DeliveryError('BRIDGE_PERMISSION_RESPONSE_DISABLED');await host.respond(body.id,body.result);result={status:'HOST_RESPONSE_SENT'};}
   if(method==='receipt'){const row=ledger.find(r=>r.key===hash([body.binding,body.message_id]));if(!row||row.wire_digest!==body.body_hash)throw new DeliveryError('HOST_INPUT_CONFLICT');result={status:row.status,...row.status==='DONE'?{receipt:row.receipt}:{}};}
   if(method==='resolve'){const row=ledger.find(r=>r.key===hash([body.binding,body.message_id]));if(!row||!['SENDING','UNKNOWN'].includes(row.status)||inflight.has(row.key))throw new DeliveryError('DELIVERY_NOT_UNCERTAIN');if(body.confirmed_not_sent===true&&!body.host_receipt)row.status='NOT_SENT';else if(typeof body.host_receipt==='string'&&body.host_receipt.length>0&&body.host_receipt.length<=128&&!body.confirmed_not_sent){row.status='DONE';row.receipt={state:host.mode==='TOOL_ONLY'?'HOST_QUEUED':'HOST_ACCEPTED',receipt:body.host_receipt};}else throw new DeliveryError('DELIVERY_RESOLUTION_REQUIRED');save();result={status:'RESOLUTION_SAVED'};}
   if(method==='deliver'){
    const message=body.message;if(!message||typeof message.message_id!=='string'||message.message_id.length>256||hash(message.binding)!==hash(body.binding))throw new DeliveryError('HOST_BINDING_MISMATCH');
    const key=hash([body.binding,message.message_id]),digest=hash(message);let previous=ledger.find(r=>r.key===key);
    if(previous?.status==='NOT_SENT'){if(previous.digest!==digest)throw new DeliveryError('HOST_INPUT_CONFLICT');ledger.splice(ledger.indexOf(previous),1);previous=null;}
    if(previous){if(previous.digest!==digest)throw new DeliveryError('HOST_INPUT_CONFLICT');if(inflight.has(key))result=await inflight.get(key);else if(previous.status==='DONE')result=previous.receipt;else throw new DeliveryError('HOST_ACK_UNKNOWN');}
    else{
     if(ledger.length>=256){const at=ledger.findIndex(r=>r.status==='DONE');if(at<0)throw new DeliveryError('BRIDGE_CAPACITY');ledger.splice(at,1);}
     const row={key,digest,wire_digest:createHash('sha256').update(JSON.stringify(message)).digest('hex'),status:'SENDING'};ledger.push(row);save();
     const task=(async()=>{try{const receipt=await host.deliver(message);row.status='DONE';row.receipt=receipt;save();return receipt;}catch(error){row.status=['HOST_NOT_READY','HOST_NOT_SENT','HOST_INBOX_FULL','HOST_INPUT_TOO_LARGE'].includes(error.code)?'NOT_SENT':'UNKNOWN';save();throw error;}finally{inflight.delete(key);}})();inflight.set(key,task);result=await task;
    }
   }
   if(!res.writableEnded){res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(result));}
  }catch(error){fail(error.code??'BRIDGE_REQUEST_INVALID');}
 });
 server.requestTimeout=10000;server.headersTimeout=10000;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(config.port??0,'127.0.0.1',resolve);});
 return {server,host,endpoint:'http://127.0.0.1:'+server.address().port,destination:host.destination,close:async()=>{host.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));lock.close();}};
}
module.exports={BridgeHost,serveBridge,tokenFile};
