#!/usr/bin/env node
'use strict';
// SPDX-License-Identifier: Apache-2.0
const fs=require('node:fs'),path=require('node:path'),net=require('node:net'),{createInterface}=require('node:readline');
if(Number(process.versions.node.split('.')[0])<24){console.error(JSON.stringify({status:'FAILED',code:'CONNECTOR_REQUIRES_NODE_24'}));process.exit(1);}
const sdk=require('../index.cjs'),{DeliveryReceiver,resolveSelftest}=require('./receiver.cjs'),{createHost}=require('./hosts.cjs'),{result,DeliveryError}=require('./client.cjs');
const usage='peerwork-connect <doctor|selftest|run|status|routes|receipt|close|requests|respond|resolve|resolve-selftest> CONFIG.json [arguments]';
async function control(socket,request){
 return new Promise((resolve,reject)=>{const client=net.connect(socket),timer=setTimeout(()=>{client.destroy();reject(new DeliveryError('RECEIVER_CONTROL_TIMEOUT'));},5000);let text='';
  client.on('connect',()=>client.write(JSON.stringify(request)+'\n'));client.on('data',data=>{text+=data.toString();if(text.length>65536){client.destroy();reject(new DeliveryError('RECEIVER_CONTROL_INVALID'));}});client.on('end',()=>{clearTimeout(timer);try{const out=JSON.parse(text);out.error?reject(new DeliveryError(out.error,out.outcome)):resolve(out);}catch(error){reject(error);}});client.on('error',error=>{clearTimeout(timer);reject(error);});
 });
}
async function main(){
 const [command,file,...args]=process.argv.slice(2);if(!command||!file)throw new DeliveryError(usage);
 const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077))throw new DeliveryError('CONNECTOR_CONFIG_NOT_PRIVATE');
 const config=JSON.parse(fs.readFileSync(file,'utf8'));if(!path.isAbsolute(config.state_directory))throw new DeliveryError('ABSOLUTE_STATE_DIRECTORY_REQUIRED');
 const socket=path.join(config.state_directory,'control.sock');
 if(['requests','respond','resolve','close'].includes(command)){
  const request=command==='close'?{method:'close',operation_id:require('node:crypto').randomUUID()}:command==='requests'?{method:'requests'}:command==='respond'?{method:'respond',id:args[0],result:JSON.parse(fs.readFileSync(args[1],'utf8'))}:{method:'resolve',sequence:Number(args[0]),...(args[1]==='--confirmed-not-sent'?{confirmed_not_sent:true}:{host_receipt:args[1]})};
  console.log(JSON.stringify(await control(socket,request)));return;
 }
 const kernel=await sdk.openKernel({...config.kernel,requiredFeatures:[...new Set([...(config.kernel.requiredFeatures??[]),'agent-delivery-v1','protocol-role-bundles-v1',...((config.host.kind==='agy-app'||config.host.destination?.host==='ANTIGRAVITY_APP')?['native-host-queue-v1']:[])])]}),session=sdk.protocolSession(kernel,config.binding),client=sdk.delivery(kernel,config.binding);
 if(command==='doctor'){
  const described=await session.describe();result(described.outcome);const host=createHost(config.host,{binding:config.binding});
  try{await host.start();const health=await host.health();console.log(JSON.stringify({status:'PASS',scope:'PRECHECK_ONLY',connection_state:'UNVERIFIED',version:sdk.version(),host:host.host,mode:host.mode,host_health:health,model_turn_started:false}));}finally{host.close();}return;
 }
 if(command==='routes'){console.log(JSON.stringify(await client.routes()));return;}
 if(command==='status'||command==='receipt'||command==='resolve-selftest'){
  if(!fs.existsSync(path.join(config.state_directory,'receiver.sqlite')))throw new DeliveryError('RECEIVER_NOT_BOUND');
  const {ReceiverStore}=require('./store.cjs'),host=createHost(config.host,{binding:config.binding}),store=new ReceiverStore(config.state_directory,{binding:client.binding,host:host.destination??host.config,includeSelf:config.include_self??false});
  try{const route=store.get('route');if(!route)throw new DeliveryError('RECEIVER_NOT_BOUND');
   if(command==='status'){
    const outcome=await client.get(route.route_id),remote=result(outcome).route,selftest=store.get('selftest');
    const connection_state=remote.state==='OFFLINE'?'DISCONNECTED':selftest?.status!=='PASS'?'UNVERIFIED':remote.state==='REALTIME_READY'?'CONNECTED':remote.state==='TOOL_ONLY'?'QUEUED_ONLY':'DEGRADED';
    console.log(JSON.stringify({outcome,pending:store.pending(),connection_state,selftest}));
   }
   else if(command==='receipt')console.log(JSON.stringify(await client.receipt(route.route_id,Number(args[0]))));
   else if(command==='resolve-selftest'){
    if(args.length!==1)throw new DeliveryError('SELFTEST_RESOLUTION_REQUIRED');
    store.lock();console.log(JSON.stringify(resolveSelftest(store,args[0]==='--confirmed-not-sent'?{confirmed_not_sent:true}:{host_receipt:args[0]})));
   }
   else throw new DeliveryError('CLOSE_REQUIRES_RUNNING_RECEIVER_CONTROL');
  }finally{store.close();}return;
 }
 if(!['run','selftest'].includes(command))throw new DeliveryError(usage);
 const host=createHost(config.host,{binding:config.binding}),receiver=new DeliveryReceiver({client,session,host,stateDirectory:config.state_directory,includeSelf:config.include_self??false,selftestTimeoutMs:config.selftest_timeout_ms??30000,onStatus:s=>console.log(JSON.stringify(s))}),abort=new AbortController();
 let server;
 const respond=async request=>{
  if(request.method==='requests')return {requests:await host.requests()};
  if(request.method==='respond'){await host.respond(request.id,request.result);return {status:'HOST_RESPONSE_SENT'};}
  if(request.method==='resolve'){await receiver.resolve(request.sequence,request);return {status:'RESOLUTION_SAVED'};}
  if(request.method==='close'){result(await client.close(receiver.fence,{operation_id:request.operation_id}));abort.abort();return {status:'ROUTE_CLOSED'};}
  throw new DeliveryError('RECEIVER_CONTROL_INVALID');
 };
 try{
  // The receiver lock is acquired before exposing the local control socket.
  receiver.store.lock();receiver.store.lock=()=>{};
  if(fs.existsSync(socket)){if(!fs.lstatSync(socket).isSocket())throw new DeliveryError('RECEIVER_CONTROL_INVALID');fs.unlinkSync(socket);}
  server=net.createServer(client=>{client.setTimeout(5000,()=>client.destroy());let text='';client.on('data',data=>{text+=data.toString();if(text.length>65536){client.destroy();return;}if(text.includes('\n')){client.removeAllListeners('data');Promise.resolve().then(()=>respond(JSON.parse(text.trim()))).then(v=>client.end(JSON.stringify(v)),e=>client.end(JSON.stringify({error:e.code??'RECEIVER_CONTROL_INVALID',outcome:e.outcome??null})));}});});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socket,resolve);});fs.chmodSync(socket,0o600);
  process.once('SIGTERM',()=>abort.abort());process.once('SIGINT',()=>abort.abort());
  const report=await receiver.run({signal:abort.signal,replace:args.includes('--replace'),resumeClosed:args.includes('--resume-closed'),selftestOnly:command==='selftest'});
  if(command==='selftest')console.log(JSON.stringify({status:'PASS',selftest:report,receiver_stopped:true}));
 }finally{abort.abort();server?.close();if(fs.existsSync(socket))fs.unlinkSync(socket);}
}
main().catch(error=>{console.error(JSON.stringify({status:'FAILED',code:error.code??'CONNECTOR_FAILED',outcome:error.outcome??null}));process.exitCode=1;});
