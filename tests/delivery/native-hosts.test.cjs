const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{createHash,randomBytes}=require('node:crypto');
const {CodexHost,createHost}=require('../../bindings/node/delivery/hosts.cjs');
const {AntigravityAppHost}=require('../../bindings/node/delivery/sidecar.cjs');
const {BridgeHost,serveBridge}=require('../../bindings/node/delivery/bridge.cjs');
const {DeliveryReceiver}=require('../../bindings/node/delivery/receiver.cjs');
function serverFrame(value,opcode=1,fin=true){const data=Buffer.from(typeof value==='string'?value:JSON.stringify(value));const header=Buffer.alloc(data.length<126?2:4);header[0]=(fin?128:0)|opcode;header[1]=data.length<126?data.length:126;if(data.length>=126)header.writeUInt16BE(data.length,2);return Buffer.concat([header,data]);}
async function appServer(directory,{badHandshake=false,loaded=true}={}){
 let active=null;const calls=[],sockets=new Set(),server=http.createServer();
 server.on('upgrade',(req,socket)=>{
  sockets.add(socket);socket.on('close',()=>sockets.delete(socket));
  const accept=createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: '+(badHandshake?'invalid':accept)+'\r\n\r\n');
  let input=Buffer.alloc(0);socket.on('data',bytes=>{
   input=Buffer.concat([input,bytes]);while(input.length>=6){let n=input[1]&127,at=2;if(n===126){if(input.length<4)return;n=input.readUInt16BE(2);at=4;}assert(input[1]&128,'client must mask all websocket frames');if(input.length<at+4+n)return;const mask=input.subarray(at,at+4),body=Buffer.from(input.subarray(at+4,at+4+n));for(let i=0;i<n;i++)body[i]^=mask[i%4];const opcode=input[0]&15;input=input.subarray(at+4+n);if(opcode===10)continue;
    const v=JSON.parse(body.toString());calls.push(v);const reply=result=>socket.write(serverFrame({id:v.id,result}));
    if(v.method==='initialize')reply({userAgent:'synthetic-existing-app'});
    if(v.method==='thread/read'||v.method==='thread/resume')reply({thread:{id:v.params.threadId,sessionId:'original-root-session',status:{type:loaded?(active?'active':'idle'):'notLoaded'}}});
    if(v.method==='thread/turns/list')reply({data:[{id:active,status:'inProgress'}]});
    if(v.method==='turn/start'){active='exact-turn';reply({turn:{id:active}});socket.write(serverFrame({method:'turn/started',params:{threadId:v.params.threadId,turn:{id:active}}}));}
    if(v.method==='turn/steer'){assert.equal(v.params.expectedTurnId,active);reply({turnId:active});}
   }
  });
 });
 const socketPath=path.join(directory,'codex.sock');await new Promise(resolve=>server.listen(socketPath,resolve));
 return {endpoint:'unix://'+socketPath,calls,server,close:async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}
test('Codex attaches over a real Unix WebSocket handshake and preserves original thread/active turn',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-native-')),app=await appServer(directory),host=new CodexHost({thread_id:'existing-thread',endpoint:app.endpoint,expected_session_id:'original-root-session'});
 try{await host.start();assert.equal((await host.deliver({message_id:'one'})).state,'HOST_ACCEPTED');assert.equal((await host.deliver({message_id:'two'})).receipt,'exact-turn');assert(app.calls.some(c=>c.method==='turn/steer'));assert(!app.calls.some(c=>['thread/start','thread/fork'].includes(c.method)));assert.equal(host.process.child,undefined);}
 finally{host.close();await app.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test('Codex rejects wrong handshake, unloaded thread and implicit managed launch',async()=>{
 assert.throws(()=>new CodexHost({thread_id:'existing'}),{code:'HOST_ENDPOINT_REQUIRED'});
 assert.throws(()=>createHost({kind:'agy-cli',conversation_id:'old'}),{code:'HOST_MANAGED_OPT_IN_REQUIRED'});
 for(const options of [{badHandshake:true},{loaded:false}]){
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-native-refuse-')),app=await appServer(directory,options),host=new CodexHost({thread_id:'existing',endpoint:app.endpoint});
  try{await assert.rejects(host.start(),{code:options.badHandshake?'HOST_WEBSOCKET_HANDSHAKE_FAILED':'HOST_SESSION_NOT_LOADED'});}finally{host.close();await app.close();fs.rmSync(directory,{recursive:true,force:true});}
 }
});
function sidecarConfig(directory){
 const executable=path.join(directory,'agentapi');fs.writeFileSync(executable,'#!/bin/sh\nexec '+JSON.stringify(process.execPath)+' '+JSON.stringify(path.join(directory,'agentapi.cjs'))+' "$@"\n',{mode:0o700});
 fs.writeFileSync(path.join(directory,'agentapi.cjs'),`const fs=require('node:fs');const args=process.argv.slice(2);if(args[0]!=='send-message'||args[1]!=='original-agy')process.exit(3);if(args.join(' ').includes('private-body'))process.exit(4);fs.appendFileSync(${JSON.stringify(path.join(directory,'calls.jsonl'))},JSON.stringify(args)+'\\n');`);
 return {kind:'agy-app',conversation_id:'original-agy',agentapi_path:executable,inbox_directory:path.join(directory,'inbox')};
}
test('AGY App invokes native existing-conversation API, keeps plaintext out of argv and reports only queued',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-sidecar-')),config=sidecarConfig(directory),host=new AntigravityAppHost(config);
 try{await host.start();assert.equal((await host.health()).execution_state,'UNKNOWN');const out=await host.deliver({message_id:'a',contents:'private-body'});assert.equal(out.state,'HOST_QUEUED');assert.equal((await host.health()).ready,false);const calls=JSON.parse(fs.readFileSync(path.join(directory,'calls.jsonl'),'utf8').trim());assert.equal(calls[1],'original-agy');assert(!calls.includes('new-conversation'));const files=fs.readdirSync(config.inbox_directory);assert.equal(files.length,1);const file=path.join(config.inbox_directory,files[0]);assert.equal(fs.statSync(file).mode&0o077,0);assert.equal(JSON.parse(fs.readFileSync(file)).contents,'private-body');}
 finally{host.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test('scoped host bridge authenticates and pins binding/destination, replays the same receipt without another host input',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-bridge-')),app=await appServer(directory),token_file=path.join(directory,'token'),binding={expected_actor:'actor',workspace_id:'space'};fs.writeFileSync(token_file,randomBytes(32).toString('base64url'),{mode:0o600});
 const bridge=await serveBridge({host:{kind:'codex',thread_id:'existing',endpoint:app.endpoint},bindings:[binding],token_file,state_directory:path.join(directory,'state')}),client=new BridgeHost({endpoint:bridge.endpoint,token_file,destination:bridge.destination},{binding});
 try{
  await client.start();const message={binding,message_id:'same-message'},first=await client.deliver(message);assert.deepEqual(await client.deliver(message),first);assert.equal(app.calls.filter(c=>c.method==='turn/start').length,1);
  await assert.rejects(client.deliver({...message,extra:'changed'}),{code:'HOST_INPUT_CONFLICT'});
  const wrong=new BridgeHost({endpoint:bridge.endpoint,token_file,destination:bridge.destination},{binding:{expected_actor:'other',workspace_id:'space'}});await assert.rejects(wrong.start(),{code:'HOST_BINDING_MISMATCH'});
  const denied=await fetch(bridge.endpoint+'/health',{method:'POST',headers:{Authorization:'Bearer wrong'},body:'{}'});assert.equal(denied.status,400);
 }finally{client.close();await bridge.close();await app.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test('queued native acceptance is retained across backend ACK loss and is never elevated to realtime',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-queued-')),binding={workspace_id:'space'},event={sequence:1,actor_id:'peer',record_refs:[]};let checkpoint=0,sends=0,lost=false;
 const accepted=structure=>({state:'ACCEPTED',result:{structure}}),client={binding,inbox:async()=>accepted({events:checkpoint?[]:[event],more:false}),ack:async body=>{if(body.stage==='HOST_QUEUED'){if(!lost){lost=true;throw Error('lost backend acknowledgement');}checkpoint=body.sequence;}return accepted({});},pulse:async body=>{assert.equal(body.ready,false);return accepted({route:{state:'TOOL_ONLY',execution_state:'UNKNOWN'}});}};
 const host={host:'ANTIGRAVITY_APP',mode:'TOOL_ONLY',config:{conversation_id:'original'},health:async()=>({ready:false,can_attempt:true,execution_state:'UNKNOWN'}),deliver:async()=>{sends++;return {state:'HOST_QUEUED',receipt:'native-queued'};}};
 const receiver=new DeliveryReceiver({client,host,session:{},stateDirectory:directory});receiver.fence={route_id:'route',epoch:1,receiver_id:'receiver'};receiver.selftestPassed=true;receiver.transportReady=true;
 try{await assert.rejects(receiver.drain());await receiver.drain();assert.equal(sends,1);assert.equal(receiver.store.delivery(1).status,'ACKED');assert.equal((await receiver.pulse()).state,'TOOL_ONLY');assert.equal(receiver.lastStatus.connection_state,'QUEUED_ONLY');}finally{receiver.store.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test('different OS user uses a scoped bridge without gaining access to the original root socket', {skip:process.getuid?.()!==0},async()=>{
 const {execFile}=require('node:child_process'),{promisify}=require('node:util'),directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-uid-'));fs.chmodSync(directory,0o755);
 const app=await appServer(directory);fs.chmodSync(path.join(directory,'codex.sock'),0o600);
 const lib=path.join(directory,'lib');fs.mkdirSync(lib,{mode:0o755});for(const name of ['bridge.cjs','client.cjs','websocket.cjs'])fs.copyFileSync(path.join(__dirname,'../../bindings/node/delivery',name),path.join(lib,name));
 const executable=path.join(directory,'node');try{fs.linkSync(process.execPath,executable);}catch{fs.copyFileSync(process.execPath,executable);}
 const peerDirectory=path.join(directory,'peer');fs.mkdirSync(peerDirectory,{mode:0o700});fs.chownSync(peerDirectory,65534,65534);
 const token_file=path.join(peerDirectory,'token');fs.writeFileSync(token_file,randomBytes(32).toString('base64url'),{mode:0o600});fs.chownSync(token_file,65534,65534);
 const binding={workspace_id:'space',expected_actor:'original-identity'},bridge=await serveBridge({host:{kind:'codex',thread_id:'original',endpoint:app.endpoint},bindings:[binding],token_file,state_directory:path.join(directory,'root-bridge')});
 try{
  const code=`const {HostWebSocket}=require(${JSON.stringify(path.join(lib,'websocket.cjs'))});const {BridgeHost}=require(${JSON.stringify(path.join(lib,'bridge.cjs'))});(async()=>{try{await new HostWebSocket({endpoint:${JSON.stringify(app.endpoint)}}).start();throw Error('original socket unexpectedly accessible')}catch(e){if(e.code!=='HOST_SOCKET_ACCESS_DENIED')throw e;}const binding=${JSON.stringify(binding)},host=new BridgeHost(${JSON.stringify({endpoint:bridge.endpoint,token_file,destination:bridge.destination})},{binding});await host.start();const result=await host.deliver({message_id:'cross-user',binding});if(result.state!=='HOST_ACCEPTED')throw Error('no receipt');host.close();console.log('SCOPED_CROSS_UID_PASS')})().catch(e=>{console.error(e.code||e.message);process.exitCode=1})`;
  const out=await promisify(execFile)(executable,['-e',code],{uid:65534,gid:65534,env:{PATH:'/usr/bin:/bin'},timeout:5000});assert.match(out.stdout,/SCOPED_CROSS_UID_PASS/);assert.equal(fs.statSync(path.join(directory,'codex.sock')).mode&0o777,0o600);
 }finally{await bridge.close();await app.close();fs.rmSync(directory,{recursive:true,force:true});}
});
test('bridge receipt survives restart, verifies original input hash and supports read-only reconciliation',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'pw-bridge-replay-')),app=await appServer(directory),token_file=path.join(directory,'token'),binding={workspace_id:'space'};fs.writeFileSync(token_file,randomBytes(32).toString('base64url'),{mode:0o600});
 const config={host:{kind:'codex',thread_id:'existing',endpoint:app.endpoint},bindings:[binding],token_file,state_directory:path.join(directory,'state')};let bridge=await serveBridge(config),client=new BridgeHost({endpoint:bridge.endpoint,token_file,destination:bridge.destination},{binding});const message={binding,message_id:'persisted'};
 try{
  await client.start();const receipt=await client.deliver(message);client.close();await bridge.close();bridge=await serveBridge(config);client=new BridgeHost({endpoint:bridge.endpoint,token_file,destination:bridge.destination},{binding});await client.start();
  const hash=createHash('sha256').update(JSON.stringify(message)).digest('hex');assert.deepEqual((await client.reconcile(message.message_id,hash)).receipt,receipt);assert.equal(app.calls.filter(c=>c.method==='turn/start').length,1);await assert.rejects(client.reconcile(message.message_id,'wrong'),{code:'HOST_INPUT_CONFLICT'});
 }finally{client.close();await bridge.close();await app.close();fs.rmSync(directory,{recursive:true,force:true});}
});
