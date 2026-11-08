'use strict';
// SPDX-License-Identifier: Apache-2.0
// Bounded RFC6455 client: Unix control sockets use HTTP Upgrade, not JSONL.
const http=require('node:http'),https=require('node:https'),fs=require('node:fs');
const {EventEmitter}=require('node:events'),{randomBytes,createHash}=require('node:crypto');
const {DeliveryError}=require('./client.cjs');
const MAX=2*1024*1024,GUID='258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(opcode,payload){
 payload=Buffer.from(payload);if(payload.length>MAX)throw new DeliveryError('HOST_FRAME_TOO_LARGE');
 const extra=payload.length<126?0:payload.length<=65535?2:8,header=Buffer.alloc(2+extra+4),mask=randomBytes(4);
 header[0]=0x80|opcode;header[1]=0x80|(extra===0?payload.length:extra===2?126:127);
 if(extra===2)header.writeUInt16BE(payload.length,2);if(extra===8)header.writeBigUInt64BE(BigInt(payload.length),2);mask.copy(header,2+extra);
 const body=Buffer.from(payload);for(let i=0;i<body.length;i++)body[i]^=mask[i%4];return Buffer.concat([header,body]);
}
function connectionError(error){
 return new DeliveryError(error.code==='EACCES'||error.code==='EPERM'?'HOST_SOCKET_ACCESS_DENIED':error.code?.startsWith('ERR_TLS')||['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(error.code)?'HOST_TLS_REJECTED':'HOST_ENDPOINT_UNAVAILABLE');
}
class HostWebSocket extends EventEmitter{
 constructor(config){super();this.config=config;this.alive=false;this.buffer=Buffer.alloc(0);this.fragments=[];this.fragmentBytes=0;}
 async start(){
  const {endpoint,auth_token_env}=this.config;if(typeof endpoint!=='string')throw new DeliveryError('HOST_ENDPOINT_REQUIRED');
  let options,request=http.request;
  if(endpoint.startsWith('unix://')){
   const socketPath=endpoint.slice(7);if(!socketPath.startsWith('/')||socketPath.includes('\0')||socketPath.includes('?')||socketPath.includes('#'))throw new DeliveryError('HOST_ENDPOINT_INVALID');
   try{const s=fs.lstatSync(socketPath);if(!s.isSocket()||s.isSymbolicLink())throw new DeliveryError('HOST_SOCKET_INVALID');fs.accessSync(socketPath,fs.constants.W_OK);}catch(error){if(error.code?.startsWith('HOST_'))throw error;throw connectionError(error);}
   options={socketPath,path:'/',host:'localhost'};
  }else{
   let u;try{u=new URL(endpoint);}catch{throw new DeliveryError('HOST_ENDPOINT_INVALID');}
   if(!['ws:','wss:'].includes(u.protocol)||u.username||u.password||u.hash||u.search)throw new DeliveryError('HOST_ENDPOINT_INVALID');
   if(u.protocol==='ws:'&&!['127.0.0.1','[::1]','localhost'].includes(u.hostname))throw new DeliveryError('HOST_TLS_REQUIRED');
   request=u.protocol==='wss:'?https.request:http.request;options={hostname:u.hostname.replace(/^\[|\]$/g,''),port:u.port||(u.protocol==='wss:'?443:80),path:u.pathname||'/'};
  }
  const nonce=randomBytes(16).toString('base64');options.headers={Connection:'Upgrade',Upgrade:'websocket','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':nonce};
  if(auth_token_env!==undefined){const token=typeof auth_token_env==='string'?process.env[auth_token_env]:null;if(!token||/[\r\n]/.test(token))throw new DeliveryError('HOST_AUTH_TOKEN_REQUIRED');options.headers.Authorization='Bearer '+token;}
  await new Promise((resolve,reject)=>{
   let settled=false;const fail=error=>{if(settled)return;settled=true;clearTimeout(timer);req.destroy();reject(error);};
   const req=request(options),timer=setTimeout(()=>fail(new DeliveryError('HOST_CONNECT_TIMEOUT')),this.config.timeoutMs??10000);this.request=req;
   req.once('error',error=>fail(connectionError(error)));
   req.once('response',response=>{response.resume();fail(new DeliveryError([401,403].includes(response.statusCode)?'HOST_AUTH_REJECTED':'HOST_TRANSPORT_MISMATCH'));});
   req.once('upgrade',(response,socket,head)=>{
    const accept=createHash('sha1').update(nonce+GUID).digest('base64');
    if(response.statusCode!==101||response.headers['sec-websocket-accept']!==accept||response.headers.upgrade?.toLowerCase()!=='websocket'||response.headers['sec-websocket-extensions']||response.headers['sec-websocket-protocol']){socket.destroy();fail(new DeliveryError('HOST_WEBSOCKET_HANDSHAKE_FAILED'));return;}
    if(settled){socket.destroy();return;}settled=true;clearTimeout(timer);this.socket=socket;this.alive=true;
    socket.on('error',()=>this.close());socket.on('close',()=>this.close());socket.on('data',bytes=>{try{this.consume(bytes);}catch(error){this.emit('protocol-error',error);this.close();}});
    resolve();if(head.length)queueMicrotask(()=>{try{this.consume(head);}catch(error){this.emit('protocol-error',error);this.close();}});
   });req.end();
  });return this;
 }
 consume(bytes){
  this.buffer=Buffer.concat([this.buffer,bytes]);
  while(this.buffer.length>=2){
   const first=this.buffer[0],second=this.buffer[1],fin=!!(first&128),opcode=first&15;let length=second&127,at=2;
   if((first&112)||(second&128)||![0,1,8,9,10].includes(opcode))throw new DeliveryError('HOST_WEBSOCKET_FRAME_INVALID');
   if(length===126){if(this.buffer.length<4)return;length=this.buffer.readUInt16BE(2);at=4;if(length<126)throw new DeliveryError('HOST_WEBSOCKET_FRAME_INVALID');}
   else if(length===127){if(this.buffer.length<10)return;const n=this.buffer.readBigUInt64BE(2);if(n>BigInt(MAX)||n<=65535n)throw new DeliveryError('HOST_FRAME_TOO_LARGE');length=Number(n);at=10;}
   if(length>MAX||opcode>=8&&(!fin||length>125))throw new DeliveryError('HOST_WEBSOCKET_FRAME_INVALID');
   if(this.buffer.length<at+length)return;const payload=this.buffer.subarray(at,at+length);this.buffer=this.buffer.subarray(at+length);
   if(opcode===8){this.close();return;}if(opcode===9){this.socket.write(frame(10,payload));continue;}if(opcode===10)continue;
   if(opcode===1){if(this.fragments.length)throw new DeliveryError('HOST_WEBSOCKET_FRAME_INVALID');}
   else if(!this.fragments.length)throw new DeliveryError('HOST_WEBSOCKET_FRAME_INVALID');
   this.fragments.push(payload);this.fragmentBytes+=length;if(this.fragmentBytes>MAX)throw new DeliveryError('HOST_FRAME_TOO_LARGE');
   if(fin){const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(this.fragments));this.fragments=[];this.fragmentBytes=0;let value;try{value=JSON.parse(text);}catch{throw new DeliveryError('HOST_RPC_INVALID');}this.emit('message',value);}
  }
 }
 write(value){if(!this.alive)throw new DeliveryError('HOST_DISCONNECTED');this.socket.write(frame(1,Buffer.from(JSON.stringify(value))));}
 close(){const wasAlive=this.alive;this.alive=false;this.request?.destroy();this.socket?.destroy();if(wasAlive)this.emit('closed');}
}
module.exports={HostWebSocket,frame};
