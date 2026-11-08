"""Generate a bounded fault-only copy of the immutable reference proxy."""
from pathlib import Path
import hashlib,json,sys
source,target,events=map(Path,sys.argv[1:]);text=source.read_text()
needle='const proxy = createServer(async (request, response) => {\n  try {'
insert='''let ackArm=false,ackFinished=false,ackFault=false,ackTampered=0;
const ackEvent=value=>writeFileSync(process.env.PEERWORK_ACK_EVENTS,JSON.stringify(value)+'\\n',{flag:'a',mode:0o600});
const proxy = createServer(async (request, response) => {
  try {
    if(request.url==='/__test/ack-arm'&&request.method==='POST'){
      if(ackArm||ackFinished)throw Error('ACK already armed');ackArm=true;
      response.writeHead(200,{'content-type':'application/json'});response.end('{}');return;
    }
    if(request.url==='/__test/ack-clear'&&request.method==='POST'){
      ackFault=false;response.writeHead(200,{'content-type':'application/json'});response.end('{}');return;
    }
    if(request.url==='/__test/ack-status'&&request.method==='GET'){
      response.writeHead(200,{'content-type':'application/json'});response.end(JSON.stringify({finished:ackFinished,fault:ackFault,tampered:ackTampered}));return;
    }'''
assert text.count(needle)==1;text=text.replace(needle,insert)
needle="    response.writeHead(original.status, {'content-type': original.headers.get('content-type') || 'application/json'});\n    response.end(bytes);"
insert='''    if(ackFault&&request.method==='GET'&&request.url.includes('/journal?')&&original.status===200){
      const before=createHash('sha256').update(bytes).digest('hex');const value=JSON.parse(bytes.toString('utf8'));
      if(!value.checkpoint||typeof value.checkpoint.head!=='string')throw Error('ACK checkpoint missing');
      value.checkpoint.head='0'.repeat(64);bytes=Buffer.from(JSON.stringify(value));ackTampered++;
      ackEvent({event:'journal_tampered',status:200,path:request.url,field:'checkpoint.head',original_sha256:before,delivered_sha256:createHash('sha256').update(bytes).digest('hex')});
    }
    if(ackArm&&request.method==='POST'&&request.url.endsWith('/commits')&&original.status>=200&&original.status<300){
      writeFileSync(process.env.PEERWORK_ACK_RESPONSE,bytes,{mode:0o600,flag:'wx'});
      ackArm=false;const command=JSON.parse(Buffer.concat(chunks).toString('utf8')).commit.payload.command_id;
      const status=original.status,hash=createHash('sha256').update(bytes).digest('hex');
      response.once('finish',()=>{ackFinished=true;ackFault=true;ackEvent({event:'post_ack_response_finished',status,command_id:command,body_sha256:hash,request_sha256:createHash('sha256').update(Buffer.concat(chunks)).digest('hex')});});
    }
    response.writeHead(original.status, {'content-type': original.headers.get('content-type') || 'application/json'});
    response.end(bytes);'''
assert text.count(needle)==1;text=text.replace(needle,insert);target.write_text(text);target.chmod(0o600)
print(json.dumps(dict(source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),overlay_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),fault='POST ack finish then HTTP200 checkpoint head mismatch; test hooks only')))
