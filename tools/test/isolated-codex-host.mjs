// Isolated official host qualification. No user credentials or model service.
import http from 'node:http';
import {spawn,execFileSync} from 'node:child_process';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
const root=process.argv[2],executable=process.env.PEERWORK_TEST_CODEX_EXECUTABLE;if(!root||!executable)throw Error('explicit fresh report directory and PEERWORK_TEST_CODEX_EXECUTABLE required');if(execFileSync(executable,['--version'],{encoding:'utf8'}).trim()!=='codex-cli 0.166.0')throw Error('qualification is pinned to official Codex0.166.0');mkdirSync(root,{recursive:true,mode:0o700});
const stats={model_requests:0,initial_completed:false,unloaded:false,post_delivery_turns:0};
const model=http.createServer(async(req,res)=>{
 let body='';for await(const chunk of req)body+=chunk;
 if(!req.url.endsWith('/responses')){res.writeHead(404).end();return;}
 JSON.parse(body);stats.model_requests++;
 const id='resp_'+stats.model_requests,item={id:'msg_'+stats.model_requests,type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'ISOLATED_HOST_OK',annotations:[]}]};
 res.writeHead(200,{'content-type':'text/event-stream'});
 const send=(type,value)=>res.write('event: '+type+'\ndata: '+JSON.stringify({type,...value})+'\n\n');
 send('response.created',{response:{id,object:'response',status:'in_progress',output:[]}});
 send('response.output_item.added',{output_index:0,item:{...item,status:'in_progress',content:[]}});
 send('response.content_part.added',{item_id:item.id,output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}});
 send('response.output_text.delta',{item_id:item.id,output_index:0,content_index:0,delta:'ISOLATED_HOST_OK'});
 send('response.output_text.done',{item_id:item.id,output_index:0,content_index:0,text:'ISOLATED_HOST_OK'});
 send('response.content_part.done',{item_id:item.id,output_index:0,content_index:0,part:item.content[0]});
 send('response.output_item.done',{output_index:0,item});
 send('response.completed',{response:{id,object:'response',status:'completed',output:[item],usage:{input_tokens:1,output_tokens:1,total_tokens:2}}});res.end();
});model.listen(0,'127.0.0.1');await once(model,'listening');
const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r));
const home=join(root,'codex-home'),work=join(root,'empty-work');mkdirSync(home,{mode:0o700});mkdirSync(work,{mode:0o700});
writeFileSync(join(home,'config.toml'),`model = "isolated-test-model"\nmodel_provider = "isolated"\n[model_providers.isolated]\nname = "Isolated synthetic provider"\nbase_url = "http://127.0.0.1:${model.address().port}/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n`,{mode:0o600});
const env={...process.env,CODEX_HOME:home};delete env.OPENAI_API_KEY;delete env.CODEX_API_KEY;
const host=spawn(executable,['app-server','--listen',`ws://127.0.0.1:${port}`],{env,cwd:work,stdio:['ignore','pipe','pipe']});
let hostLog='';host.stderr.on('data',b=>{hostLog=(hostLog+b).slice(-3000);});host.stdout.resume();
let socket;const pending=new Map();let next=1,completed=0;
async function connect(){
 const s=new WebSocket(`ws://127.0.0.1:${port}`);await new Promise((resolve,reject)=>{s.onopen=resolve;s.onerror=reject;});
 s.onmessage=e=>{const v=JSON.parse(e.data);if(v.id&&pending.has(v.id)){const p=pending.get(v.id);pending.delete(v.id);v.error?p.reject(Error(JSON.stringify(v.error))):p.resolve(v.result);}if(v.method==='turn/completed')completed++;};socket=s;
 await rpc('initialize',{clientInfo:{name:'peerwork_isolated_test',version:'1'},capabilities:{experimentalApi:true}});socket.send(JSON.stringify({method:'initialized'}));
}
function rpc(method,params){return new Promise((resolve,reject)=>{const id=next++;const t=setTimeout(()=>{pending.delete(id);reject(Error('RPC_TIMEOUT '+method));},10000);pending.set(id,{resolve:v=>{clearTimeout(t);resolve(v);},reject:e=>{clearTimeout(t);reject(e);}});socket.send(JSON.stringify({id,method,params}));});}
async function until(fn,ms){const end=Date.now()+ms;for(;;){const v=await fn();if(v)return v;if(Date.now()>=end)throw Error('WAIT_TIMEOUT');await delay(500);}}
let control;
async function stop(){try{socket?.close();}catch{}control?.close();model.close();host.kill('SIGTERM');await Promise.race([once(host,'exit'),delay(3000)]);if(host.exitCode===null){host.kill('SIGKILL');await once(host,'exit');}writeFileSync(join(root,'terminal.json'),JSON.stringify({...stats,state:'STOPPED',child_reaped:host.exitCode!==null||host.signalCode!==null}));}
process.on('SIGTERM',()=>stop().then(()=>process.exit(0)));const lifetime=setTimeout(()=>stop().then(()=>process.exit(2)),300000);
try{
 await until(async()=>{try{await connect();return true;}catch{return false;}},15000);
 const started=await rpc('thread/start',{cwd:work,approvalPolicy:'never',sandbox:'read-only'});const id=started.thread.id;
 await rpc('turn/start',{threadId:id,input:[{type:'text',text:'Return ISOLATED_HOST_OK. Do not use tools.'}]});await until(()=>completed>0,20000);stats.initial_completed=true;
 const before=await rpc('thread/read',{threadId:id,includeTurns:false});if(!before.thread.sessionId)throw Error('SESSION_ID_MISSING');
 await rpc('thread/unsubscribe',{threadId:id});
 await until(async()=>{const v=await rpc('thread/read',{threadId:id,includeTurns:false});return v.thread.status.type==='notLoaded';},90000);stats.unloaded=true;
 const adapter={kind:'codex',endpoint:`ws://127.0.0.1:${port}`,thread_id:id,expected_session_id:before.thread.sessionId};writeFileSync(join(root,'adapter.json'),JSON.stringify(adapter),{mode:0o600});
 control=http.createServer(async(req,res)=>{try{const state=await rpc('thread/read',{threadId:id,includeTurns:true});res.end(JSON.stringify({...stats,thread:state.thread}));}catch(e){res.writeHead(500).end(JSON.stringify({error:e.message}));}});control.listen(0,'127.0.0.1');await once(control,'listening');
 writeFileSync(join(root,'ready.json'),JSON.stringify({state:'READY_UNLOADED',control:`http://127.0.0.1:${control.address().port}`,adapter:join(root,'adapter.json'),official_version:'0.166.0',synthetic_model:true}));
}catch(e){writeFileSync(join(root,'failure.json'),JSON.stringify({error:e.message,hostLog}));await stop();clearTimeout(lifetime);process.exit(1);}
