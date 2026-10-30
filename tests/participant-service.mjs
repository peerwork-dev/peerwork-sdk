// Synthetic real-HTTP participant acceptance fixture. Only test identities and
// an isolated PostgreSQL schema are used; no user profile is opened.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {once} from 'node:events';

const root=process.env.PEERWORK_STRUCTURE_REFERENCE_ROOT;
if(!root||!process.env.PEERWORK_POSTGRES_TEST_URL)throw Error('explicit product root and synthetic PostgreSQL required');
const require=createRequire(join(root,'package.json'));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server')));
const {postgresFixture}=await import(pathToFileURL(join(root,'dist-workspace/tests/fixtures/workspace-postgres-fixture.js')));
const {createPostgresControlApp}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-postgres-http.js')));
const f=await postgresFixture();f.clock.now=Date.now();
let reportQuotaBlocked=false;const reportQuotaLimits=new Map();
let clockOffset=0;const ticker=setInterval(()=>{f.clock.now=Date.now()+clockOffset;},10);
const app=createPostgresControlApp(f.kernel,{source:()=> '127.0.0.1'});
let offline=false,dropAction=null,delayName=null,delayAction=null,release=null,streamDurationOnce=0;
const counts={commands:0,discovery:0,context:0,journal_reads:0,dropped:0,native_streams:0,delayed:0,claim_commands:[],actions:{}};
const commandIds=new Set();
const server=serve({hostname:'127.0.0.1',port:0,fetch:async request=>{
 const path=new URL(request.url).pathname;
 if(path==='/__test/config'){
  const options=await request.json();
  if(options.offline!==undefined)offline=options.offline;
  if(options.report_quota_blocked!==undefined){
   reportQuotaBlocked=options.report_quota_blocked;
   if(!reportQuotaBlocked){for(const [workspace,limit]of reportQuotaLimits)await f.store.pool.query(`UPDATE "${f.schema}".workspace_capacity SET byte_limit=$2 WHERE workspace_id=$1`,[workspace,limit]);reportQuotaLimits.clear();}
  }
  if(options.fence_mailbox!==undefined)await f.store.pool.query(`UPDATE "${f.schema}".communication_mailboxes SET epoch=epoch+1,lease_until=0,ready=false WHERE mailbox_id=$1`,[options.fence_mailbox]);
  if(options.clock_offset_ms!==undefined){clockOffset=options.clock_offset_ms;f.clock.now=Date.now()+clockOffset;}
  if(options.drop_action!==undefined)dropAction=options.drop_action;
  if(options.delay_name!==undefined)delayName=options.delay_name;
  if(options.delay_action!==undefined)delayAction=options.delay_action;
  if(options.stream_duration_once_ms!==undefined)streamDurationOnce=options.stream_duration_once_ms;
  if(options.close_connections)setTimeout(()=>server.closeAllConnections(),10);
  if(options.release){release?.();release=null;delayName=null;}
  return Response.json({ok:true});
 }
 if(path==='/__test/counts')return Response.json({...counts,unique_commands:commandIds.size,
  workspaces:Number((await f.store.pool.query(`SELECT count(*) n FROM "${f.schema}".workspaces`)).rows[0].n),
  key_epochs:Number((await f.store.pool.query(`SELECT count(*) n FROM "${f.schema}".structure_content_key_epochs`)).rows[0].n),
  events:Number((await f.store.pool.query(`SELECT count(*) n FROM "${f.schema}".events`)).rows[0].n),
  records:Number((await f.store.pool.query(`SELECT count(*) n FROM "${f.schema}".records`)).rows[0].n)});
 if(path.endsWith('/discovery'))counts.discovery++;
 if(path.endsWith('/context'))counts.context++;
 if(path.endsWith('/journal'))counts.journal_reads++;
 if(offline)return new Response('synthetic disconnected link',{status:503});
 let command=null;
 if(path==='/api/workspace/v1/commands'&&request.method==='POST'){
  const envelope=await request.clone().json();
  command=JSON.parse(Buffer.from(envelope.jws.split('.')[1],'base64url').toString('utf8'));
  counts.commands++;commandIds.add(command.command_id);
  counts.actions[command.action_id]=(counts.actions[command.action_id]??0)+1;
  if(command.action_id==='structure.mailbox.claim')counts.claim_commands.push({command_id:command.command_id,receiver_id:command.body.receiver_id,replace:command.body.replace,expected_epoch:command.body.expected_epoch});
  if(delayAction===command.action_id){delayAction=null;counts.delayed++;await new Promise(resolve=>{release=resolve;});}
  if(reportQuotaBlocked&&command.action_id==='structure.mailbox.report'){
   const workspace=command.workspace_id;
   if(!reportQuotaLimits.has(workspace)){
    const row=(await f.store.pool.query(`SELECT byte_limit FROM "${f.schema}".workspace_capacity WHERE workspace_id=$1`,[workspace])).rows[0];reportQuotaLimits.set(workspace,row.byte_limit);
   }
   await f.store.pool.query(`UPDATE "${f.schema}".workspace_capacity SET byte_limit=used_bytes+1048576 WHERE workspace_id=$1`,[workspace]);
  }
  if(delayName&&command.body?.name===delayName)await new Promise(resolve=>{release=resolve;});
 }
 const response=await app.fetch(request);
 if(path==='/api/workspace/v1/structure/communication/stream'&&response.ok){
  counts.native_streams++;
  if(streamDurationOnce){
   const duration=streamDurationOnce;streamDurationOnce=0;const reader=response.body.getReader();let closed=false,timer;
   return new Response(new ReadableStream({start(controller){
    const close=()=>{if(closed)return;closed=true;clearTimeout(timer);void reader.cancel().catch(()=>{});try{controller.close();}catch{}};
    timer=setTimeout(close,duration);void(async()=>{try{for(;;){const r=await reader.read();if(closed)return;if(r.done){close();return;}controller.enqueue(r.value);}}catch{close();}})();
   },cancel(){closed=true;clearTimeout(timer);return reader.cancel().catch(()=>{});}}),{status:response.status,headers:response.headers});
  }
 }
 if(command?.action_id===dropAction&&response.status===200){
  const result=await response.clone().json();
  if(result.result?.workspace_id&&!result.result.error){dropAction=null;offline=true;counts.dropped++;return new Response('synthetic lost committed response',{status:503});}
 }
 return response;
}});
await once(server,'listening');
process.stdout.write(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`})+'\n');
process.once('SIGTERM',async()=>{
 clearInterval(ticker);release?.();server.closeAllConnections();
 await new Promise(resolve=>server.close(resolve));await f.close();process.exit(0);
});
