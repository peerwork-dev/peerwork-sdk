// Candidate-only native SDK interoperability fixture. This is distinct from
// the immutable historical reference server and never opens a user profile.
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
import {join,relative} from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

const root=process.env.PEERWORK_STRUCTURE_REFERENCE_ROOT;
const state=process.env.PEERWORK_TEST_STATE;
const manifestPath=process.env.PEERWORK_STRUCTURE_REFERENCE_MANIFEST;
if(!root||!state||!manifestPath)throw new Error('candidate root, fresh state and frozen manifest required');
const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
if(manifest.format!=='peerwork.structure-candidate.v1')throw new Error('unsupported candidate manifest');
function files(directory){return readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
 const path=join(directory,entry.name);
 if(entry.isDirectory())return files(path);
 if(!entry.isFile())throw new Error('candidate source must contain ordinary files');
 return [relative(root,path)];
}).sort();}
const expectedFiles=[...files(join(root,'src')),...files(join(root,'dist-workspace/src')),'package.json','package-lock.json'].sort();
if(JSON.stringify(Object.keys(manifest.files).sort())!==JSON.stringify(expectedFiles))throw new Error('candidate closure differs from frozen manifest');
for(const name of expectedFiles){
 const actual=createHash('sha256').update(readFileSync(join(root,name))).digest('hex');
 if(actual!==manifest.files[name])throw new Error(`candidate source changed: ${name}`);
}
const require=createRequire(join(root,'package.json'));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server')).href);
const {PostgresStore}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-postgres-store.js')).href);
const {PostgresKernel}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-postgres-kernel.js')).href);
const {createPostgresControlApp}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-postgres-http.js')).href);
const {stepPgMaintenance}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-postgres-maintenance.js')).href);
const connectionString=process.env.PEERWORK_POSTGRES_TEST_URL;
if(!connectionString)throw new Error('synthetic PostgreSQL test connection required');
const schema='native_'+createHash('sha256').update(state).digest('hex').slice(0,24);
const store=new PostgresStore({connectionString,schema,max:8});
let dropped=0,journalReads=0,maintenanceDropped=0;
const maintenanceDropLimit=Number(process.env.PEERWORK_STRUCTURE_TEST_MAINTENANCE_DROPS??0);
const dropLimit=Number(process.env.PEERWORK_STRUCTURE_TEST_DROPS??1);
let testClock=process.env.PEERWORK_STRUCTURE_TEST_CLOCK===undefined?null:Number(process.env.PEERWORK_STRUCTURE_TEST_CLOCK);
const kernel=new PostgresKernel(store,'structure-candidate',Buffer.alloc(32,71),()=>testClock??Date.now(),{afterCommit(response){
 if(maintenanceDropped<maintenanceDropLimit&&response.result?.status==='ORDERED'&&response.result?.maintenance){maintenanceDropped++;throw new Error('synthetic maintenance admission reply loss');}
 if(dropped<dropLimit&&response.result?.profile==='backend-structure-v1'&&response.result?.status==='APPLIED'){
  dropped++;throw new Error('synthetic committed reply loss');
 }
}});
await kernel.initialize();
const app=createPostgresControlApp(kernel);
const count=async(table)=>Number((await store.pool.query(`SELECT count(*)::integer AS n FROM "${schema}"."${table}"`)).rows[0].n);
const server=serve({hostname:'127.0.0.1',port:0,fetch:async(request,env)=>{
 const path=new URL(request.url).pathname;if(path.endsWith('/journal'))journalReads++;
 if(path==='/__test/advance-clock'&&testClock!==null){testClock+=700_000;return Response.json({advanced:true});}
 if(path==='/__test/counts')return Response.json({records:await count('records'),dropped,journal_reads:journalReads});
 if(path==='/__test/collaboration-counts')return Response.json({workspaces:await count('workspaces'),identities:await count('identity_roots'),grant_heads:await count('structure_grant_heads'),current_records:await count('structure_current_records')});
 if(path==='/__test/maintenance-counts')return Response.json({jobs:await count('maintenance_jobs'),maintenance_dropped:maintenanceDropped,journal_reads:journalReads});
 return app.fetch(request,env);
}});
await new Promise(resolve=>server.once('listening',resolve));
process.stdout.write(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}/`})+'\n');
let stepping=false;
const maintenanceTimer=setInterval(()=>{if(stepping)return;stepping=true;stepPgMaintenance(kernel).catch(()=>{}).finally(()=>{stepping=false;});},100);
process.on('SIGTERM',()=>{clearInterval(maintenanceTimer);server.close(async()=>{await store.pool.query(`DROP SCHEMA "${schema}" CASCADE`);await store.close();process.exit(0);});});
