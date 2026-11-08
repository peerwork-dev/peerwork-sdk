// Actual archived-space HTTP + staging worker, using synthetic fixture data.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {once} from 'node:events';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
const root=process.env.PEERWORK_STRUCTURE_REFERENCE_ROOT;
if(!root||!process.env.PEERWORK_POSTGRES_TEST_URL)throw Error('explicit synthetic fixture configuration required');
process.chdir(root);
const require=createRequire(join(root,'package.json'));
const load=p=>import(pathToFileURL(join(root,'dist-workspace',p)));
const {serve}=await import(pathToFileURL(require.resolve('@hono/node-server')));
const {migrationFixture}=await load('tests/fixtures/workspace-self-service-migration-fixture.js');
const {activateOwnerCheckpoints}=await load('src/workspace-postgres-owner-checkpoint.js');
const {initializeArchiveMigration,stepArchiveMigration}=await load('src/workspace-archive-migration.js');
const {PostgresStore}=await load('src/workspace-postgres-store.js');
const {PostgresKernel}=await load('src/workspace-postgres-kernel.js');
const {createPostgresControlApp}=await load('src/workspace-postgres-http.js');
const f=await migrationFixture(17);
await activateOwnerCheckpoints(f.kernel,f.old.snapshotSha,{productionManifest:{schema:'peerwork.production-activation.v1',snapshot_sha256:f.old.snapshotSha,workspaces:[{workspace_id:f.old.workspace,disposition:'ARCHIVED_UNAVAILABLE'}]}});
await initializeArchiveMigration(f.kernel);f.kernel.archiveMigrationEnabled=true;
const prepared=f.bundle(),identity=join(f.directory,'native-identity');
writeFileSync(identity,'PEERWORK-NATIVE-SECURE-STATE\n1\n'+JSON.stringify({kind:'peerwork.native-identity.v1',seed:f.old.privateKey.export({format:'jwk'}).d}),{mode:0o600});
const stageName=f.store.schema.slice(1,-1)+'_mstage';
const stageStore=new PostgresStore({connectionString:process.env.PEERWORK_POSTGRES_TEST_URL,schema:stageName,max:2});
const stage=new PostgresKernel(stageStore,'checkpoint-test',Buffer.alloc(32,7),()=>f.clock.now);
const work=mkdtempSync(join(tmpdir(),'participant-migration-worker-'));
const ticker=setInterval(()=>{f.clock.now=Date.now();},10);
let stop=false,paused=true,offline=false,drop=false;
const counts={commands:0,dropped:0};
const worker=(async()=>{while(!stop){if(!paused)await stepArchiveMigration(f.kernel,stage,work);await new Promise(r=>setTimeout(r,20));}})();
const app=createPostgresControlApp(f.kernel,{source:()=> '127.0.0.1'});
const server=serve({hostname:'127.0.0.1',port:0,fetch:async request=>{
 const path=new URL(request.url).pathname;
 if(path==='/__test/config'){
  const v=await request.json();if(v.paused!==undefined)paused=v.paused;if(v.offline!==undefined)offline=v.offline;if(v.drop_admission!==undefined)drop=v.drop_admission;
  if(v.remove_checkpoint)rmSync(prepared.file);
  return Response.json({ok:true});
 }
 if(path==='/__test/counts')return Response.json({...counts,jobs:Number((await f.store.pool.query(`SELECT count(*) n FROM ${f.store.schema}.archive_migration_jobs WHERE kind='IMPORT'`)).rows[0].n)});
 if(offline)return new Response('synthetic disconnected link',{status:503});
 let command=null;if(path==='/api/workspace/v1/commands'){command=JSON.parse(Buffer.from((await request.clone().json()).jws.split('.')[1],'base64url').toString());counts.commands++;}
 const response=await app.fetch(request);
 if(drop&&command?.action_id==='structure.migration.open'&&response.ok){drop=false;offline=true;counts.dropped++;return new Response('synthetic lost migration admission',{status:503});}
 return response;
}});
await once(server,'listening');
process.stdout.write(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`,workspace_id:f.old.workspace,instance_id:f.old.instance,protocol_digest:prepared.protocol,actor_id:f.old.actor,authority:f.old.authority,identity_path:identity,checkpoint_path:prepared.file,checkpoint_sha256:createHash('sha256').update(readFileSync(prepared.file)).digest('hex')})+'\n');
process.once('SIGTERM',async()=>{
 stop=true;await worker;clearInterval(ticker);server.closeAllConnections();await new Promise(r=>server.close(r));await stageStore.close();
 await f.store.pool.query(`DROP SCHEMA IF EXISTS "${stageName}_archive" CASCADE;DROP SCHEMA IF EXISTS "${stageName}" CASCADE`);
 rmSync(work,{recursive:true,force:true});await f.close();process.exit(0);
});
