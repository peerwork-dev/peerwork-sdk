// Opt-in anonymous catalog fixture using the exact pinned public Hono routes.
// Test-only direct seed keeps publishing/authorship outside this read test.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {readFileSync, statSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';

const root=process.env.PEERWORK_REFERENCE_ROOT;
const state=process.env.PEERWORK_TEST_STATE;
const sdk=process.env.PEERWORK_SDK_ROOT;
if(!root||!state||!sdk)throw new Error('reference, state, and SDK roots required');
const pinned='f828b6c50a0a58d1e718af90f653b214adcc3328';
if(execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==pinned)throw new Error('reference source pin changed');
try{execFileSync('git',['-C',root,'diff','--quiet','HEAD','--','src/workspace-catalog-http.ts','src/workspace-catalog.ts','src/protocol-package.ts']);}
catch{throw new Error('reference catalog source differs from pinned commit');}
for(const relative of ['src/workspace-catalog-http.ts','src/workspace-catalog.ts','src/protocol-package.ts']){
 const source=join(root,relative),built=join(root,'dist-workspace',relative.replace(/\.ts$/,'.js'));
 if(statSync(built).mtimeMs<statSync(source).mtimeMs)throw new Error(`stale reference build ${relative}`);
}
const requireReference=createRequire(join(root,'package.json'));
const {Hono}=await import(pathToFileURL(requireReference.resolve('hono')).href);
const {serve}=await import(pathToFileURL(requireReference.resolve('@hono/node-server')).href);
const {initializeProtocolCatalog,openProtocolCatalogReadOnly}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-catalog.js')).href);
const {mountPublicProtocolCatalog}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-catalog-http.js')).href);
const {canonicalProtocolPackageBytes,parseProtocolPackageBytes}=await import(pathToFileURL(join(root,'dist-workspace/src/protocol-package.js')).href);
const databasePath=join(state,'public-catalog.sqlite');
initializeProtocolCatalog(databasePath);
const db=new DatabaseSync(databasePath);
const fixtures=['public-package-vectors.json','public-package-v2-vectors.json'];
let sequence=0;
for(const filename of fixtures){
 const vector=JSON.parse(readFileSync(join(sdk,'conformance',filename),'utf8'));
 const bytes=canonicalProtocolPackageBytes(vector.bundle),parsed=parseProtocolPackageBytes(bytes);
 if(parsed.packageDigest!==vector.package_digest)throw new Error(`TS package digest changed: ${filename}`);
 const digest=createHash('sha256').update(bytes).digest('hex');
 if(digest!==vector.package_digest)throw new Error(`source vector hash changed: ${filename}`);
 const index=++sequence;
 db.prepare('INSERT INTO catalog_packages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
  `fixture-owner-${index}`,parsed.metadata.package_id,parsed.metadata.version,digest,
  vector.source_digest,vector.protocol_digest,JSON.stringify(parsed.source.imports.map(x=>x.package_digest)),
  Buffer.from(bytes),JSON.stringify(parsed.metadata),JSON.stringify({passed:true,inspection:{fileCount:Object.keys(parsed.bundle.files).length}}),
  'A'.repeat(43),Date.now(),index);
}
db.prepare('UPDATE catalog_meta SET watermark=? WHERE id=1').run(sequence);
db.close();
const catalog=openProtocolCatalogReadOnly(databasePath);
const app=new Hono();
mountPublicProtocolCatalog(app,catalog);
let packageGets=0,anonymousGets=0;
const server=serve({hostname:'127.0.0.1',port:0,fetch:async request=>{
 const url=new URL(request.url);
 if(url.pathname.startsWith('/api/protocol-catalog/v1/packages')){
  if(request.method!=='GET'||request.headers.has('authorization')||request.headers.has('cookie')||request.headers.has('x-peerwork-read'))return new Response('non-anonymous catalog request',{status:400});
  anonymousGets++;
 }
 const response=await app.fetch(request);
 if(url.pathname.includes('/by-digest/')&&response.status===200&&++packageGets===3){
  const bytes=Buffer.concat([Buffer.from(await response.arrayBuffer()),Buffer.from(' ')]);
  return new Response(bytes,{status:200,headers:{'content-type':'application/vnd.peerwork.protocol-package+json'}});
 }
 return response;
}});
await new Promise(resolve=>server.once('listening',resolve));
console.log(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`,bundles:sequence}));
process.on('SIGTERM',()=>{catalog.close();server.close();});
