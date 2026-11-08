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
const selectedSeed=process.env.PEERWORK_TEST_CATALOG_BINDING_PACKAGE==='1';
if(!root||!state||!sdk)throw new Error('reference, state, and SDK roots required');
const pinned='f828b6c50a0a58d1e718af90f653b214adcc3328';
if(execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim()!==pinned)throw new Error('reference source pin changed');
const guardedSources=['src/workspace-catalog-http.ts','src/workspace-catalog.ts','src/protocol-package.ts',...(selectedSeed?['src/protocol-compiler.ts']:[])];
try{execFileSync('git',['-C',root,'diff','--quiet','HEAD','--',...guardedSources]);}
catch{throw new Error('reference catalog source differs from pinned commit');}
for(const relative of guardedSources){
 const source=join(root,relative),built=join(root,'dist-workspace',relative.replace(/\.ts$/,'.js'));
 if(statSync(built).mtimeMs<statSync(source).mtimeMs)throw new Error(`stale reference build ${relative}`);
}
for(const [relative,expected] of Object.entries({
 'workspace-catalog-http.js':'e244fc3ab9922dd9fda2127bc4cfa6416633a56d80c93206c63191f7def1b890',
 'workspace-catalog.js':'6cab714a6783cd43fa159b59447bec80e4539bc54e52c3cc5bece1079e205865',
 'protocol-package.js':'c864257535bd3f63128d4c943356fa36f84381244ca980531727abee3b60466a',
 ...(selectedSeed?{'protocol-compiler.js':'918f83ce69f8fa7cc5bb21d715079a619c3459a38b6e1c11120808c9b32eb498'}:{}),
 })){
 const actual=createHash('sha256').update(readFileSync(join(root,'dist-workspace/src',relative))).digest('hex');
 if(actual!==expected)throw new Error(`compiled catalog source changed: ${relative}`);
}
const requireReference=createRequire(join(root,'package.json'));
const {Hono}=await import(pathToFileURL(requireReference.resolve('hono')).href);
const {serve}=await import(pathToFileURL(requireReference.resolve('@hono/node-server')).href);
const {initializeProtocolCatalog,openProtocolCatalogReadOnly}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-catalog.js')).href);
const {mountPublicProtocolCatalog}=await import(pathToFileURL(join(root,'dist-workspace/src/workspace-catalog-http.js')).href);
const {canonicalProtocolPackageBytes,parseProtocolPackageBytes}=await import(pathToFileURL(join(root,'dist-workspace/src/protocol-package.js')).href);
const compileProtocolPackage=selectedSeed?(await import(pathToFileURL(join(root,'dist-workspace/src/protocol-compiler.js')).href)).compileProtocolPackage:undefined;
const databasePath=join(state,'public-catalog.sqlite');
initializeProtocolCatalog(databasePath);
const db=new DatabaseSync(databasePath);
const fixtures=['public-package-vectors.json','public-package-v2-vectors.json'];
let sequence=0;
const artifacts=new Map();
if(selectedSeed)fixtures.push('private-package-options-reference.json');
for(const filename of fixtures){
 const vector=JSON.parse(readFileSync(join(sdk,'conformance',filename),'utf8'));
 const selected=filename==='private-package-options-reference.json';
 const expectedDigest=selected?vector.binding.root_package_digest:vector.package_digest;
 const selectedBytes=selected?Buffer.from(vector.binding.closure.packages[expectedDigest],'base64url'):undefined;
 const bytes=selected?selectedBytes:canonicalProtocolPackageBytes(vector.bundle),parsed=parseProtocolPackageBytes(bytes);
 if(parsed.packageDigest!==expectedDigest)throw new Error(`TS package digest changed: ${filename}`);
 const digest=createHash('sha256').update(bytes).digest('hex');
 if(digest!==expectedDigest)throw new Error(`source vector hash changed: ${filename}`);
 if(selected&&(parsed.source.imports.length!==0||Object.keys(vector.binding.closure.packages).length!==1))throw new Error('selected package is not single-root');
 const compiled=selected?compileProtocolPackage(parsed,{bindings:parsed.lock.baseline_bindings}):undefined;
 if(selected&&compiled.protocolDigest!==vector.binding.default_protocol_digest)throw new Error('selected package baseline differs from pinned reference');
 artifacts.set(digest,Buffer.from(bytes));
 const index=++sequence;
 db.prepare('INSERT INTO catalog_packages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
  `fixture-owner-${index}`,parsed.metadata.package_id,parsed.metadata.version,digest,
  selected?compiled.sourceDigest:vector.source_digest,selected?compiled.protocolDigest:vector.protocol_digest,JSON.stringify(parsed.source.imports.map(x=>x.package_digest)),
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
 if(!selectedSeed&&url.pathname.includes('/by-digest/')&&response.status===200&&++packageGets===3){
  const bytes=Buffer.concat([Buffer.from(await response.arrayBuffer()),Buffer.from(' ')]);
  return new Response(bytes,{status:200,headers:{'content-type':'application/vnd.peerwork.protocol-package+json'}});
 }
 if(!selectedSeed&&url.pathname.includes('/by-digest/')&&response.status===200&&packageGets===4){
  const selected=url.pathname.split('/').at(-1),other=[...artifacts.entries()].find(([digest])=>digest!==selected)?.[1];
  if(!other)throw new Error('missing alternate canonical package');
  return new Response(other,{status:200,headers:{'content-type':'application/vnd.peerwork.protocol-package+json'}});
 }
 return response;
}});
await new Promise(resolve=>server.once('listening',resolve));
console.log(JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`,bundles:sequence}));
process.on('SIGTERM',()=>{catalog.close();server.close();});
