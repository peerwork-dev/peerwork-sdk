// Reproducible offline conformance for public communication component packages.
import {mkdtemp, readFile, readdir, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=process.env.PEERWORK_TS_SOURCE??join(root,'reference/src');
const temporary=await mkdtemp(join(tmpdir(),'peerwork-communication-patterns-'));
try {
 const output=join(temporary,'compiler.mjs');
 await build({stdin:{contents:"export {parseProtocolPackage} from './protocol-package.ts'; export {compileProtocolPackage} from './protocol-compiler.ts'; export {createProtocolPackageClosure} from './protocol-package-closure.ts';",resolveDir:resolve(source)},outfile:output,bundle:true,platform:'node',format:'esm',logLevel:'silent'});
 const {parseProtocolPackage,compileProtocolPackage,createProtocolPackageClosure}=await import(pathToFileURL(output));
 async function directory(at,prefix='',files={}) {for(const entry of await readdir(at,{withFileTypes:true})){const name=prefix+entry.name;if(entry.isDirectory())await directory(join(at,entry.name),name+'/',files);else files[name]=await readFile(join(at,entry.name),'utf8');}return files;}
 const packages=new Map(),roots=[];
 async function add(path){const pkg=parseProtocolPackage({format:'peerwork.protocol-package.v1',files:await directory(path)});packages.set(pkg.packageDigest,pkg);return pkg;}
 for(const id of ['wiki-draft-component','wiki-review-component'])await add(join(root,'public-fixtures',id));
 const fixtureRoot=join(root,'public-fixtures/communication');
 for(const entry of (await readdir(fixtureRoot,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:1))if(entry.isDirectory())roots.push(await add(join(fixtureRoot,entry.name)));
 const vectors=[];
 for(const pkg of roots){
  const compiled=compileProtocolPackage(pkg,{loadExactPackage:digest=>packages.get(digest)});
  if(!compiled.validation.passed||!compiled.passed)throw new Error(pkg.metadata.package_id+': '+JSON.stringify(compiled.fixtureResults));
  const dependencies=new Map();
  const visit=at=>{for(const item of at.source.imports){const child=packages.get(item.package_digest);if(!child)throw new Error('missing exact dependency');if(!dependencies.has(child.packageDigest)){dependencies.set(child.packageDigest,child);visit(child);}}};visit(pkg);
  vectors.push({name:pkg.metadata.package_id,closure:createProtocolPackageClosure(pkg,[...dependencies.values()]),compiled_manifest:compiled.manifest,protocol_digest:compiled.protocolDigest,source_digest:compiled.sourceDigest,compilation_lock:compiled.lock,interfaces_complete:compiled.interfacesComplete,fixture_count:compiled.fixtureResults.length});
 }
 await writeFile(join(root,'communication-pattern-vectors.json'),JSON.stringify(vectors,null,2)+'\n');
 process.stdout.write(`Wrote ${vectors.length} communication pattern vectors\n`);
} finally {await rm(temporary,{recursive:true,force:true});}
