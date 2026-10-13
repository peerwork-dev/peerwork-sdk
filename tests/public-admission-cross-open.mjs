// Native-authored PUBLIC offer/consent checked by the pinned TypeScript oracle.
// Synthetic signatures/certificates only; no private material is exported.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const root=resolve(import.meta.dirname,'..');
const {build}=await import(pathToFileURL(join(root,'conformance/node_modules/esbuild/lib/main.js')).href);
const directory=await mkdtemp(join(tmpdir(),'peerwork-public-admission-'));
try{
 const clientOutput=join(directory,'secure-client.mjs');
 await build({entryPoints:[join(root,'conformance/reference/src/workspace-secure-client.ts')],
  outfile:clientOutput,bundle:true,platform:'node',format:'esm',
  nodePaths:[join(root,'conformance/node_modules')],logLevel:'silent'});
 const client=await import(pathToFileURL(clientOutput).href);
 const output=join(directory,'vector.json');
 const cargo=process.env.CARGO_BIN??'cargo';
 const run=spawnSync(cargo,['test','-p','peerwork-core','--lib','prepared_public_admission',
  '--offline','--locked'],{cwd:root,encoding:'utf8',env:{...process.env,PEERWORK_ADMISSION_VECTOR:output}});
 if(run.status!==0)throw Error(`focused native admission test failed\n${run.stdout}\n${run.stderr}`);
 const v=JSON.parse(await readFile(output,'utf8'));
 await client.verifyInvitation(v.offer,{actorId:v.owner_actor,key:v.owner_key},v.now);
 await client.verifySecure(v.decision,'peerwork.secure.invite-decision.v1',v.recipient_key);
 assert.equal(v.decision.payload.offer_hash,await client.secureHash(v.offer));
 assert.equal(v.decision.payload.actor_id,v.recipient_actor);
 assert.equal(v.decision.payload.decision,'ACCEPT');
 const altered=structuredClone(v.offer);
 altered.payload.policy_hash='a'.repeat(64);
 await assert.rejects(client.verifyInvitation(altered,{actorId:v.owner_actor,key:v.owner_key},v.now));
 const wrong=structuredClone(v.decision);
 wrong.payload.offer_hash='b'.repeat(64);
 await assert.rejects(client.verifySecure(wrong,'peerwork.secure.invite-decision.v1',v.recipient_key));
 console.log('native PUBLIC offer and consent verify under pinned TypeScript; signed tampering refused');
}finally{await rm(directory,{recursive:true,force:true});}
