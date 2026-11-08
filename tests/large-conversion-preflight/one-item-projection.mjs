// OFFLINE byte arithmetic on retained genuine artifacts. No new signatures or history.
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
const out=process.argv[2],load=n=>JSON.parse(readFileSync(join(out,n),'utf8'));
const canonical=x=>JSON.stringify(x&&typeof x==='object'?Array.isArray(x)?x.map(v=>JSON.parse(canonical(v))):Object.fromEntries(Object.keys(x).sort().map(k=>[k,JSON.parse(canonical(x[k]))])):x),len=x=>Buffer.byteLength(canonical(x));
const source=load('source-public-snapshot.json'),converted=load('converted-signed-snapshot.json'),small=load('result.json');
const stage=converted.commits.find(c=>c.payload.action_id==='secure.convert.stage');
const objects=[];
for(const c of source.commits){const raw=Buffer.from(canonical(c)),descriptor={kind:'secure_commits',id:String(c.payload.sequence),revision:1};if(raw.length<=49152)objects.push({...descriptor,value:c});else{const digest=createHash('sha256').update(canonical(descriptor)).digest('hex'),count=Math.ceil(raw.length/16384);for(let i=0;i<count;i++)objects.push({kind:'secure_fragment',id:digest+'-'+i,revision:1,value:{fragment:{...descriptor,index:i,count,provenance:'AUTHOR_SIGNED'},data:raw.subarray(i*16384,(i+1)*16384).toString('base64url')}});}}
objects.sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id)||a.revision-b.revision);
for(const object of objects)object.provenance='AUTHOR_SIGNED';
const plaintext=items=>len({v:1,kind:'MIGRATE',input:{},objects:items});
assert.equal(plaintext(objects),small.migrate_plain_bytes);
const sealedBytes=n=>{const cipher=n+16,chunks=Math.ceil(cipher/6144);let encoded=0;for(let i=0;i<chunks;i++)encoded+=Math.ceil(Math.min(6144,cipher-i*6144)*4/3);return len({v:1,alg:'A256GCM',nonce:'0'.repeat(16),chunks:[]})+encoded+chunks*2+Math.max(0,chunks-1);};
assert.equal(sealedBytes(plaintext(objects)),len(stage.payload.body));
const descriptor=o=>({kind:o.kind,id:o.id,revision:o.revision});
const header=len(stage)-len(stage.payload.body)-len(stage.payload.migration.source_items);
const oneBytes=o=>header+len([descriptor(o)])+sealedBytes(plaintext([o]));
const actualSingleItemBytes=objects.map(oneBytes),bootstrap=objects.filter(o=>o.kind==='secure_fragment').reduce((n,o)=>n+oneBytes(o),0),action=objects.filter(o=>o.kind==='secure_commits').map(oneBytes);
// Same tested writer pattern only, conservative reservation for changed numeric widths.
const proposedActions=small.projection.proposed_actions,perAction=Math.max(...action)+512;
const policyAndFinish=small.canonical_policy_bytes.reduce((a,b)=>a+b,0)+small.finish_wire_bytes;
const projection=bootstrap+proposedActions*perAction+policyAndFinish;
const result={classification:'OFFLINE LENGTH PROJECTION; not newly signed, accepted, or a universal bound',one_item_protocol_valid:true,empty_item_protocol_valid:false,planner_64_is_mandatory:false,retained_small_plaintext_bytes:plaintext(objects),retained_small_ciphertext_wire_bytes:sealedBytes(plaintext(objects)),retained_source_objects:objects.length,one_item_stage_wire_lengths:actualSingleItemBytes,one_item_small_collection_bytes:actualSingleItemBytes.reduce((a,b)=>a+b,0)+policyAndFinish,projected_actions:proposedActions,projected_source_reservation:small.projection.projected_source_stored_bytes,per_action_wire_reservation:perAction,projected_one_item_collection_bytes:projection,exceeds_64MiB:projection>64*1024*1024,conclusion:'This genuine writer pattern does not provide a >64MiB witness even with one source object per stage. Other legal producers are unproven; no impossibility claim.'};
writeFileSync(join(out,'one-item-projection.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(result));
