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

const minimum=[];for(const original of source.commits.slice(1)){const input=original.payload.body.input.body.message;assert.equal(input.length,8007);let occurrences=0;const visit=x=>{if(typeof x==='string'&&x===input){occurrences++;return '';}if(Array.isArray(x))return x.map(visit);if(x&&typeof x==='object')return Object.fromEntries(Object.entries(x).map(([k,v])=>[k,visit(v)]));return x;};const model=visit(original);assert.equal(occurrences,2);assert.equal(len(original)-len(model),16014);const object={kind:'secure_commits',id:String(original.payload.sequence),revision:1,provenance:'AUTHOR_SIGNED',value:model};minimum.push({source_commit_bytes:len(model),one_item_private_bytes:oneBytes(object),removed_message_bytes:16014,occurrences});}
const responseBytes=small.projection.per_record_source_reservation-256-Math.max(...small.source_commit_wire_bytes.slice(1));assert.equal(responseBytes,687);const sourceFloor=Math.min(...minimum.map(x=>x.source_commit_bytes))+responseBytes,base=small.source_stored_bytes-2*(18170+responseBytes),maximumActions=Math.floor((33554432-base)/sourceFloor),perStage=Math.max(...minimum.map(x=>x.one_item_private_bytes));
const value={classification:'OFFLINE LENGTH MODEL ONLY; altered contents are neither signed nor saved as history',old_message_bytes:8007,minimum_message_bytes:0,actual_minimum_api_executed:false,minimum_models:minimum,response_storage_bytes:responseBytes,source_base_bytes:base,minimum_source_per_action:sourceFloor,optimistic_max_actions:maximumActions,minimum_source_total:base+maximumActions*sourceFloor,one_item_stage_bytes:perStage,stage_numeric_width_reservation:512,final_collection_projection:bootstrap+maximumActions*(perStage+512)+policyAndFinish,threshold:67108864,crosses64MiB:false,conclusion:'Even the optimistic action count plus 512 extra wire bytes per stage projects below64MiB for this fixed-shape discussion writer. No new fixture justified; no universal producer bound or native/large pass.'};assert.ok(value.final_collection_projection<value.threshold);writeFileSync(join(process.argv[3],'minimum-projection.json'),JSON.stringify(value,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(value));
