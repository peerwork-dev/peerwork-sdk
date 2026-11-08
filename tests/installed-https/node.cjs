'use strict';const fs=require('node:fs'),crypto=require('node:crypto'),home=process.env.HOME,sdk=require(home+'/node_modules/@peerwork/agent-sdk'),x=JSON.parse(fs.readFileSync(home+'/input.json','utf8')),calls=[];
if(process.geteuid()!==65534)throw Error('UID');
async function call(name,origin,transport,query='t090'){const start=performance.now();let result;try{const value=await sdk.openPublicCatalog({origin,...(transport===undefined?{}:{transport})}).search(query);if(JSON.stringify(JSON.parse(value.listing_canonical_json))!==JSON.stringify({items:[],next:null,watermark:0}))throw Error('listing');result={ok:true,value};}catch(error){result={ok:false,code:error.code,message:error.message};}result={...result,name,seconds:(performance.now()-start)/1000,target:origin+'/api/protocol-catalog/v1/packages'};result.http_status=result.ok?200:null;calls.push(result);fs.writeFileSync(home+'/calls.json',JSON.stringify(calls,null,2),{mode:0o600});if(!result.ok&&result.code!=='CATALOG_TRANSPORT_FAILED')throw Error('unexpected catalog error');return result;}
void(async()=>{const ca={requestTimeoutMs:2000,additionalRootPemFiles:[x.ca]};
if((await call('default-untrusted',x.origin,undefined)).ok)throw Error('untrusted');
if(!(await call('explicit-CA',x.origin,ca)).ok)throw Error('CA');
if((await call('hostname-mismatch',x.origin.replace('localhost','127.0.0.1'),ca)).ok)throw Error('hostname');
if((await call('selected-timeout',x.origin,{...ca,requestTimeoutMs:100},'delay')).ok)throw Error('timeout');
if(!(await call('normal-recovery',x.origin,ca)).ok)throw Error('recovery');
const paths=[require.resolve(home+'/node_modules/@peerwork/agent-sdk'),Object.keys(require.cache).find(p=>p.endsWith('.node'))];
console.log(JSON.stringify({result:'PASS',interface:'node',uid:process.geteuid(),runtime:process.version,calls,loaded:paths.map(p=>({path:p,sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')}))}));})().catch(error=>{console.error(JSON.stringify({code:error.code??'HARNESS_ASSERTION',message:error.message,calls}));process.exitCode=1});
