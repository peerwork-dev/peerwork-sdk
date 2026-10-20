// Load only an installed Node package selected by the acceptance harness.
import {createRequire} from 'node:module';
import {readFileSync,renameSync} from 'node:fs';
import {dirname,basename} from 'node:path';
import assert from 'node:assert/strict';
const [packageRoot,configPath,inputPath,removeSource,checkCoordination]=process.argv.slice(2);
const require=createRequire(packageRoot+'/package.json');
const sdk=require('@peerwork/agent-sdk');
const config=JSON.parse(readFileSync(configPath)),input=JSON.parse(readFileSync(inputPath));
const options={origin:config.origin,stateDir:config.state_dir,allowLoopbackHttp:config.allow_loopback_http};
const source=Object.fromEntries(Object.entries(input).map(([k,v])=>[k.replace(/_([a-z])/g,(_,c)=>c.toUpperCase()),v]));
const owner=sdk.openSecureOwnerWorkspaces(options);
let attached;
try{attached=await owner.attach(source);}
catch(error){assert.deepEqual(await owner.attachments(),[]);console.log(JSON.stringify({code:error.code,attachments:0}));}
if(attached){
 assert.equal(attached.status,'ATTACHED');
 if(removeSource==='--remove-synthetic-source'){
  const directory=dirname(input.protected_ts_state_path);assert(basename(directory).startsWith('facade-'));
  renameSync(directory,directory+'-removed');
 }
 const reopened=sdk.openSecureOwnerWorkspaces(options);
 assert.equal((await reopened.resumeAttachment(attached.attach_id)).status,'ATTACHED');
 const read=await reopened.read(input.workspace_id);
 const result={status:attached.status,workspace_id:read.workspace_id,sequence:read.sequence,head:read.head};
 if(checkCoordination==='--check-coordination'){
  assert.equal(attached.coordination_intents.filter(m=>m.status==='ARCHIVED_COMPLETED').length,4);
  const pending=attached.coordination_intents.filter(m=>m.status==='RETAINED_UNRESOLVED');assert.equal(pending.length,1);
  const marker=pending[0],cancel=new AbortController();cancel.abort();
  await assert.rejects(reopened.retireCoordinationIntent(attached.attach_id,marker.marker_key,marker.input_hash,{signal:cancel.signal}),e=>e.code==='CANCELLED');
  await assert.rejects(reopened.retireCoordinationIntent(attached.attach_id,marker.marker_key,'0'.repeat(64)),e=>e.code==='ATTACH_CONFLICT');
  await reopened.retireCoordinationIntent(attached.attach_id,marker.marker_key,marker.input_hash);
  const final=await sdk.openSecureOwnerWorkspaces(options).retireCoordinationIntent(attached.attach_id,marker.marker_key,marker.input_hash);
  assert.equal(final.coordination_intents.filter(m=>m.status==='RETIRED_LOCAL').length,1);
  result.coordination={archived:4,retired:1,wrong_hash_refused:true,preabort:true};
 }
 console.log(JSON.stringify(result));
}
