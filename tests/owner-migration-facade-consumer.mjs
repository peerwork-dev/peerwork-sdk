// Load only an installed Node package selected by the acceptance harness.
import {createRequire} from 'node:module';
import {readFileSync,renameSync} from 'node:fs';
import {dirname,basename} from 'node:path';
import assert from 'node:assert/strict';
const [packageRoot,configPath,inputPath,removeSource]=process.argv.slice(2);
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
 console.log(JSON.stringify({status:attached.status,workspace_id:read.workspace_id,sequence:read.sequence,head:read.head}));
}
