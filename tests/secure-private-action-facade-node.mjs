// Public facade boundary: member profiles remain explicit; retry forwards saved ID only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
const realRequire=createRequire(import.meta.url), calls=[];
class KernelCancelHandle {cancel(){this.cancelled=true;}}
const native={KernelCancelHandle,securePrivateActionJson:async(...args)=>{calls.push(args);return JSON.stringify({ok:true,value:args[0]==='pending'?[]:{status:'PENDING',command_id:'c'.repeat(43),receipt_canonical_json:null}});},securePublicActionJson:()=>{throw new Error('PUBLIC_FALLBACK');}};
const require=name=>name==='/stub/native'?native:realRequire(name);require.resolve=()=>'/stub/native';
const sdk={};new Function('require','exports','process',readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'))(require,sdk,process);
const profile={origin:'https://control.example',stateDir:'/protected/alice/workspace',identityPath:'/protected/alice/identity.state',workspaceId:'w'.repeat(43)};
const client=sdk.openSecurePrivateActions(profile), operationId='o'.repeat(43);
const result=await client.submit('task.create','i'.repeat(43),{title:'member'},{operationId});
assert.equal(result.status,'PENDING');assert.equal(result.receipt,null);
assert.equal(calls[0][4],operationId);assert.equal(JSON.parse(calls[0][1]).identity_path,profile.identityPath);
assert.equal(JSON.parse(calls[0][2]).action_id,'task.create');
await client.reconcile('c'.repeat(43));await client.retrySaved('c'.repeat(43));await client.pending();
assert.deepEqual(calls.slice(1).map(x=>[x[0],x[2],x[3]]),[['reconcile',undefined,'c'.repeat(43)],['retry',undefined,'c'.repeat(43)],['pending',undefined,undefined]]);
const second=sdk.openSecurePrivateActions({...profile,stateDir:'/protected/bob/workspace',identityPath:'/protected/bob/identity.state'});await second.pending();assert.equal(JSON.parse(calls.at(-1)[1]).identity_path,'/protected/bob/identity.state');
await client.pending();assert.equal(JSON.parse(calls.at(-1)[1]).identity_path,profile.identityPath);
const abort=new AbortController();abort.abort();await client.submit('task.create','i'.repeat(43),{},{operationId,signal:abort.signal});assert.equal(calls.at(-1)[5].cancelled,true);
const before=calls.length;assert.throws(()=>client.submit('task.create','i'.repeat(43),{},{operationId:'bad'}),TypeError);assert.equal(calls.length,before);
assert.throws(()=>sdk.openSecurePrivateActions({...profile,identityPath:''}),TypeError);
console.log('PRIVATE member facade: explicit profile, stable operation ID, exact saved retry, cancellation PASS (stub native boundary)');
