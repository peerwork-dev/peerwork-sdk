// Explicit transport option marshalling; native boundary is stubbed.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const realRequire = createRequire(import.meta.url), calls = [];
let configuredTransport;
class KernelCancelHandle { cancel() {} }
const native = { KernelCancelHandle };
for (const name of ['loadConfigJson','kernelJson','secureReadJson','secureReadProfileJson','securePrivateReadJson',
  'securePublicActionJson','securePublicInstallJson','secureOwnerCreateJson','secureOwnerConsumerJson',
  'publicCatalogJson','secureRecipientEnrollmentJson','secureIdentityDirectoryJson',
  'securePublicAdmissionJson','securePublicDecisionJson']) {
  native[name] = async (...args) => {
    calls.push([name,args]);
    const value = name === 'loadConfigJson' ? {origin:'https://x',state_dir:'/s',...(configuredTransport ? {transport:configuredTransport} : {})} :
      name === 'publicCatalogJson' ? {listing_canonical_json:'{}'} : {};
    return JSON.stringify({ok:true,value});
  };
}
const mockRequire = name => name === '/stub/native' ? native : realRequire(name);
mockRequire.resolve = () => '/stub/native';
const api = {};
new Function('require','exports','process',readFileSync(new URL('../bindings/node/index.cjs',import.meta.url),'utf8'))(mockRequire,api,process);
const transport = {requestTimeoutMs:2345,additionalRootPemFiles:['root-a.pem','root-b.pem']};
const expected = {request_timeout_ms:2345,additional_root_pem_files:['root-a.pem','root-b.pem']};
const parse = (name,index) => JSON.parse(calls.filter(row => row[0] === name).at(-1)[1][index]);
await api.openKernel({origin:'https://x',journalPath:'/j',identityPath:'/i',transport});
assert.deepEqual(JSON.parse(calls.at(-1)[1].at(-1)),expected);
await api.readSecureSnapshot({origin:'https://x',kernelJournalPath:'/j',readStatePath:'/r',lifecyclePath:'/l',identityPath:'/i',workspaceId:'w',authority:'a',ownerActorId:'a',ownerKeyId:'k',transport});
assert.deepEqual(parse('secureReadJson',0).transport,expected);
await api.readSecureWorkspace({origin:'https://x',stateDir:'/s',identityPath:'/i',workspaceId:'w',transport});
assert.deepEqual(parse('secureReadProfileJson',0).transport,expected);
await api.openSecureOwnerWorkspaces({origin:'https://x',stateDir:'/s',transport}).read('w');
assert.deepEqual(parse('secureOwnerCreateJson',1).transport,expected);
await api.openPublicCatalog({origin:'https://x',transport}).search('query');
assert.deepEqual(parse('publicCatalogJson',1).transport,expected);
await api.openSecureRecipientEnrollment({origin:'https://x',stateDir:'/s',transport}).pending();
assert.deepEqual(JSON.parse(calls.filter(row=>row[0]==='secureRecipientEnrollmentJson').at(-1)[1].at(-1)),expected);
await api.openSecureIdentityDirectory({origin:'https://x',stateDir:'/s',transport}).lookup('actor','key');
assert.deepEqual(JSON.parse(calls.filter(row=>row[0]==='secureIdentityDirectoryJson').at(-1)[1].at(-1)),expected);
await api.openSecureInvitation({origin:'https://x',stateDir:'/s',workspaceId:'w',ownerActorId:'a',ownerKeyId:'k',transport}).pendingDecisions();
assert.deepEqual(parse('securePublicAdmissionJson',2).transport,expected);
const returned = await api.loadConfig();
assert.deepEqual(returned,{origin:'https://x',stateDir:'/s'});
configuredTransport = expected;
const loaded = await api.loadConfig();
assert.deepEqual(loaded, {origin:'https://x',stateDir:'/s',transport:{requestTimeoutMs:2345,additionalRootPemFiles:['root-a.pem','root-b.pem']}});
await api.readSecureWorkspace({origin:'https://x',stateDir:'/s',identityPath:'/i',workspaceId:'w',transport:loaded.transport});
assert.deepEqual(parse('secureReadProfileJson',0).transport,expected);
// Omitted option leaves old JSON shape and positional bridge defaults untouched.
await api.readSecureWorkspace({origin:'https://x',stateDir:'/s',identityPath:'/i',workspaceId:'w'});
assert.equal(Object.hasOwn(parse('secureReadProfileJson',0),'transport'),false);
await api.openSecureRecipientEnrollment({origin:'https://x',stateDir:'/s'}).pending();
assert.equal(calls.filter(row=>row[0]==='secureRecipientEnrollmentJson').at(-1)[1].at(-1),undefined);
for(const value of [null,0,-1,1.5,Number.MAX_SAFE_INTEGER+1,2**64])
  assert.throws(()=>api.openSecureOwnerWorkspaces({origin:'https://x',stateDir:'/s',transport:{requestTimeoutMs:value}}),TypeError);
for(const value of [null,[''],[1],Array(17).fill('root.pem'),'root.pem'])
  assert.throws(()=>api.openSecureOwnerWorkspaces({origin:'https://x',stateDir:'/s',transport:{additionalRootPemFiles:value}}),TypeError);
assert.throws(()=>api.openSecureOwnerWorkspaces({origin:'https://x',stateDir:'/s',transport:{extra:true}}),TypeError);
assert.throws(()=>api.openSecureOwnerWorkspaces({origin:'https://x',stateDir:'/s',transport:Object.defineProperty({},'requestTimeoutMs',{enumerable:true,get(){throw Error('getter invoked')}})}),TypeError);
console.log('Node explicit/omitted transport marshalling and validation PASS (stub boundary)');
