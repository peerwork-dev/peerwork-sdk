import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
const [packagePath,fixturePath]=process.argv.slice(2);const sdk=createRequire(import.meta.url)(packagePath),v=JSON.parse(readFileSync(fixturePath));
const i=v.input,client=sdk.openSecureRecipientEnrollment({origin:v.origin,stateDir:v.profile,allowLoopbackHttp:true});
const request={protectedTsStatePath:i.protected_ts_state_path,expectedActorId:i.expected_actor_id,expectedSigningKeyId:i.expected_signing_key_id,expectedSourceDigest:i.expected_source_digest};
const first=await client.importLegacyKeys(request);assert.equal(first.status,'IMPORTED');assert.equal(first.historical_certificates,1);
assert.equal((await client.importLegacyKeys(request)).status,'ALREADY_IMPORTED');
const firstWorkspace=v.workspaces[0];
await assert.rejects(sdk.readSecurePrivateWorkspace({origin:v.origin,stateDir:v.profile,identityPath:v.profile+'/identity.state',workspaceId:firstWorkspace.id,ownerActorId:v.owner_actor,ownerKeyId:v.owner_key,allowLoopbackHttp:true}),e=>e.code==='VERIFICATION_FAILED');
for(const ws of v.workspaces.slice(0,1)){const read=await sdk.readSecurePrivateWorkspace({origin:v.origin,stateDir:v.profile,identityPath:v.profile+'/identity.state',workspaceId:ws.id,ownerActorId:v.owner_actor,ownerKeyId:v.owner_key,allowLoopbackHttp:true});
 assert(read.objects.some(o=>o.value?.payload?.title==='Before migration '+ws.label));}
console.log(JSON.stringify({status:'PASS',historical_certificates:first.historical_certificates}));
