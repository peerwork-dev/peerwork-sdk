// Direct pinned TypeScript resolveSecureAuthor vectors for the narrow ACTION
// principal/delegation scope boundary. No journal or effect authority.
import {createECDH, createPrivateKey, createPublicKey, webcrypto} from 'node:crypto';
import {writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';

const root=fileURLToPath(new URL('.',import.meta.url));
const source=fileURLToPath(new URL('reference/src/',import.meta.url));
const temp=await mkdtemp(join(tmpdir(),'peerwork-action-delegation-'));
const b64=value=>Buffer.from(value).toString('base64url');
const seed=byte=>Buffer.alloc(32,byte);
const identity=async byte=>{
  const der=Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed(byte)]);
  const privateKey=createPrivateKey({key:der,format:'der',type:'pkcs8'});
  const spki=createPublicKey(privateKey).export({format:'der',type:'spki'});
  const keyId=b64(spki.subarray(spki.length-32));
  const cryptoKey=await webcrypto.subtle.importKey('pkcs8',der,{name:'Ed25519'},false,['sign']);
  return {privateKey:cryptoKey,keyId};
};
try {
  const output=join(temp,'oracle.mjs');
  await build({entryPoints:[resolve(source,'workspace-secure-client.ts')],outfile:output,
    bundle:true,platform:'node',format:'esm',logLevel:'silent'});
  const {resolveSecureAuthor, signSecure, secureActorId}=await import(pathToFileURL(output));
  const principal=await identity(7),device=await identity(11);
  principal.actorId=await secureActorId(principal.keyId);
  device.actorId=await secureActorId(device.keyId);
  const ecdh=createECDH('prime256v1'); ecdh.setPrivateKey(seed(13));
  const point=ecdh.getPublicKey();
  const jwk={kty:'EC',crv:'P-256',x:b64(point.subarray(1,33)),y:b64(point.subarray(33,65))};
  const canonical=(value)=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))));
  const keyHash=b64(await webcrypto.subtle.digest('SHA-256',Buffer.from(canonical(jwk))));
  const certificate=await signSecure(device,'peerwork.secure.key-certificate.v1',
    {v:1,actor_id:device.actorId,signing_key:device.keyId,encryption_key:jwk,
      encryption_key_id:keyHash,issued_at:10,expires_at:10+366*86400000});
  const principalCertificate=await signSecure(principal,'peerwork.secure.key-certificate.v1',
    {v:1,actor_id:principal.actorId,signing_key:principal.keyId,encryption_key:jwk,
      encryption_key_id:keyHash,issued_at:10,expires_at:10+366*86400000});
  const workspace='W'.repeat(43),instance='I'.repeat(43);
  const scope=(actions,roles=['author'],capabilities=['edit'],at=null)=>
    ({instance_id:instance,actions,protocol_roles:roles,capabilities,expires_at:at});
  const policy={v:1,workspace_id:workspace,owner_id:principal.actorId,signing_key:principal.keyId,
    version:1,previous_policy:null,effective_sequence:1,visibility:'PUBLIC',epoch:0,
    members:[{actor_id:principal.actorId,certificate:principalCertificate,role:'OWNER',
      scopes:[scope(['alpha','beta'])]}],issued_at:10};
  const payload={v:1,workspace_id:workspace,actor_id:principal.actorId,
    signing_key:principal.keyId,device:certificate,request_id:'R'.repeat(43),
    scope:[scope(['alpha','beta'],['author','reviewer'],['edit','approve'])],read:true,
    origin:'https://example.test',audience:'https://example.test',issued_at:20,expires_at:1000};
  const delegation=await signSecure(principal,'peerwork.secure.device-delegation.v1',payload);
  const longDelegation=await signSecure(principal,'peerwork.secure.device-delegation.v1',
    {...payload,expires_at:certificate.payload.expires_at+1000});
  const globalPrincipal={...policy,members:[{...policy.members[0],scopes:[{...scope(['alpha']),instance_id:null}]}]};
  const globalDelegate=await signSecure(principal,'peerwork.secure.device-delegation.v1',
    {...payload,scope:[{...scope(['alpha']),instance_id:null}]});
  const expiredScope=await signSecure(principal,'peerwork.secure.device-delegation.v1',
    {...payload,scope:[scope(['alpha'],['author'],['edit'],30)]});
  const duplicateActions=await signSecure(principal,'peerwork.secure.device-delegation.v1',
    {...payload,scope:[scope(['alpha','alpha'])]});
  const context={v:1,workspace_id:workspace,sequence:2,previous:'a'.repeat(64),
    policy_hash:'b'.repeat(64),epoch:0,actor_id:device.actorId,signing_key:device.keyId,
    command_id:'C'.repeat(43),action_id:'alpha',instance_id:instance,
    issued_at:30,delegation};
  const input=[
    ['valid_delegated',context,policy],
    ['valid_direct',{...context,actor_id:principal.actorId,signing_key:principal.keyId,delegation:null},policy],
    ['actor_key_mismatch',{...context,signing_key:principal.keyId},policy],
    ['direct_not_member',{...context,delegation:null},policy],
    ['delegated_action_denied',{...context,action_id:'gamma'},policy],
    ['delegation_expired',{...context,issued_at:1000},policy],
    ['certificate_expired',{...context,delegation:longDelegation,issued_at:certificate.payload.expires_at},policy],
    ['principal_action_denied',context,{...policy,members:[{...policy.members[0],scopes:[scope(['beta'])]}]}],
    ['tampered_signed_scope',{...context,delegation:{...delegation,payload:{...delegation.payload,
      scope:[scope(['gamma'])]}}},policy],
    ['wrong_device_actor',{...context,actor_id:principal.actorId,signing_key:principal.keyId},policy],
    ['global_principal_scope',context,globalPrincipal],
    ['global_device_scope',{...context,delegation:globalDelegate},policy],
    ['delegation_scope_expires_at_issue',{...context,delegation:expiredScope},policy],
    ['principal_scope_expires_at_issue',context,{...policy,members:[{...policy.members[0],scopes:[scope(['alpha'],['author'],['edit'],30)]}]}],
    ['duplicate_signed_scope_actions',{...context,delegation:duplicateActions},policy],
  ];
  const vectors=[];
  for(const [name,ctx,pol] of input){
    const row={name,context:ctx,policy_payload:pol};
    try {const resolved=await resolveSecureAuthor(ctx,{payload:pol,signature:''});
      row.result={actor_id:resolved.actor_id,role:resolved.role,scopes:resolved.scopes};}
    catch(error){row.error=error.code??error.message;}
    vectors.push(row);
  }
  await writeFile(join(root,'action-delegation-vectors.json'),JSON.stringify(vectors,null,2)+'\n');
} finally {await rm(temp,{recursive:true,force:true});}
