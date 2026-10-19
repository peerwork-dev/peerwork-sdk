// Test-only browser wire peer. Native SDK exclusively performs approval.
// Keys and redeemed code stay in this process/pipes; stdout emits safe outcomes.
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
const root=process.env.PEERWORK_REFERENCE_ROOT;
const load=name=>import(pathToFileURL(join(root,'dist-workspace/src',name)).href);
const {createSigningIdentity,createEncryptionIdentity,certifyEncryptionKey}=await load('workspace-secure-crypto.js');
const {formatBrowserApprovalReference}=await load('browser-approval.js');
const {canonical}=await load('workspace-contract.js');
const {openKeyGrant,verifyJournal}=await load('workspace-secure-client.js');
const origin=process.env.PEERWORK_BROWSER_TEST_ORIGIN;
const workspace=process.env.PEERWORK_BROWSER_TEST_WORKSPACE;
const owner=JSON.parse(process.env.PEERWORK_BROWSER_TEST_OWNER);
const principal=process.env.PEERWORK_BROWSER_TEST_ACTOR;
const browserOrigin='https://synthetic-browser.example';
const signing=await createSigningIdentity(), encryption=await createEncryptionIdentity();
const certificate=await certifyEncryptionKey(signing,encryption,Date.now());
const b64=x=>Buffer.from(x).toString('base64url');
const hash=x=>createHash('sha256').update(x).digest('hex');
const discovery=await (await fetch(new URL('/api/workspace/v1/discovery',origin))).json();
const requests=new Map();
let stage="startup";
async function http(path,body){
 stage=`http:${path.includes('/redeem')?'redeem':path.includes('/sessions/')?'session-read':path.includes('/status')?'status':'create'}`;
 const response=await fetch(new URL(path,origin),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 const value=await response.json();
 assert.ok(response.ok,`BROWSER_HTTP_${response.status}_${value?.error?.code??'FAILED'}`);
 return value;
}
async function proof(target,extra={}){
 const h=b64(canonical({alg:'EdDSA',typ:'peerwork.browser-session.v1+jws',kid:signing.keyId}));
 const p=b64(canonical({v:1,audience:discovery.audience,origin:browserOrigin,target,
   nonce:randomBytes(32).toString('base64url'),expires_at:Date.now()+30000,...extra}));
 return `${h}.${p}.${b64(await crypto.subtle.sign('Ed25519',signing.privateKey,Buffer.from(`${h}.${p}`)))}`;
}
async function create(input){
 const now=Date.now(),verifier=randomBytes(32).toString('base64url');
 const challenge=createHash('sha256').update(verifier,'ascii').digest('base64url');
 const expires=now+(input.ttl_ms??240000),sessionExpires=now+3500000;
 const scope={read:true,writes:input.writes??[],session_expires_at:sessionExpires};
 const created=await http('/api/workspace/v1/browser/requests',{workspace_id:workspace,device_key:signing.keyId,
  secure_certificate:certificate,origin:browserOrigin,scope,expires_at:expires,verifier_challenge:challenge});
 assert.ok(created.request_id);
 const binding={request_id:created.request_id,workspace_id:workspace,device_key:signing.keyId,
  device_key_sha256:hash(Buffer.from(signing.keyId,'base64url')),secure_certificate:certificate,
  origin:browserOrigin,browser_origin:browserOrigin,control_origin:new URL(origin).origin,
  audience:discovery.audience,verifier_challenge:challenge,scope,
  request_expires_at:created.expires_at??expires,session_expires_at:sessionExpires};
 const reference=formatBrowserApprovalReference(binding);
 requests.set(created.request_id,{verifier,scope,reference});
 return {reference,request_id:created.request_id,expires_at:binding.request_expires_at};
}
async function redeem(input){
 const saved=requests.get(input.request_id);assert.ok(saved);
 const parts=input.code.split(':');
 assert.equal(parts.length,7);assert.equal(parts[0],'peerwork-secure-code');assert.equal(parts[1],'v1');
 assert.equal(parts[2],workspace);assert.equal(parts[3],input.request_id);assert.equal(parts[5],owner.key);
 const path=`/api/workspace/v1/browser/requests/${input.request_id}/redeem`;
 const redemption={request_id:input.request_id,code:parts[4],verifier:saved.verifier};
 const session=await http(path,{...redemption,proof:await proof(path,{issued_at:Date.now(),request_id:input.request_id,redemption_digest:hash(canonical(redemption))})});
 assert.equal(session.state,'REDEEMED');assert.equal(session.workspace_id,workspace);
 assert.equal(session.secure_delegation.payload.actor_id,principal);
 assert.equal(session.secure_delegation.payload.signing_key,parts[6]);
 assert.deepEqual(session.scope.writes,[]);
 const commits=[];let page,first;let after=0;
 for(let n=0;n<20;n++){
  const target=`/api/workspace/v1/secure/workspaces/${workspace}/journal?after=${after}&limit=50`;
  page=await http(`/api/workspace/v1/browser/sessions/${session.session_id}/read`,
   {target,proof:await proof(target),secure_delegation:session.secure_delegation});
  first??=page;assert.deepEqual(page.checkpoint,first.checkpoint);commits.push(...page.commits);
  if(page.next===null)break;assert.ok(page.next>after);after=page.next;
 }
 assert.equal(page.next,null);
 stage='select-grant-policy';
 const policy=first.policies.find(p=>p.payload.epoch===session.secure_key_grant.payload.epoch &&
  hash(canonical(p))===session.secure_key_grant.payload.policy_hash);
 assert.ok(policy);
 stage='decrypt-key-grant';
 const keyring=await openKeyGrant({grant:session.secure_key_grant,recipient:certificate,
  privateKey:encryption.privateKey,policy,policies:first.policies,owner,
  expectedDelegation:session.secure_delegation});
 stage='verify-decrypt-journal';
 const verified=await verifyJournal({workspaceId:workspace,policies:first.policies,commits,
  checkpoint:first.checkpoint,trustedOwner:owner,keyring});
 stage='readback-canary';
 const values=verified.objects instanceof Map?[...verified.objects.values()]:verified.objects;
 assert.ok(JSON.stringify(values).includes('Python PRIVATE member readback'));
 return {redeemed:true,decrypted:true,member_author:session.secure_delegation.payload.actor_id,
  no_write_scope:true,sequence:first.checkpoint.sequence};
}
for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})){
 try{const input=JSON.parse(line);let result;
  if(input.operation==='create')result=await create(input);
  else if(input.operation==='redeem')result=await redeem(input);
  else if(input.operation==='status')result=await http(`/api/workspace/v1/browser/requests/${input.request_id}/status`,{proof:await proof(`request:${input.request_id}`)});
  else throw Error('UNKNOWN_TEST_OPERATION');
  process.stdout.write(JSON.stringify({ok:true,result})+'\n');
 }catch(error){process.stdout.write(JSON.stringify({ok:false,code:String(error?.code??'BROWSER_PEER_FAILED'),stage})+'\n');}
}
