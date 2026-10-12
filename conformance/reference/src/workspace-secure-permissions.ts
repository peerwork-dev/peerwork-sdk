/** Owner-signed scope replacement cannot change membership, keys or protocol policy. */
import type {SecureCommitContext,SecureOperation,SecurePolicy,SecureScope,SecureObject} from './workspace-secure-contract.js';
import {encodeCanonicalJson} from './workspace-secure-crypto.js';
const equal=(a:unknown,b:unknown)=>new TextDecoder().decode(encodeCanonicalJson(a))===new TextDecoder().decode(encodeCanonicalJson(b));
const check=(ok:unknown)=>{if(!ok)throw new Error('MEMBER_SCOPE_TRANSITION_INVALID');};
export function validateMemberScopeTransition(previous:SecurePolicy,next:SecurePolicy,context:SecureCommitContext):string{
 const before=previous.payload,after=next.payload;
 check(context.action_id==='secure.member.scopes'&&context.actor_id===before.owner_id&&context.signing_key===before.signing_key&&context.delegation===null&&context.instance_id===null&&after.version===before.version+1&&after.effective_sequence===context.sequence&&after.issued_at===context.issued_at);
 check(after.members.length===before.members.length);const changed:string[]=[];
 for(let i=0;i<before.members.length;i++){const old=before.members[i]!,member=after.members[i]!;check(member&&equal({...old,scopes:member.scopes},member));if(!equal(old.scopes,member.scopes))changed.push(old.actor_id);}
 check(changed.length===1&&equal({...before,members:after.members,version:after.version,previous_policy:after.previous_policy,effective_sequence:after.effective_sequence,issued_at:after.issued_at},after));
 if(context.structure)check(context.structure.mode==='DELTA'&&context.structure.records.length===0&&context.structure.heads.length===0);
 return changed[0]!;
}
export function validateMemberScopeOperation(operation:SecureOperation,actorId:string,priorHash:string):void{
 check(equal(operation,{v:1,kind:'ADMIN',input:{member_id:actorId,expected_policy_hash:priorHash},objects:[]}));
}
export function validateReplacementScopes(scopes:SecureScope[]):void{
 if(!Array.isArray(scopes)||scopes.length>128)throw new Error('MEMBER_SCOPES_INVALID');
 for(const s of scopes){if(!s||typeof s!=='object'||Array.isArray(s)||!['instance_id','actions','protocol_roles','capabilities'].every(k=>Object.hasOwn(s,k))||Object.keys(s).some(k=>!['instance_id','actions','protocol_roles','capabilities','expires_at'].includes(k))||s.instance_id!==null&&!/^[A-Za-z0-9_-]{43}$/.test(s.instance_id)||s.expires_at!==undefined&&s.expires_at!==null&&(!Number.isSafeInteger(s.expires_at)||s.expires_at<1))throw new Error('MEMBER_SCOPES_INVALID');for(const list of [s.actions,s.protocol_roles,s.capabilities])if(!Array.isArray(list)||list.length>64||new Set(list).size!==list.length||list.some(x=>typeof x!=='string'||x.length<1||x.length>120))throw new Error('MEMBER_SCOPES_INVALID');}
}

export function memberScopeCatalog(objects:SecureObject[]){
 const latest=new Map<string,SecureObject>();for(const o of objects){const key=JSON.stringify([o.kind,o.id]);if(!latest.has(key)||latest.get(key)!.revision<o.revision)latest.set(key,o);}
 const values=[...latest.values()];return values.filter(o=>o.kind==='instances').map(o=>{const value=o.value as any,protocol=values.find(p=>p.kind==='protocols'&&p.id===value.protocol_digest)?.value as any;if(!protocol)throw new Error('MEMBER_SCOPE_PROTOCOL_NOT_FOUND');const raw=protocol.resolved_manifest??protocol.manifest,manifest=typeof raw==='string'?JSON.parse(raw):raw;return {instance_id:o.id,protocol_digest:value.protocol_digest,entrypoint:value.origin_entrypoint,actions:manifest.actions.map((a:any)=>a.id) as string[],protocol_roles:manifest.protocol_roles as string[],capabilities:manifest.capabilities as string[],role_conflicts:manifest.role_conflicts,historical_role_conflicts:manifest.historical_role_conflicts};});
}
/** Decrypted manifest names are checked by trusted clients, not inferred by Control. */
export function validateMemberScopePermissions(scopes:SecureScope[],objects:SecureObject[]):void{
 validateReplacementScopes(scopes);const catalog=memberScopeCatalog(objects);for(const scope of scopes){const selected=catalog.filter(i=>scope.instance_id===null||i.instance_id===scope.instance_id);if(!selected.length)throw new Error('MEMBER_SCOPE_INSTANCE_NOT_FOUND');for(const key of ['actions','protocol_roles','capabilities'] as const){const allowed=new Set(selected.flatMap(i=>i[key]));if(scope[key].some(v=>!allowed.has(v)))throw new Error('MEMBER_SCOPE_UNDECLARED_PERMISSION');}}
}
