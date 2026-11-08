/** Complete portable compilation material retained inside the encrypted journal. */
import {parseJson} from './json.js';
import {canonicalStructured} from './workspace-manifest.js';
import {encodeCanonicalJson} from './workspace-secure-crypto.js';
import {SECURE_LIMITS,type SecureCheckpoint,type SecureObject} from './workspace-secure-contract.js';
import {verifiedJournalCheckpoint,type SecureVerifiedJournal} from './workspace-secure-client.js';
import {hash,utf8Bytes,equalBytes} from './protocol-package-runtime.js';
import {canonicalProtocolPackageClosureBytes,parseProtocolPackageClosureBytes,exactPackageLoader,protocolPackageClosureLimits,type ProtocolPackageClosure} from './protocol-package-closure.js';
import {compileProtocolPackage,assertPublishableCompilation,assertExecutableCompilation,type CompiledProtocolPackage} from './protocol-compiler.js';

export type ProtocolPackageMaterial={v:1;closure:ProtocolPackageClosure;bindings:Record<string,unknown>};
export type ProtocolPackagePartDescriptor={id:string;index:number;sha256:string;bytes:number};
export type ProtocolPackageSourceProof={v:1;workspace_id:string;source:SecureCheckpoint;source_id:string;source_sha256:string;bytes:number;parts:ProtocolPackagePartDescriptor[];root_package_digest:string;closure_digest:string;compilation_lock_sha256:string;protocol_digest:string};
export const protocolPackageSourceLimits=Object.freeze({partBytes:64*1024,parts:128,materialBytes:protocolPackageClosureLimits.wireBytes+32*6*8192+64*1024});
const token=/^[A-Za-z0-9_-]{43}$/,digest=/^[a-f0-9]{64}$/;
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
function check(ok:unknown,code='PROTOCOL_PACKAGE_SOURCE_INVALID'):asserts ok{if(!ok)throw new Error(code);}
function exact(value:unknown,keys:string[]):value is Record<string,unknown>{return Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null)&&Object.keys(value).sort().join(',')===keys.slice().sort().join(','));}
const same=(a:unknown,b:unknown)=>equalBytes(encodeCanonicalJson(a),encodeCanonicalJson(b));
export function normalizeProtocolPackageSourceCheckpoint(value:unknown):SecureCheckpoint{
 check(exact(value,['v','workspace_id','owner_id','owner_key','sequence','head','policy_hash'])&&value.v===1&&typeof value.workspace_id==='string'&&token.test(value.workspace_id)&&typeof value.owner_id==='string'&&token.test(value.owner_id)&&typeof value.owner_key==='string'&&token.test(value.owner_key)&&Number.isSafeInteger(value.sequence)&&Number(value.sequence)>=1&&typeof value.head==='string'&&digest.test(value.head)&&typeof value.policy_hash==='string'&&digest.test(value.policy_hash));
 return structuredClone(value) as SecureCheckpoint;
}
const sourceId=(source:SecureCheckpoint,sha256:string)=>hash('peerwork.protocol-package-source.v1\0'+decoder.decode(encodeCanonicalJson({source,source_sha256:sha256})));
export const protocolPackagePartId=(source:SecureCheckpoint,source_id:string,index:number)=>hash('peerwork.protocol-package-part.v1\0'+decoder.decode(encodeCanonicalJson({source,source_id,index})));
export function normalizePackageMaterial(value:unknown):ProtocolPackageMaterial{
 check(exact(value,['v','closure','bindings'])&&value.v===1&&value.bindings&&typeof value.bindings==='object'&&!Array.isArray(value.bindings));
 const closure=parseProtocolPackageClosureBytes(canonicalProtocolPackageClosureBytes(value.closure as ProtocolPackageClosure)).closure;
 // Keep the compiler's real binding rules, without imposing a new total budget.
 const bindings=JSON.parse(canonicalStructured(value.bindings)) as Record<string,unknown>,material={v:1 as const,closure,bindings};
 check(encodeCanonicalJson(material).byteLength<=protocolPackageSourceLimits.materialBytes);
 return material;
}
export function compilePackageMaterial(value:unknown):CompiledProtocolPackage{
 const material=normalizePackageMaterial(value),closure=parseProtocolPackageClosureBytes(canonicalProtocolPackageClosureBytes(material.closure));
 const compiled=assertPublishableCompilation(compileProtocolPackage(closure.rootPackage,{bindings:material.bindings,loadExactPackage:exactPackageLoader(closure)}));
 assertExecutableCompilation(compiled);return compiled;
}
function partObject(source:SecureCheckpoint,source_id:string,index:number,text:string):SecureObject{
 const bytes=utf8Bytes(text);
 return {kind:'protocol_package_part',id:protocolPackagePartId(source,source_id,index),revision:1,provenance:'AUTHOR_SIGNED',value:{v:1,workspace_id:source.workspace_id,source_id,index,bytes:bytes.byteLength,sha256:hash(bytes),text}};
}
export function validateProtocolPackagePart(value:unknown):SecureObject{
 check(exact(value,['kind','id','revision','provenance','value'])&&value.kind==='protocol_package_part'&&typeof value.id==='string'&&digest.test(value.id)&&value.revision===1&&value.provenance==='AUTHOR_SIGNED');
 const part=value.value;
 check(exact(part,['v','workspace_id','source_id','index','bytes','sha256','text'])&&part.v===1&&typeof part.workspace_id==='string'&&token.test(part.workspace_id)&&typeof part.source_id==='string'&&digest.test(part.source_id)&&Number.isSafeInteger(part.index)&&Number(part.index)>=0&&Number(part.index)<protocolPackageSourceLimits.parts&&Number.isSafeInteger(part.bytes)&&Number(part.bytes)>0&&Number(part.bytes)<=protocolPackageSourceLimits.partBytes&&typeof part.sha256==='string'&&digest.test(part.sha256)&&typeof part.text==='string');
 const bytes=utf8Bytes(part.text);check(decoder.decode(bytes)===part.text&&bytes.byteLength===part.bytes&&hash(bytes)===part.sha256&&encodeCanonicalJson(value).byteLength<=SECURE_LIMITS.objectBytes);
 return value as unknown as SecureObject;
}
export function normalizeProtocolPackageSourceProof(value:unknown):ProtocolPackageSourceProof{
 check(exact(value,['v','workspace_id','source','source_id','source_sha256','bytes','parts','root_package_digest','closure_digest','compilation_lock_sha256','protocol_digest'])&&value.v===1);
 const source=normalizeProtocolPackageSourceCheckpoint(value.source);check(value.workspace_id===source.workspace_id&&typeof value.source_id==='string'&&digest.test(value.source_id)&&typeof value.source_sha256==='string'&&digest.test(value.source_sha256)&&value.source_id===sourceId(source,value.source_sha256)&&Number.isSafeInteger(value.bytes)&&Number(value.bytes)>0&&Number(value.bytes)<=protocolPackageSourceLimits.materialBytes&&Array.isArray(value.parts)&&value.parts.length>0&&value.parts.length<=protocolPackageSourceLimits.parts);
 for(const field of ['root_package_digest','closure_digest','compilation_lock_sha256','protocol_digest'])check(typeof value[field]==='string'&&digest.test(value[field] as string));
 let bytes=0;
 for(let index=0;index<value.parts.length;index++){
  const part=value.parts[index];check(exact(part,['id','index','sha256','bytes'])&&part.index===index&&part.id===protocolPackagePartId(source,value.source_id,index)&&typeof part.sha256==='string'&&digest.test(part.sha256)&&Number.isSafeInteger(part.bytes)&&Number(part.bytes)>0&&Number(part.bytes)<=protocolPackageSourceLimits.partBytes);bytes+=Number(part.bytes);
 }
 check(bytes===value.bytes);
 return structuredClone(value) as unknown as ProtocolPackageSourceProof;
}
export function createProtocolPackageSource(value:unknown,sourceCP:SecureCheckpoint):{proof:ProtocolPackageSourceProof;parts:SecureObject[]}{
 const source=normalizeProtocolPackageSourceCheckpoint(sourceCP),material=normalizePackageMaterial(value),compiled=compilePackageMaterial(material),bytes=encodeCanonicalJson(material),text=decoder.decode(bytes),source_sha256=hash(bytes),source_id=sourceId(source,source_sha256),parts:SecureObject[]=[];
 let offset=0;
 while(offset<text.length){
  check(parts.length<protocolPackageSourceLimits.parts);const index=parts.length;let low=offset+1,high=Math.min(text.length,offset+protocolPackageSourceLimits.partBytes),chosen:SecureObject|undefined,end=offset;
  while(low<=high){
   const middle=Math.floor((low+high)/2);let boundary=middle;
   if(boundary<text.length&&boundary>offset&&text.charCodeAt(boundary-1)>=0xd800&&text.charCodeAt(boundary-1)<=0xdbff&&text.charCodeAt(boundary)>=0xdc00&&text.charCodeAt(boundary)<=0xdfff)boundary--;
   const candidate=partObject(source,source_id,index,text.slice(offset,boundary)),size=(candidate.value as {bytes:number}).bytes;
   if(boundary>offset&&size<=protocolPackageSourceLimits.partBytes&&encodeCanonicalJson(candidate).byteLength<=SECURE_LIMITS.objectBytes){chosen=candidate;end=boundary;low=middle+1;}else high=middle-1;
  }
  check(chosen&&end>offset);parts.push(validateProtocolPackagePart(chosen));offset=end;
 }
 const proof=normalizeProtocolPackageSourceProof({v:1,workspace_id:source.workspace_id,source,source_id,source_sha256,bytes:bytes.byteLength,parts:parts.map(part=>{const value=part.value as {index:number;sha256:string;bytes:number};return {id:part.id,index:value.index,sha256:value.sha256,bytes:value.bytes};}),root_package_digest:material.closure.root_package_digest,closure_digest:hash(canonicalProtocolPackageClosureBytes(material.closure)),compilation_lock_sha256:hash(encodeCanonicalJson(compiled.lock)),protocol_digest:compiled.protocolDigest});
 return {proof,parts};
}
function restoreProtocolPackageSource(value:unknown,objects:SecureObject[]){
 const proof=normalizeProtocolPackageSourceProof(value),related=objects.filter(object=>object.kind==='protocol_package_part'&&(object.value as any)?.source_id===proof.source_id);
 check(related.length===proof.parts.length);const pieces:string[]=[];
 for(const descriptor of proof.parts){
  const candidates=related.filter(object=>object.id===descriptor.id);check(candidates.length===1);const object=validateProtocolPackagePart(candidates[0]),part=object.value as {workspace_id:string;source_id:string;index:number;bytes:number;sha256:string;text:string};
  check(part.workspace_id===proof.workspace_id&&part.source_id===proof.source_id&&part.index===descriptor.index&&part.bytes===descriptor.bytes&&part.sha256===descriptor.sha256);pieces.push(part.text);
 }
 const text=pieces.join(''),bytes=utf8Bytes(text);check(bytes.byteLength===proof.bytes&&hash(bytes)===proof.source_sha256);
 const material=normalizePackageMaterial(parseJson(text));check(equalBytes(encodeCanonicalJson(material),bytes));const compiled=compilePackageMaterial(material);
 check(material.closure.root_package_digest===proof.root_package_digest&&hash(canonicalProtocolPackageClosureBytes(material.closure))===proof.closure_digest&&hash(encodeCanonicalJson(compiled.lock))===proof.compilation_lock_sha256&&compiled.protocolDigest===proof.protocol_digest);
 return {material,compiled};
}
export function verifyProtocolPackageSource(value:unknown,objects:SecureObject[]):CompiledProtocolPackage{return restoreProtocolPackageSource(value,objects).compiled;}
/** Reuse only complete source whose compiled identity independently matches its proof. */
export function readProtocolPackageMaterial(value:unknown,objects:SecureObject[]):ProtocolPackageMaterial{return restoreProtocolPackageSource(value,objects).material;}
/** Only the verified consecutive stage prefix may advance an already reviewed source. */
export function verifyStagedPackageCheckpoint(journal:SecureVerifiedJournal,value:unknown,targetCP:SecureCheckpoint=journal.checkpoint):SecureCheckpoint{
 const proof=normalizeProtocolPackageSourceProof(value),base=proof.source,target=normalizeProtocolPackageSourceCheckpoint(targetCP);
 check(same(verifiedJournalCheckpoint(journal,base.sequence),base)&&same(verifiedJournalCheckpoint(journal,target.sequence),target),'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');
 const count=target.sequence-base.sequence,after=journal.checkpoint.sequence-target.sequence;
 check(count>=0&&count<=proof.parts.length&&after>=0&&target.workspace_id===base.workspace_id&&target.owner_id===base.owner_id&&target.owner_key===base.owner_key&&target.policy_hash===base.policy_hash,'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');
 if(count===0){check(same(target,base),'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');return target;}
 // Operations intentionally have no guessed sequence metadata. Recovery gaps
 // which prevent this bounded tail mapping cause an explicit refusal.
 const end=journal.operations.length-after,start=end-count;check(start>=0&&end<=journal.operations.length,'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');
 for(let index=0;index<count;index++){
  const operation=journal.operations[start+index],stage=operation?.input as any,descriptor=proof.parts[index]!;
  check(exact(operation,['v','kind','input','objects'])&&operation.v===1&&operation.kind==='ADMIN'&&exact(stage,['package_stage'])&&exact(stage.package_stage,['source','source_id','part_index'])&&same(stage.package_stage.source,base)&&stage.package_stage.source_id===proof.source_id&&stage.package_stage.part_index===index&&Array.isArray(operation.objects)&&operation.objects.length===1,'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');
  const part=validateProtocolPackagePart(operation.objects[0]),data=part.value as any;
  check(part.id===descriptor.id&&data.workspace_id===base.workspace_id&&data.source_id===proof.source_id&&data.index===index&&data.bytes===descriptor.bytes&&data.sha256===descriptor.sha256&&same(verifiedJournalCheckpoint(journal,base.sequence+index+1).policy_hash,base.policy_hash),'PROTOCOL_INSTALL_CHECKPOINT_MISMATCH');
 }
 return target;
}
