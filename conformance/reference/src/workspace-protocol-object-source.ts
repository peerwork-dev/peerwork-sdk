/** Bounded, portable storage for the complete signed value of a protocol object. */
import {encodeCanonicalJson} from './workspace-secure-crypto.js';
import {SECURE_LIMITS,type SecureCheckpoint,type SecureObject,type SecureJson} from './workspace-secure-contract.js';
import {hash,utf8Bytes,equalBytes} from './protocol-package-runtime.js';

export type ProtocolObjectPartDescriptor={id:string;index:number;sha256:string;bytes:number};
export type ProtocolObjectSourceProof={v:1;workspace_id:string;source:SecureCheckpoint;source_id:string;protocol_digest:string;value_sha256:string;bytes:number;parts:ProtocolObjectPartDescriptor[]};
export const protocolObjectSourceLimits=Object.freeze({partBytes:64*1024,valueBytes:SECURE_LIMITS.workspaceBytes,parts:2048});
const token=/^[A-Za-z0-9_-]{43}$/,digest=/^[a-f0-9]{64}$/;
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
function check(ok:unknown):asserts ok{if(!ok)throw new Error('PROTOCOL_OBJECT_SOURCE_INVALID');}
function exact(value:unknown,keys:string[]):value is Record<string,unknown>{return Boolean(value&&typeof value==='object'&&!Array.isArray(value)&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null)&&Object.keys(value).sort().join(',')===keys.slice().sort().join(','));}
function checkpoint(value:unknown):SecureCheckpoint{
 check(exact(value,['v','workspace_id','owner_id','owner_key','sequence','head','policy_hash'])&&value.v===1&&typeof value.workspace_id==='string'&&token.test(value.workspace_id)&&typeof value.owner_id==='string'&&token.test(value.owner_id)&&typeof value.owner_key==='string'&&token.test(value.owner_key)&&Number.isSafeInteger(value.sequence)&&Number(value.sequence)>=1&&typeof value.head==='string'&&digest.test(value.head)&&typeof value.policy_hash==='string'&&digest.test(value.policy_hash));
 return structuredClone(value) as SecureCheckpoint;
}
function valueShape(value:unknown,workspaceId:string,protocolDigest:string):Record<string,unknown>{
 check(value&&typeof value==='object'&&!Array.isArray(value));const row=value as Record<string,unknown>;
 check(exact(row,['workspace_id','digest','manifest','resolved_manifest',...(row.composition!==undefined?['composition']:[]),...(row.package_source!==undefined?['package_source']:[])])&&row.workspace_id===workspaceId&&row.digest===protocolDigest&&row.manifest!==undefined&&row.resolved_manifest!==undefined);
 return row;
}
const sourceId=(source:SecureCheckpoint,protocolDigest:string,valueSha256:string)=>hash('peerwork.protocol-object-source.v1\0'+decoder.decode(encodeCanonicalJson({source,protocol_digest:protocolDigest,value_sha256:valueSha256})));
export const protocolObjectPartId=(source:SecureCheckpoint,source_id:string,index:number)=>hash('peerwork.protocol-object-part.v1\0'+decoder.decode(encodeCanonicalJson({source,source_id,index})));
function partObject(source:SecureCheckpoint,source_id:string,index:number,text:string):SecureObject{
 const bytes=utf8Bytes(text);
 return {kind:'protocol_object_part',id:protocolObjectPartId(source,source_id,index),revision:1,provenance:'AUTHOR_SIGNED',value:{v:1,workspace_id:source.workspace_id,source_id,index,bytes:bytes.byteLength,sha256:hash(bytes),text}};
}
export function validateProtocolObjectPart(input:unknown):SecureObject{
 check(exact(input,['kind','id','revision','provenance','value'])&&input.kind==='protocol_object_part'&&typeof input.id==='string'&&digest.test(input.id)&&input.revision===1&&input.provenance==='AUTHOR_SIGNED');
 const part=input.value;
 check(exact(part,['v','workspace_id','source_id','index','bytes','sha256','text'])&&part.v===1&&typeof part.workspace_id==='string'&&token.test(part.workspace_id)&&typeof part.source_id==='string'&&digest.test(part.source_id)&&Number.isSafeInteger(part.index)&&Number(part.index)>=0&&Number(part.index)<protocolObjectSourceLimits.parts&&Number.isSafeInteger(part.bytes)&&Number(part.bytes)>0&&Number(part.bytes)<=protocolObjectSourceLimits.partBytes&&typeof part.sha256==='string'&&digest.test(part.sha256)&&typeof part.text==='string');
 const bytes=utf8Bytes(part.text);check(decoder.decode(bytes)===part.text&&bytes.byteLength===part.bytes&&hash(bytes)===part.sha256&&encodeCanonicalJson(input).byteLength<=SECURE_LIMITS.objectBytes);
 return input as unknown as SecureObject;
}
export function normalizeProtocolObjectSourceProof(input:unknown):ProtocolObjectSourceProof{
 check(exact(input,['v','workspace_id','source','source_id','protocol_digest','value_sha256','bytes','parts'])&&input.v===1);
 const source=checkpoint(input.source);check(input.workspace_id===source.workspace_id&&typeof input.source_id==='string'&&digest.test(input.source_id)&&typeof input.protocol_digest==='string'&&digest.test(input.protocol_digest)&&typeof input.value_sha256==='string'&&digest.test(input.value_sha256)&&input.source_id===sourceId(source,input.protocol_digest,input.value_sha256)&&Number.isSafeInteger(input.bytes)&&Number(input.bytes)>0&&Number(input.bytes)<=protocolObjectSourceLimits.valueBytes&&Array.isArray(input.parts)&&input.parts.length>0&&input.parts.length<=protocolObjectSourceLimits.parts);
 let bytes=0;
 for(let index=0;index<input.parts.length;index++){
  const part=input.parts[index];check(exact(part,['id','index','sha256','bytes'])&&part.index===index&&part.id===protocolObjectPartId(source,input.source_id,index)&&typeof part.sha256==='string'&&digest.test(part.sha256)&&Number.isSafeInteger(part.bytes)&&Number(part.bytes)>0&&Number(part.bytes)<=protocolObjectSourceLimits.partBytes);bytes+=Number(part.bytes);
 }
 check(bytes===input.bytes);return structuredClone(input) as unknown as ProtocolObjectSourceProof;
}
export function createProtocolObjectSource(value:unknown,sourceCP:SecureCheckpoint):{proof:ProtocolObjectSourceProof;parts:SecureObject[]}{
 const source=checkpoint(sourceCP);valueShape(value,source.workspace_id,(value as Record<string,unknown>)?.digest as string);
 const protocolDigest=(value as Record<string,unknown>).digest as string;check(digest.test(protocolDigest));
 const bytes=encodeCanonicalJson(value),text=decoder.decode(bytes);check(bytes.byteLength>0&&bytes.byteLength<=protocolObjectSourceLimits.valueBytes);
 const value_sha256=hash(bytes),source_id=sourceId(source,protocolDigest,value_sha256),parts:SecureObject[]=[];
 let offset=0;
 while(offset<text.length){
  check(parts.length<protocolObjectSourceLimits.parts);const index=parts.length;let low=offset+1,high=Math.min(text.length,offset+protocolObjectSourceLimits.partBytes),chosen:SecureObject|undefined,end=offset;
  while(low<=high){
   const middle=Math.floor((low+high)/2);let boundary=middle;
   if(boundary<text.length&&boundary>offset&&text.charCodeAt(boundary-1)>=0xd800&&text.charCodeAt(boundary-1)<=0xdbff&&text.charCodeAt(boundary)>=0xdc00&&text.charCodeAt(boundary)<=0xdfff)boundary--;
   const candidate=partObject(source,source_id,index,text.slice(offset,boundary)),size=(candidate.value as {bytes:number}).bytes;
   if(boundary>offset&&size<=protocolObjectSourceLimits.partBytes&&encodeCanonicalJson(candidate).byteLength<=SECURE_LIMITS.objectBytes){chosen=candidate;end=boundary;low=middle+1;}else high=middle-1;
  }
  check(chosen&&end>offset);parts.push(validateProtocolObjectPart(chosen));offset=end;
 }
 const proof=normalizeProtocolObjectSourceProof({v:1,workspace_id:source.workspace_id,source,source_id,protocol_digest:protocolDigest,value_sha256,bytes:bytes.byteLength,parts:parts.map(part=>{const row=part.value as {index:number;sha256:string;bytes:number};return {id:part.id,index:row.index,sha256:row.sha256,bytes:row.bytes};})});
 return {proof,parts};
}
export function readProtocolObjectSource(input:unknown,objects:SecureObject[]):SecureJson{
 const proof=normalizeProtocolObjectSourceProof(input),related=objects.filter(object=>object.kind==='protocol_object_part'&&(object.value as any)?.source_id===proof.source_id);
 check(related.length===proof.parts.length);const pieces:string[]=[];
 for(const descriptor of proof.parts){
  const candidates=related.filter(object=>object.id===descriptor.id);check(candidates.length===1);const part=validateProtocolObjectPart(candidates[0]),row=part.value as {workspace_id:string;source_id:string;index:number;bytes:number;sha256:string;text:string};
  check(row.workspace_id===proof.workspace_id&&row.source_id===proof.source_id&&row.index===descriptor.index&&row.bytes===descriptor.bytes&&row.sha256===descriptor.sha256);pieces.push(row.text);
 }
 const text=pieces.join(''),bytes=utf8Bytes(text);check(bytes.byteLength===proof.bytes&&hash(bytes)===proof.value_sha256);
 let value:unknown;try{value=JSON.parse(text);check(equalBytes(encodeCanonicalJson(value),bytes));}catch{throw new Error('PROTOCOL_OBJECT_SOURCE_INVALID');}
 valueShape(value,proof.workspace_id,proof.protocol_digest);return value as SecureJson;
}
