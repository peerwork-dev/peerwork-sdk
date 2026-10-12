/** Decrypted-content check for the signed v3 protocol-format ceiling. */
import type {SecureCommit,SecureObject} from './workspace-secure-contract.js';
import {inflateSecureFragments} from './workspace-secure-migration.js';

const fail=():never=>{throw new Error('PROTOCOL_FORMAT_CEILING_VIOLATION');};
const record=(value:unknown):Record<string,any>=>value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,any>:fail();
function decoded(value:unknown):Record<string,any>{try{return record(typeof value==='string'?JSON.parse(value):value);}catch{return fail();}}
function formatWithin(value:unknown,ceiling:1|2){const version=decoded(value).format_version;if(version!==undefined&&!(ceiling===2&&version===2))fail();}
function protocol(object:SecureObject,ceiling:1|2){
 const formatOne=(value:unknown)=>formatWithin(value,ceiling);
 const value=record(object.value);
 if(object.provenance==='AUTHOR_SIGNED'){
  if(value.manifest===undefined||value.resolved_manifest===undefined)fail();
  formatOne(value.manifest);formatOne(value.resolved_manifest);
  if(value.composition!==undefined){const proof=record(value.composition);formatOne(proof.source_manifest);if(!Array.isArray(proof.dependencies))fail();for(const node of proof.dependencies)formatOne(record(node).manifest);}
 }else if(object.provenance==='LEGACY_OWNER_ATTESTED'){
  const envelope=decoded(value.manifest);if(envelope.manifest===undefined||value.resolved_manifest===undefined)fail();
  formatOne(envelope.manifest);formatOne(value.resolved_manifest);
 }else fail();
}
function collect(objects:SecureObject[],budget:{objects:number},depth=0):SecureObject[]{
 if(depth>8)fail();const result:SecureObject[]=[];
 for(const object of objects){if(++budget.objects>65_536||!object||typeof object!=='object')fail();
  if(object.kind==='secure_commits'){
   const value=record(object.value),commit=(typeof value.artifact==='string'?decoded(value.artifact):value) as SecureCommit,payload=record(commit.payload);
   if(payload.mode!=='PUBLIC')fail();const body=record(payload.body);if(!Array.isArray(body.objects))fail();
   result.push(...collect(body.objects as SecureObject[],budget,depth+1));
  }else result.push(object);
 }
 return result;
}

/** No result is released until every nested archived source and fragment is checked. */
export async function assertProtocolFormatCeiling(objects:SecureObject[],ceiling:1|2):Promise<void>{
 if(ceiling!==1&&ceiling!==2)fail();
 if(!Array.isArray(objects))fail();const budget={objects:0};let candidate=collect(objects,budget),fragmentBytes=0;
 for(let layer=0;candidate.some(object=>object.kind==='secure_fragment');layer++){
  if(layer>=8)fail();for(const object of candidate)if(object.kind==='secure_fragment'){
   const value=record(object.value);if(typeof value.data!=='string')fail();fragmentBytes+=Math.ceil(value.data.length*3/4);if(fragmentBytes>32*1024*1024)fail();
  }
  try{candidate=collect(await inflateSecureFragments(candidate),budget);}catch{return fail();}
 }
 for(const object of candidate)if(object.kind==='protocols')protocol(object,ceiling);
}

export const assertProtocolFormatCeilingOne=(objects:SecureObject[])=>assertProtocolFormatCeiling(objects,1);
