import type {SecureJson,SecureObject} from './workspace-secure-contract.js';
import {decodeBase64Url,encodeCanonicalJson,sha256} from './workspace-secure-crypto.js';
type Fragment={kind:string;id:string;revision:number;index:number;count:number;provenance:SecureObject['provenance']};
function fail():never{throw new Error('MIGRATION_FRAGMENT_INVALID');}
/** Reassemble only after the complete signed descriptor set is verified. */
export async function inflateSecureFragments(objects:SecureObject[]):Promise<SecureObject[]>{
 const groups=new Map<string,{fragment:Fragment;parts:Map<number,Uint8Array>}>();const normal=objects.filter(o=>o.kind!=='secure_fragment');let byteCount=0;
 for(const object of objects){if(object.kind!=='secure_fragment')continue;const value=object.value as {fragment?:Fragment;data?:SecureJson},f=value?.fragment;
  if(!f||typeof f.kind!=='string'||!f.kind||f.kind==='secure_fragment'||typeof f.id!=='string'||!f.id||!Number.isSafeInteger(f.revision)||f.revision<1||!Number.isSafeInteger(f.count)||f.count<1||f.count>2048||!Number.isSafeInteger(f.index)||f.index<0||f.index>=f.count||!['AUTHOR_SIGNED','LEGACY_OWNER_ATTESTED'].includes(f.provenance)||typeof value.data!=='string'||object.revision!==1)fail();
  const key=[...await sha256(encodeCanonicalJson({kind:f.kind,id:f.id,revision:f.revision}))].map(b=>b.toString(16).padStart(2,'0')).join('');if(object.id!==`${key}-${f.index}`)fail();
  const part=decodeBase64Url(value.data);byteCount+=part.byteLength;if(!part.byteLength||part.byteLength>16384||byteCount>32*1024*1024)fail();
  const group=groups.get(key)??{fragment:f,parts:new Map<number,Uint8Array>()};if(group.fragment.count!==f.count||group.fragment.provenance!==f.provenance||group.parts.has(f.index))fail();group.parts.set(f.index,part);groups.set(key,group);
 }
 for(const {fragment:f,parts} of groups.values()){if(parts.size!==f.count)fail();const size=[...parts.values()].reduce((n,p)=>n+p.byteLength,0),all=new Uint8Array(size);let offset=0;for(let i=0;i<f.count;i++){const part=parts.get(i);if(!part||i<f.count-1&&part.byteLength!==16384)fail();all.set(part,offset);offset+=part.length;}
  const text=new TextDecoder('utf-8',{fatal:true}).decode(all),value=JSON.parse(text) as SecureJson;if(new TextDecoder().decode(encodeCanonicalJson(value))!==text)fail();if(normal.some(o=>o.kind===f.kind&&o.id===f.id&&o.revision===f.revision))fail();normal.push({kind:f.kind,id:f.id,revision:f.revision,provenance:f.provenance,value});
 }
 return normal;
}
