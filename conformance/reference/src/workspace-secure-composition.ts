/** Dependency proofs are encrypted with the protocol object in private spaces. */
import {manifestCanonical,type Manifest} from './workspace-manifest.js';
import {composeProtocol} from './workspace-protocol-composition.js';
import {encodeCanonicalJson,sha256} from './workspace-secure-crypto.js';

export type ProtocolDependency={digest:string;manifest:unknown};
export type ProtocolComposition={v:1;source_digest:string;source_manifest:Manifest;dependencies:{digest:string;manifest:Manifest}[]};
const equal=(a:unknown,b:unknown)=>new TextDecoder().decode(encodeCanonicalJson(a))===new TextDecoder().decode(encodeCanonicalJson(b));
const check=(ok:unknown,code='PROTOCOL_COMPOSITION_INVALID')=>{if(!ok)throw new Error(code);};
export async function secureManifestDigest(value:unknown){const result=manifestCanonical(value),digest=[...await sha256(new TextEncoder().encode(result.canonical))].map(b=>b.toString(16).padStart(2,'0')).join('');return {...result,digest};}

/** Load only exact digests; a loader must not perform implicit network discovery. */
export async function resolveSecureProtocol(source:unknown,load:(digest:string)=>unknown|undefined){
 const root=await secureManifestDigest(source),nodes=new Map<string,Manifest>(),active=new Set<string>();
 const visit=async(digest:string,depth:number):Promise<void>=>{
  check(!active.has(digest),'DEPENDENCY_CYCLE');if(nodes.has(digest))return;
  check(depth<=16&&active.size+nodes.size<16,'RESOURCE_EXHAUSTED');
  const value=load(digest);check(value!==undefined,'DEPENDENCY_MISSING');
  const checked=await secureManifestDigest(value);check(checked.digest===digest,'DEPENDENCY_MISMATCH');
  active.add(digest);for(const child of [...checked.manifest.dependencies].sort())await visit(child,depth+1);
  active.delete(digest);nodes.set(digest,checked.manifest);
 };
 for(const digest of [...root.manifest.dependencies].sort())await visit(digest,1);
 const resolved=composeProtocol(root.manifest,digest=>nodes.get(digest));
 check(Object.keys(resolved.manifest.constraints).length===0,'PROTOCOL_CONSTRAINTS_UNRESOLVED');
 const result=await secureManifestDigest(resolved.manifest);
 const composition:ProtocolComposition={v:1,source_digest:root.digest,source_manifest:root.manifest,dependencies:resolved.dependencyClosure.map(digest=>({digest,manifest:nodes.get(digest)!}))};
 return {manifest:result.manifest,digest:result.digest,composition};
}

/** Recompute both the exact closure and executable manifest, not just their hashes. */
export async function verifyProtocolComposition(value:unknown):Promise<void>{
 const object=value as any,proof=object?.composition;
 check(proof&&typeof proof==='object'&&Object.keys(proof).sort().join(',')==='dependencies,source_digest,source_manifest,v'&&proof.v===1&&Array.isArray(proof.dependencies)&&proof.dependencies.length<=16);
 const nodes=new Map<string,unknown>();
 for(const node of proof.dependencies){check(node&&typeof node==='object'&&Object.keys(node).sort().join(',')==='digest,manifest'&&typeof node.digest==='string'&&/^[a-f0-9]{64}$/.test(node.digest)&&!nodes.has(node.digest));nodes.set(node.digest,node.manifest);}
 const resolved=await resolveSecureProtocol(proof.source_manifest,digest=>nodes.get(digest));
 check(equal(resolved.composition,proof)&&resolved.digest===object.digest&&equal(resolved.manifest,object.manifest)&&equal(resolved.manifest,object.resolved_manifest));
}
