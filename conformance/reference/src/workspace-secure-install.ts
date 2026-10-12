import {normalizeProtocolObjectSourceProof,readProtocolObjectSource,type ProtocolObjectSourceProof} from './workspace-protocol-object-source.js';
import {manifestCanonical} from './workspace-manifest.js';
/** Additive protocol installation inside an Owner-signed structure adoption. */
import type {SecureCommitContext,SecureObject,SecureOperation} from './workspace-secure-contract.js';
import {encodeCanonicalJson,sha256} from './workspace-secure-crypto.js';
import {verifyProtocolComposition} from './workspace-secure-composition.js';
import {requireExecutableProtocol} from './workspace-protocol-execution.js';
import {normalizeProtocolPackageSourceProof,verifyProtocolPackageSource} from './workspace-protocol-package-source.js';
const equal=(a:unknown,b:unknown)=>encodeCanonicalJson(a).toString()===encodeCanonicalJson(b).toString();
const check=(ok:unknown)=>{if(!ok)throw new Error('STRUCTURE_INSTALL_INVALID');};
/** Reject edits, content fabrication and unbound new instances during snapshot begin. */
export async function validateStructureInstall(operation:SecureOperation,context:SecureCommitContext,objects:SecureObject[],objectSource?:ProtocolObjectSourceProof):Promise<void>{
 const input=operation.input as any,install=input?.install;
 check(operation.kind==='ADMIN'&&context.action_id==='secure.structure.begin'&&context.structure?.mode==='SNAPSHOT_BEGIN'&&context.instance_id===null&&context.delegation===null);
 check(input&&Object.keys(input).length===1&&install&&Object.keys(install).sort().join(',')==='entrypoint,instance_id,protocol_digest');
 check(/^[A-Za-z0-9_-]{43}$/.test(install.instance_id)&&/^[a-f0-9]{64}$/.test(install.protocol_digest)&&typeof install.entrypoint==='string'&&/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(install.entrypoint));
 check(!objects.some(o=>o.kind==='instances'&&o.id===install.instance_id));
 const prior=objects.find(o=>o.kind==='protocols'&&o.id===install.protocol_digest),added=operation.objects.find(o=>o.kind==='protocols'),instance=operation.objects.find(o=>o.kind==='instances');
 check(operation.objects.length===(prior?1:2)&&Boolean(prior)!==Boolean(added)&&instance&&instance.id===install.instance_id&&instance.revision===1&&instance.provenance==='AUTHOR_SIGNED');
 const protocol=prior??added!,value=protocol.value as any,manifest=typeof value.manifest==='string'?JSON.parse(value.manifest):value.manifest;
 if(objectSource){const proof=normalizeProtocolObjectSourceProof(objectSource);check(Boolean(added)&&proof.protocol_digest===protocol.id&&proof.workspace_id===context.workspace_id&&equal(readProtocolObjectSource(proof,objects),value));}
 const checked=manifestCanonical(manifest);
 requireExecutableProtocol(checked.manifest);
 const allowFormatTwo=context.v===3&&context.protocol_format_ceiling===2;
 check(allowFormatTwo||checked.manifest.format_version!==2);
 check(allowFormatTwo||value.composition?.source_manifest?.format_version!==2&&!value.composition?.dependencies?.some((node:any)=>node.manifest?.format_version===2));
 // Each instance proves its own compilation and reviewed stage checkpoint. An
 // existing protocol retains the provenance of its first installation.
 const instanceValue=instance!.value as any,packageSource=instanceValue.package_source;
 if(packageSource!==undefined){
  const proof=normalizeProtocolPackageSourceProof(packageSource),compiled=verifyProtocolPackageSource(proof,objects),source=context.structure!.snapshot?.source,packageStageHead=objectSource?.source??source;
  check(proof.workspace_id===context.workspace_id&&source&&source.workspace_id===proof.workspace_id&&source.owner_id===proof.source.owner_id&&source.owner_id===context.actor_id&&source.owner_key===proof.source.owner_key&&source.owner_key===context.signing_key&&source.policy_hash===proof.source.policy_hash&&packageStageHead&&packageStageHead.workspace_id===source.workspace_id&&packageStageHead.owner_id===source.owner_id&&packageStageHead.owner_key===source.owner_key&&packageStageHead.policy_hash===source.policy_hash&&packageStageHead.sequence===proof.source.sequence+proof.parts.length&&source.sequence===packageStageHead.sequence+(objectSource?.parts.length??0)&&source.sequence===context.sequence-1&&source.head===context.previous&&compiled.protocolDigest===install.protocol_digest&&equal(compiled.manifest,manifest)&&equal(value.manifest,value.resolved_manifest));
  if(added)check(value.composition===undefined&&value.package_source!==undefined&&equal(value.package_source,proof));
 }
 // Independently preserve the original protocol's closure proof, without
 // rebinding its old source to this instance's snapshot.
 if(value.package_source!==undefined){
  check(value.composition===undefined&&packageSource!==undefined);const proof=normalizeProtocolPackageSourceProof(value.package_source),compiled=verifyProtocolPackageSource(proof,objects);
  check(proof.workspace_id===context.workspace_id&&compiled.protocolDigest===install.protocol_digest&&equal(compiled.manifest,manifest)&&equal(value.manifest,value.resolved_manifest));
 }else if(value.composition!==undefined)await verifyProtocolComposition(value);
 else if(added&&packageSource===undefined)check(Array.isArray(manifest.dependencies)&&manifest.dependencies.length===0&&manifest.constraints&&typeof manifest.constraints==='object'&&!Array.isArray(manifest.constraints)&&Object.keys(manifest.constraints).length===0);
 const digest=[...await sha256(encodeCanonicalJson({semantics:'peerwork.kernel.v1',manifest}))].map(b=>b.toString(16).padStart(2,'0')).join('');check(digest===install.protocol_digest&&value.digest===digest&&value.workspace_id===context.workspace_id);
 if(added)check(added.id===digest&&added.revision===1&&added.provenance==='AUTHOR_SIGNED'&&equal(Object.keys(value).sort(),[...(value.composition!==undefined?['composition']:[]),'digest','manifest',...(value.package_source!==undefined?['package_source']:[]),'resolved_manifest','workspace_id'])&&equal(value.manifest,value.resolved_manifest));
 const expected={id:install.instance_id,workspace_id:context.workspace_id,protocol_digest:digest,origin_entrypoint:install.entrypoint,semantics:'peerwork.kernel.v1',state:manifest.initial_state,revision:0,event_revision:0,created:context.issued_at,...(packageSource!==undefined?{package_source:normalizeProtocolPackageSourceProof(packageSource)}:{})};
 check(equal(instance!.value,expected));
}
