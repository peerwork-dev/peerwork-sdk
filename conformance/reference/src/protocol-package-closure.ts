import {parseJson} from './json.js';
import {decodeBase64url as decodeCanonicalBase64url,encodeBase64url,equalBytes,hash,utf8Bytes} from './protocol-package-runtime.js';
import {canonicalProtocolPackageBytes,parseProtocolPackage,parseProtocolPackageBytes,PROTOCOL_PACKAGE_FORMAT,type ProtocolPackage,type ProtocolPackageBundle} from './protocol-package.js';

export const PROTOCOL_PACKAGE_CLOSURE_FORMAT='peerwork.protocol-package-closure.v1' as const;
export const protocolPackageClosureLimits=Object.freeze({entries:16,rawBytes:4*1024*1024,wireBytes:6*1024*1024,depth:16,compileSteps:128});
export type ProtocolPackageClosure={format:typeof PROTOCOL_PACKAGE_CLOSURE_FORMAT;root_package_digest:string;packages:Record<string,string>};
export type ParsedProtocolPackageClosure={closure:ProtocolPackageClosure;rootPackage:ProtocolPackage;packages:Map<string,ProtocolPackage>;rawBytes:number};
const digestPattern=/^[a-f0-9]{64}$/;

function fail(message:string):never{throw new Error(`INVALID_PROTOCOL_PACKAGE_CLOSURE: ${message}`);}
function canonicalObject(closure:ProtocolPackageClosure){const packages=Object.fromEntries(Object.entries(closure.packages).sort(([a],[b])=>a<b?-1:a>b?1:0));return {format:PROTOCOL_PACKAGE_CLOSURE_FORMAT,packages,root_package_digest:closure.root_package_digest};}
function decodeBase64url(value:string){try{return decodeCanonicalBase64url(value);}catch{return fail('package bytes are not canonical base64url');}}
function packageValue(value:ProtocolPackage|ProtocolPackageBundle){if(value&&typeof value==='object'&&Object.hasOwn(value,'bundle')){const parsed=parseProtocolPackage((value as ProtocolPackage).bundle);if(parsed.packageDigest!==(value as ProtocolPackage).packageDigest)return fail('parsed package digest mismatch');return parsed;}return parseProtocolPackage(value);}
function assertEnvelope(value:unknown):ProtocolPackageClosure{
 if(!value||typeof value!=='object'||Array.isArray(value))return fail('invalid closure envelope');const obj=value as Record<string,unknown>;
 if(Object.keys(obj).sort().join(',')!=='format,packages,root_package_digest'||obj.format!==PROTOCOL_PACKAGE_CLOSURE_FORMAT||typeof obj.root_package_digest!=='string'||!digestPattern.test(obj.root_package_digest)||!obj.packages||typeof obj.packages!=='object'||Array.isArray(obj.packages))return fail('invalid closure envelope');
 const packages=obj.packages as Record<string,unknown>,entries=Object.entries(packages);if(entries.length===0||entries.length>protocolPackageClosureLimits.entries)return fail('closure package count out of bounds');
 for(const [digest,value]of entries)if(!digestPattern.test(digest)||typeof value!=='string')return fail('invalid package map entry');
 if(!Object.hasOwn(packages,obj.root_package_digest))return fail('root package is missing');return {format:PROTOCOL_PACKAGE_CLOSURE_FORMAT,root_package_digest:obj.root_package_digest,packages:packages as Record<string,string>};
}
function validateClosure(closureValue:unknown):ParsedProtocolPackageClosure{
 const closure=assertEnvelope(closureValue),packages=new Map<string,ProtocolPackage>();let rawBytes=0,steps=0;
 for(const [expectedDigest,encoded]of Object.entries(closure.packages)){const bytes=decodeBase64url(encoded);rawBytes+=bytes.byteLength;if(bytes.byteLength>1024*1024||rawBytes>protocolPackageClosureLimits.rawBytes)return fail('raw package closure byte limit exceeded');let parsed:ProtocolPackage;try{parsed=parseProtocolPackageBytes(bytes);}catch{return fail('contained package is invalid or noncanonical');}if(parsed.packageDigest!==expectedDigest)return fail('package map digest does not match canonical package bytes');packages.set(expectedDigest,parsed);}
 const visited=new Set<string>(),active=new Set<string>();const visit=(digest:string,depth:number)=>{if(depth>protocolPackageClosureLimits.depth)return fail('dependency depth exceeded');if(active.has(digest))return fail('dependency cycle');if(visited.has(digest))return;if(++steps>protocolPackageClosureLimits.compileSteps)return fail('closure compile step limit exceeded');const pkg=packages.get(digest);if(!pkg)return fail(`missing exact package dependency ${digest}`);active.add(digest);for(const dependency of pkg.source.imports)visit(dependency.package_digest,depth+1);active.delete(digest);visited.add(digest);};
 visit(closure.root_package_digest,0);if(visited.size!==packages.size)return fail('closure contains unreferenced packages');
 return {closure,rootPackage:packages.get(closure.root_package_digest)!,packages,rawBytes};
}

export function canonicalProtocolPackageClosureBytes(value:ProtocolPackageClosure):Uint8Array{
 const closure=assertEnvelope(value),bytes=utf8Bytes(JSON.stringify(canonicalObject(closure)));if(bytes.byteLength>protocolPackageClosureLimits.wireBytes)return fail('closure wire byte limit exceeded');validateClosure(closure);return new Uint8Array(bytes);
}
export function parseProtocolPackageClosureBytes(bytes:Uint8Array):ParsedProtocolPackageClosure{
 if(bytes.byteLength>protocolPackageClosureLimits.wireBytes)return fail('closure wire byte limit exceeded');let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return fail('invalid UTF-8 closure');}let parsed:unknown;try{parsed=parseJson(text);}catch{return fail('invalid or duplicate-key JSON closure');}const result=validateClosure(parsed);const canonical=utf8Bytes(JSON.stringify(canonicalObject(result.closure)));if(!equalBytes(canonical,bytes))return fail('closure bytes are not canonical');return result;
}
export function digestProtocolPackageClosure(value:ProtocolPackageClosure){return hash(canonicalProtocolPackageClosureBytes(value));}
export function createProtocolPackageClosure(rootValue:ProtocolPackage|ProtocolPackageBundle,dependencyValues:Array<ProtocolPackage|ProtocolPackageBundle>):ProtocolPackageClosure{
 const root=packageValue(rootValue),packages=new Map<string,ProtocolPackage>([[root.packageDigest,root]]);for(const value of dependencyValues){const pkg=packageValue(value);if(packages.has(pkg.packageDigest))return fail('duplicate package digest');packages.set(pkg.packageDigest,pkg);}
 const encoded:Record<string,string>=Object.create(null);for(const [digest,pkg]of packages)encoded[digest]=encodeBase64url(canonicalProtocolPackageBytes(pkg));const closure={format:PROTOCOL_PACKAGE_CLOSURE_FORMAT,root_package_digest:root.packageDigest,packages:encoded};validateClosure(closure);return closure;
}
export function exactPackageLoader(closure:ParsedProtocolPackageClosure|ProtocolPackageClosure){const parsed='rootPackage' in closure?closure:validateClosure(closure);return (digest:string)=>parsed.packages.get(digest);}
export function packageClosureDigest(value:ProtocolPackage|ProtocolPackageBundle){return packageValue(value).packageDigest;}
