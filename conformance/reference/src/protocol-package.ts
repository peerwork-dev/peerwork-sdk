import {z} from 'zod';
import {parseJson} from './json.js';
import {manifestSchema,SEMANTICS} from './workspace-manifest.js';
import {equalBytes,hash,utf8Bytes,utf8ByteLength} from './protocol-package-runtime.js';
import {guardSchema} from './workspace-interpreter.js';

export const PROTOCOL_PACKAGE_FORMAT='peerwork.protocol-package.v1' as const;
export const PROTOCOL_SOURCE_FORMAT='peerwork.protocol-source.v1' as const;
export const PROTOCOL_SOURCE_FORMAT_V2='peerwork.protocol-source.v2' as const;
export const PROTOCOL_METADATA_FORMAT='peerwork.protocol-package-metadata.v1' as const;
export const PROTOCOL_LOCK_FORMAT='peerwork.protocol-lock.v1' as const;
export const PROTOCOL_COMPILER_VERSION='peerwork.protocol-compiler.v1';
export const PROTOCOL_COMPILER_VERSION_V2='peerwork.protocol-compiler.v2';
export const PROTOCOL_COMPILER_VERSION_V3='peerwork.protocol-compiler.v3';
export const packageLimits=Object.freeze({bytes:1024*1024,files:64,fileBytes:256*1024,pathDepth:8,dependencies:16,fixtures:64,nodes:8192});

const packageId=z.string().min(1).max(80).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
const packageVersion=z.string().min(1).max(80).regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
const digestSchema=z.string().regex(/^[a-f0-9]{64}$/);
const safeRelativePath=z.string().min(1).max(200).refine(value=>{
 if(!/^[A-Za-z0-9._/-]+$/.test(value)||value!==value.normalize('NFC')||value.includes('\\')||value.startsWith('/')||/^[A-Za-z]:/.test(value)||value.includes('\0'))return false;
 const parts=value.split('/');return parts.length<=packageLimits.pathDepth&&parts.every(part=>part!==''&&part!=='.'&&part!=='..'&&part===part.trim()&&!['__proto__','prototype','constructor'].includes(part));
},'unsafe package path');
const sourceMaintainerSchema=z.object({name:z.string().min(1).max(120),origin:z.string().min(1).max(240).optional()}).strict();
const packageMetadataSchema=z.object({
 format:z.literal(PROTOCOL_METADATA_FORMAT),package_id:packageId,version:packageVersion,name:z.string().min(1).max(120),
 description:z.string().min(1).max(4000),license:z.string().min(1).max(100).regex(/^[A-Za-z0-9.+-]+$/),
 license_file:safeRelativePath,source_maintainers:z.array(sourceMaintainerSchema).min(1).max(16),
}).strict();
const bindingTargetSchema=z.object({kind:z.literal('protocol_role_guard'),action_id:z.string().min(1).max(120),variant_index:z.number().int().nonnegative().max(31),guard_index:z.number().int().nonnegative().max(31),conflict_role:z.string().min(1).max(80).optional()}).strict();
const parameterSchema=z.object({name:z.string().min(1).max(80).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),type:z.enum(['string','enum','integer','boolean']),values:z.array(z.string().min(1).max(120)).min(1).max(32).optional(),minimum:z.number().int().optional(),maximum:z.number().int().optional(),default:z.unknown().optional(),required:z.boolean().default(false),binding:bindingTargetSchema.optional()}).strict().superRefine((value,ctx)=>{
 if(value.type==='enum'&&!value.values)ctx.addIssue({code:'custom',message:'enum requires values'});
 if(value.type!=='enum'&&value.values)ctx.addIssue({code:'custom',message:'values are only valid for enum'});
 if(value.type==='integer'&&((value.minimum!==undefined&&value.maximum!==undefined&&value.minimum>value.maximum)||(value.minimum!==undefined&&!Number.isSafeInteger(value.minimum))||(value.maximum!==undefined&&!Number.isSafeInteger(value.maximum))))ctx.addIssue({code:'custom',message:'invalid integer range'});
 if(value.type!=='integer'&&(value.minimum!==undefined||value.maximum!==undefined))ctx.addIssue({code:'custom',message:'integer bounds on non-integer parameter'});
});
const importSchema=z.object({alias:z.string().min(1).max(40).regex(/^[a-z][a-z0-9_-]*$/),package_digest:digestSchema,namespace:z.string().min(1).max(32).regex(/^[A-Za-z][A-Za-z0-9_-]*$/)}).strict();
const exportSchema=z.object({slot:z.string().min(1).max(120).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),parameter:z.string().min(1).max(80)}).strict();
const parentBindingSchema=z.object({parameter:z.string().min(1).max(80),import_alias:z.string().min(1).max(40),slot:z.string().min(1).max(120)}).strict();
const derivationSchema=z.object({op:z.literal('add_constraint'),action_id:z.string().min(1).max(120).refine(value=>!['__proto__','prototype','constructor'].includes(value)),guard:guardSchema}).strict();
const interfaceOutputSchema=z.union([
 z.object({name:z.string().min(1).max(120).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),type:z.literal('exact_ref'),schema:z.string().min(1).max(80),scope:z.enum(['INSTANCE','WORKSPACE']),selector:z.union([z.object({from:z.literal('state'),path:z.array(z.string().min(1).max(80)).min(1).max(12)}).strict(),z.object({from:z.literal('import'),alias:z.string().min(1).max(40),output:z.string().min(1).max(120)}).strict()]),available_when:guardSchema}).strict(),
 z.object({name:z.string().min(1).max(120).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),type:z.literal('actor_id'),selector:z.union([z.object({from:z.literal('state'),path:z.array(z.string().min(1).max(80)).min(1).max(12)}).strict(),z.object({from:z.literal('import'),alias:z.string().min(1).max(40),output:z.string().min(1).max(120)}).strict()]),available_when:guardSchema}).strict(),
]);
const sourceActionInputField=z.union([
 z.object({type:z.literal('string'),maxBytes:z.number().int().positive().max(8192).optional(),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('integer'),minimum:z.number().int().safe().optional(),maximum:z.number().int().safe().optional(),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('boolean'),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('enum'),values:z.array(z.string().min(1).max(8192)).min(1).max(64),nullable:z.boolean().optional()}).strict(),
 z.object({type:z.literal('actor_id'),input:z.string().min(1).max(120)}).strict(),
 z.object({type:z.literal('exact_ref'),input:z.string().min(1).max(120),scope:z.enum(['INSTANCE','WORKSPACE'])}).strict(),
 z.object({type:z.literal('exact_ref'),schema:z.string().min(1).max(80),scope:z.enum(['INSTANCE','WORKSPACE'])}).strict(),
]);
const actionBodySchema=z.object({fields:z.record(z.string().min(1).max(80),sourceActionInputField),required:z.array(z.string().min(1).max(80)).max(32),additionalProperties:z.boolean()}).strict();
const interfaceInputSchema=z.union([
 z.object({action:z.string().min(1).max(120),variant:z.number().int().nonnegative().max(31),name:z.string().min(1).max(120).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),type:z.literal('exact_ref'),scope:z.enum(['INSTANCE','WORKSPACE']),body_path:z.array(z.string().min(1).max(80)).length(1),required:z.boolean(),action_body:actionBodySchema,provenance_hook:z.object({record_slot:z.string().min(1).max(80),record_schema:z.string().min(1).max(80),relation_kind:z.string().min(1).max(80),target_input:z.string().min(1).max(120)}).strict().optional()}).strict(),
 z.object({action:z.string().min(1).max(120),variant:z.number().int().nonnegative().max(31),name:z.string().min(1).max(120).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),type:z.literal('actor_id'),relation:z.enum(['same_actor','different_actor']),body_path:z.array(z.string().min(1).max(80)).length(1),required:z.boolean(),action_body:actionBodySchema}).strict(),
]);
const actionBodyContractSchema=z.object({action:z.string().min(1).max(120),body:actionBodySchema}).strict();
const interfacesSchema=z.object({outputs:z.array(interfaceOutputSchema).max(32).default([]),inputs:z.array(interfaceInputSchema).max(32).default([]),action_bodies:z.array(actionBodyContractSchema).max(64).default([])}).strict();
const connectionSchema=z.object({from:z.object({import:z.string().min(1).max(40),output:z.string().min(1).max(120)}).strict(),to:z.object({import:z.string().min(1).max(40),action:z.string().min(1).max(120),variant:z.number().int().nonnegative().max(31),input:z.string().min(1).max(120)}).strict()}).strict();
const roleMappingSchema=z.object({from:z.object({import:z.string().min(1).max(40),role:z.string().min(1).max(80)}).strict(),to:z.string().min(1).max(80)}).strict();
const capabilityMappingSchema=z.object({from:z.object({import:z.string().min(1).max(40),capability:z.string().min(1).max(120)}).strict(),to:z.string().min(1).max(120)}).strict();
const fixtureDispositionSchema=z.object({origin:z.object({package_digest:digestSchema,import_path:z.array(z.string().min(1).max(40).regex(/^[a-z][a-z0-9_-]*$/)).max(packageLimits.dependencies),fixture_id:z.string().min(1).max(80).regex(/^[A-Za-z0-9_.-]+$/)}).strict(),expected_rejection:z.string().min(1).max(80),rationale:z.string().min(1).max(1000),replacement_scenario_id:z.string().min(1).max(120)}).strict();
export const protocolSourceSchema=z.object({
 format:z.enum([PROTOCOL_SOURCE_FORMAT,PROTOCOL_SOURCE_FORMAT_V2]),semantics:z.literal(SEMANTICS),manifest:manifestSchema,
 imports:z.array(importSchema).max(packageLimits.dependencies).default([]),parameters:z.array(parameterSchema).max(32).default([]),
 exports:z.array(exportSchema).max(32).default([]),bindings:z.array(parentBindingSchema).max(32).default([]),derive:z.array(derivationSchema).max(32).default([]),
 interfaces:interfacesSchema.optional(),connections:z.array(connectionSchema).max(64).optional(),role_mappings:z.array(roleMappingSchema).max(64).optional(),capability_mappings:z.array(capabilityMappingSchema).max(64).optional(),fixture_dispositions:z.array(fixtureDispositionSchema).max(packageLimits.fixtures).optional(),
}).strict().superRefine((value,ctx)=>{
 const names=new Set<string>();for(const parameter of value.parameters){if(names.has(parameter.name))ctx.addIssue({code:'custom',message:'duplicate parameter'});names.add(parameter.name);}
 const aliases=new Set<string>();for(const imported of value.imports){if(aliases.has(imported.alias))ctx.addIssue({code:'custom',message:'duplicate import alias'});aliases.add(imported.alias);}
 const slots=new Set<string>();for(const item of value.exports){if(slots.has(item.slot))ctx.addIssue({code:'custom',message:'duplicate exported slot'});slots.add(item.slot);if(!names.has(item.parameter))ctx.addIssue({code:'custom',message:'export references unknown parameter'});}
 for(const parameter of value.parameters)if(!parameter.binding&&!value.exports.some(item=>item.parameter===parameter.name))ctx.addIssue({code:'custom',message:'parameter needs a local binding or exported slot'});
 const targets=new Set<string>();for(const binding of value.bindings){if(!names.has(binding.parameter))ctx.addIssue({code:'custom',message:'binding references unknown parameter'});if(!aliases.has(binding.import_alias))ctx.addIssue({code:'custom',message:'binding references unknown import'});const target=`${binding.import_alias}\0${binding.slot}`;if(targets.has(target))ctx.addIssue({code:'custom',message:'duplicate imported slot binding'});targets.add(target);}
 if(value.format===PROTOCOL_SOURCE_FORMAT&&(value.interfaces!==undefined||value.connections!==undefined||value.role_mappings!==undefined||value.capability_mappings!==undefined||value.fixture_dispositions!==undefined))ctx.addIssue({code:'custom',message:'composition extensions require protocol-source.v2'});
 if(value.format===PROTOCOL_SOURCE_FORMAT_V2&&!value.interfaces)ctx.addIssue({code:'custom',message:'protocol-source.v2 requires interfaces'});
 if(value.format===PROTOCOL_SOURCE_FORMAT_V2){const outputNames=new Set<string>();for(const output of value.interfaces?.outputs??[]){if(outputNames.has(output.name))ctx.addIssue({code:'custom',message:'duplicate interface output'});outputNames.add(output.name);}const bodyActions=new Set<string>();for(const contract of value.interfaces?.action_bodies??[]){if(bodyActions.has(contract.action))ctx.addIssue({code:'custom',message:'duplicate action body contract'});bodyActions.add(contract.action);if(!value.manifest.actions.some(action=>action.id===contract.action))ctx.addIssue({code:'custom',message:'action body contract targets an unknown local action'});for(const name of contract.body.required)if(!Object.hasOwn(contract.body.fields,name))ctx.addIssue({code:'custom',message:'action body required field is undeclared'});}const inputNames=new Set<string>();for(const input of value.interfaces?.inputs??[]){if(inputNames.has(input.name))ctx.addIssue({code:'custom',message:'duplicate interface input'});inputNames.add(input.name);if(!Object.hasOwn(input.action_body.fields,input.body_path[0]!))ctx.addIssue({code:'custom',message:'interface body path must name a declared top-level field'});const inputField=input.action_body.fields[input.body_path[0]!];if(input.type==='exact_ref'&&(inputField?.type!=='exact_ref'||!('input'in inputField)||inputField.input!==input.name))ctx.addIssue({code:'custom',message:'interface input must bind its declared exact-ref body field'});if(input.type==='actor_id'&&(inputField?.type!=='actor_id'||inputField.input!==input.name))ctx.addIssue({code:'custom',message:'interface input must bind its declared actor-id body field'});if(input.type==='exact_ref'&&input.provenance_hook&&input.provenance_hook.target_input!==input.name)ctx.addIssue({code:'custom',message:'provenance hook must name its interface input'});}
  const dispositionOrigins=new Set<string>();for(const disposition of value.fixture_dispositions??[]){const key=`${disposition.origin.package_digest}\0${disposition.origin.import_path.join('/') }\0${disposition.origin.fixture_id}`;if(dispositionOrigins.has(key))ctx.addIssue({code:'custom',message:'duplicate fixture disposition origin'});dispositionOrigins.add(key);}
  const targetPorts=new Set<string>();for(const input of value.interfaces?.inputs??[]){const action=value.manifest.actions.find(item=>item.id===input.action);if(!action||!action.variants[input.variant])ctx.addIssue({code:'custom',message:'interface input targets an unknown local action variant'});const field=input.action_body.fields[input.body_path[0]!];if(input.required!==input.action_body.required.includes(input.body_path[0]!))ctx.addIssue({code:'custom',message:'interface required flag differs from full action body schema'});if(input.type==='exact_ref'&&field?.type==='exact_ref'&&'input'in field&&field.scope!==input.scope)ctx.addIssue({code:'custom',message:'interface input scope differs from body field'});}
  for(const output of value.interfaces?.outputs??[]){if(output.type==='exact_ref'&&output.selector.from==='state'&&!Object.hasOwn(value.manifest.record_schemas,output.schema))ctx.addIssue({code:'custom',message:'interface output references unknown local record schema'});if(output.selector.from==='state'){let current:unknown=value.manifest.initial_state;for(const segment of output.selector.path){if(!current||typeof current!=='object'||Array.isArray(current)||!Object.hasOwn(current,segment)){ctx.addIssue({code:'custom',message:'interface output path is not in declared initial state'});break;}current=(current as Record<string,unknown>)[segment];}}else if(!aliases.has(output.selector.alias))ctx.addIssue({code:'custom',message:'forwarded interface output references unknown import'});}
  for(const connection of value.connections??[]){if(!aliases.has(connection.from.import)||!aliases.has(connection.to.import))ctx.addIssue({code:'custom',message:'connection references unknown import'});const target=`${connection.to.import}\0${connection.to.action}\0${connection.to.variant}\0${connection.to.input}`;if(targetPorts.has(target))ctx.addIssue({code:'custom',message:'interface input is connected more than once'});targetPorts.add(target);}
  for(const mapping of [...(value.role_mappings??[]),...(value.capability_mappings??[])])if(!aliases.has(mapping.from.import))ctx.addIssue({code:'custom',message:'symbol mapping references unknown import'});
 }
 if(value.manifest.dependencies.length)ctx.addIssue({code:'custom',message:'source manifest dependencies must be expressed as exact package imports'});
 if(value.manifest.execution_requirements)ctx.addIssue({code:'custom',message:'execution requirements are compiler-owned runtime metadata'});
});
const fixtureAuthSchema=z.object({actorId:z.string().regex(/^[A-Za-z0-9_-]{43}$/),workspaceRoles:z.array(z.string()).max(64).default([]),protocolRoles:z.array(z.string()).max(64).default([]),capabilities:z.array(z.string()).max(64).default([])}).strict();
const fixtureInputSchema=z.object({recordId:z.string().regex(/^[A-Za-z0-9_-]{43}$/),revision:z.number().int().positive(),schema:z.string().min(1).max(80),payload:z.unknown(),scope:z.enum(['INSTANCE','WORKSPACE']),entityId:z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional()}).strict();
const fixtureExpectedSchema=z.union([
 z.object({accepted:z.literal(true),state:z.unknown().optional(),records:z.unknown().optional(),headSelections:z.unknown().optional(),revisionEffects:z.unknown().optional(),evaluated_at:z.number().int().nonnegative().safe().optional()}).strict(),
 z.object({accepted:z.literal(false),code:z.string().min(1).max(80)}).strict(),
]);
const singleProtocolFixtureSchema=z.object({id:z.string().min(1).max(80).regex(/^[A-Za-z0-9_.-]+$/),action_id:z.string().min(1).max(120),state:z.unknown(),body:z.unknown(),auth:fixtureAuthSchema,exact_inputs:z.array(fixtureInputSchema).max(32).default([]),time_ms:z.number().int().nonnegative().safe().optional(),expected:fixtureExpectedSchema}).strict();
const fixtureSequenceStepSchema=z.object({action_id:z.string().min(1).max(120),body:z.unknown(),auth:fixtureAuthSchema,exact_inputs:z.array(z.string().min(1).max(80).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/)).max(32).default([]),bind_refs:z.array(z.object({name:z.string().min(1).max(80).regex(/^[A-Za-z][A-Za-z0-9_.-]*$/),record_slot:z.string().min(1).max(80)}).strict()).max(32).default([]),time_ms:z.number().int().nonnegative().safe().optional(),expected:fixtureExpectedSchema}).strict();
const sequenceProtocolFixtureSchema=z.object({kind:z.literal('sequence'),id:z.string().min(1).max(80).regex(/^[A-Za-z0-9_.-]+$/),state:z.unknown(),steps:z.array(fixtureSequenceStepSchema).min(1).max(32)}).strict().superRefine((fixture,ctx)=>{const names=new Set<string>();for(const step of fixture.steps){for(const name of step.exact_inputs)if(!names.has(name))ctx.addIssue({code:'custom',message:'sequence exact input refers to an unbound reference'});for(const binding of step.bind_refs){if(names.has(binding.name))ctx.addIssue({code:'custom',message:'duplicate sequence reference binding'});names.add(binding.name);}}});
export const protocolFixtureSchema=z.union([singleProtocolFixtureSchema,sequenceProtocolFixtureSchema]);
export type ProtocolFixture=z.infer<typeof protocolFixtureSchema>;
const releaseLockSchema=z.object({format:z.literal(PROTOCOL_LOCK_FORMAT),compiler_version:z.string().min(1).max(80),semantics:z.literal(SEMANTICS),dependencies:z.array(z.object({alias:z.string().min(1).max(40),package_digest:digestSchema,namespace:z.string().min(1).max(32)}).strict()).max(packageLimits.dependencies),baseline_bindings:z.record(z.string().min(1).max(80),z.unknown()),output_protocol_digest:digestSchema}).strict();
const bundleSchema=z.object({format:z.literal(PROTOCOL_PACKAGE_FORMAT),files:z.record(safeRelativePath,z.string())}).strict();
export type ProtocolPackageBundle=z.infer<typeof bundleSchema>;
export type ProtocolPackage={bundle:ProtocolPackageBundle;packageDigest:string;metadata:z.infer<typeof packageMetadataSchema>;source:z.infer<typeof protocolSourceSchema>;lock:z.infer<typeof releaseLockSchema>;fixtures:ProtocolFixture[]};
export type ProtocolPackageMetadata=z.infer<typeof packageMetadataSchema>;
export type ProtocolSource=z.infer<typeof protocolSourceSchema>;
export type ProtocolReleaseLock=z.infer<typeof releaseLockSchema>;
export type PackageInspection={packageId:string;version:string;name:string;description:string;license:string;licenseFile:string;sourceMaintainers:{name:string;origin?:string}[];fileCount:number;totalBytes:number;imports:{alias:string;packageDigest:string;namespace:string}[];fixtureIds:string[]};

function fail(message:string):never{throw new Error(`INVALID_PROTOCOL_PACKAGE: ${message}`);}
function assertSafeJsonKeys(value:unknown,path:string,depth=0,nodes={value:0}){if(++nodes.value>packageLimits.nodes||depth>32)fail(`JSON complexity limit exceeded in ${path}`);if(Array.isArray(value)){for(const item of value)assertSafeJsonKeys(item,path,depth+1,nodes);return;}if(value&&typeof value==='object')for(const key of Object.keys(value)){if(['__proto__','prototype','constructor'].includes(key))fail(`unsafe object key in ${path}`);assertSafeJsonKeys((value as Record<string,unknown>)[key],path,depth+1,nodes);}}
function safeParseFile<T>(text:string,parser:(value:unknown)=>T,path:string):T{let value:unknown;try{value=parseJson(text);assertSafeJsonKeys(value,path);}catch{return fail(`invalid or unsafe JSON in ${path}`);}try{return parser(value);}catch{return fail(`invalid content in ${path}`);}}
function assertUtf8(text:string,path:string){const bytes=utf8Bytes(text);if(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)!==text)fail(`invalid UTF-8 text in ${path}`);if(bytes.byteLength>packageLimits.fileBytes)fail(`file too large: ${path}`);}
function canonicalBundleBytes(bundle:ProtocolPackageBundle){const files=Object.fromEntries(Object.entries(bundle.files).sort(([a],[b])=>a<b?-1:a>b?1:0));return utf8Bytes(JSON.stringify({format:bundle.format,files}));}

export function parseProtocolPackage(value:unknown):ProtocolPackage{
 let bundle:ProtocolPackageBundle;try{assertSafeJsonKeys(value,'bundle');bundle=bundleSchema.parse(value);}catch{return fail('invalid or unsafe bundle envelope');}
 const entries=Object.entries(bundle.files);if(entries.length>packageLimits.files)fail('too many files');
 for(const [path,text] of entries){safeRelativePath.parse(path);assertUtf8(text,path);}
 const bytes=canonicalBundleBytes(bundle);if(bytes.byteLength>packageLimits.bytes)fail('bundle exceeds byte limit');
 const required=['package.json','protocol.source.json','release.lock.json','README.md','LICENSE'];for(const path of required)if(!Object.hasOwn(bundle.files,path))fail(`missing required file ${path}`);
 const metadata=safeParseFile(bundle.files['package.json']!,v=>packageMetadataSchema.parse(v),'package.json');
 if(metadata.license_file!=='LICENSE'&&!Object.hasOwn(bundle.files,metadata.license_file))fail('license file is missing');
 const source=safeParseFile(bundle.files['protocol.source.json']!,v=>protocolSourceSchema.parse(v),'protocol.source.json');
 const lock=safeParseFile(bundle.files['release.lock.json']!,v=>releaseLockSchema.parse(v),'release.lock.json');
 if(lock.dependencies.length!==source.imports.length||source.imports.some((entry,index)=>{const locked=lock.dependencies.find(item=>item.alias===entry.alias);return !locked||locked.package_digest!==entry.package_digest||locked.namespace!==entry.namespace||index<0;}))fail('source imports differ from exact dependency lock');
 const fixtures=entries.filter(([path])=>path.startsWith('fixtures/')&&path.endsWith('.json')).map(([path,text])=>safeParseFile(text,v=>protocolFixtureSchema.parse(v),path));
 if(fixtures.length===0||fixtures.length>packageLimits.fixtures)fail('fixture count out of bounds');
 if(new Set(fixtures.map(item=>item.id)).size!==fixtures.length)fail('duplicate fixture ID');
 const parsed={bundle,packageDigest:hash(bytes),metadata,source,lock,fixtures};
 return parsed;
}

export function parseProtocolPackageBytes(bytes:Uint8Array):ProtocolPackage{
 if(bytes.byteLength>packageLimits.bytes)fail('bundle exceeds byte limit');let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return fail('invalid UTF-8 bundle');}
 let value:unknown;try{value=parseJson(text);}catch{return fail('invalid JSON bundle');}const parsed=parseProtocolPackage(value);if(!equalBytes(canonicalBundleBytes(parsed.bundle),bytes))fail('bundle bytes are not canonical');return parsed;
}

export function canonicalProtocolPackageBytes(value:ProtocolPackage|ProtocolPackageBundle):Uint8Array{
 const parsed='packageDigest' in value?value.bundle:bundleSchema.parse(value);const bytes=canonicalBundleBytes(parsed);if(bytes.byteLength>packageLimits.bytes)fail('bundle exceeds byte limit');return new Uint8Array(bytes);
}
export function digestProtocolPackage(value:ProtocolPackage|ProtocolPackageBundle){return hash(canonicalProtocolPackageBytes(value));}
export function inspectProtocolPackage(value:unknown):PackageInspection{
 const pkg=parseProtocolPackage(value),files=Object.values(pkg.bundle.files),totalBytes=files.reduce((sum,text)=>sum+utf8ByteLength(text),0);
 return {packageId:pkg.metadata.package_id,version:pkg.metadata.version,name:pkg.metadata.name,description:pkg.metadata.description,license:pkg.metadata.license,licenseFile:pkg.metadata.license_file,sourceMaintainers:pkg.metadata.source_maintainers,fileCount:files.length,totalBytes,imports:pkg.source.imports.map(({alias,package_digest,namespace})=>({alias,packageDigest:package_digest,namespace})),fixtureIds:pkg.fixtures.map(f=>f.id)};
}
