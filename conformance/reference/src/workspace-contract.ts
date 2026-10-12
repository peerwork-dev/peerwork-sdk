import {createHash} from 'node:crypto';
import {z} from 'zod';
import {ApiError} from './errors.js';
import {SEMANTICS,limits,token,digest,jsonValue,normalized,canonical,manifestCanonical} from './workspace-manifest.js';
export {SEMANTICS,limits,token,digest,manifestSchema,canonical,canonicalResponse,canonicalCommand,canonicalStructured,type Manifest} from './workspace-manifest.js';

export const CONTROL_APPLICATION_ID=0x50574b31;
export const PUBLIC_APPLICATION_ID=0x50575031;
export const CONTROL_DATABASE_VERSION=9;
export const PUBLIC_DATABASE_VERSION=1;
export const COMMAND_TYPE='peerwork.kernel-command.v1+jws';
export const RECEIPT_TYPE='peerwork.kernel-receipt.v1+jws';
export const READ_TYPE='peerwork.kernel-read.v1+jws';
export const exactRef=z.object({record_id:token,revision:z.number().int().positive()}).strict();
export const commandSchema=z.object({
 v:z.literal(1),audience:z.string().min(1).max(200),command_id:token,actor_id:token,authority:digest,
 method:z.literal('POST'),path:z.string().regex(/^\/api\/workspace\/v1\/(?:commands|catalog\/upload|private\/packages\/upload|browser\/sessions\/[A-Za-z0-9_-]{43}\/commands)$/),
 workspace_id:token.nullable(),instance_id:token.nullable(),protocol_digest:digest.nullable(),
 action_id:z.string().min(1).max(120),expected_workspace_revision:z.number().int().nonnegative().nullable(),expected_instance_revision:z.number().int().nonnegative().nullable(),
 exact_input_refs:z.array(exactRef).max(limits.refs),body:jsonValue,
 issued_at:z.number().int().nonnegative(),expires_at:z.number().int().positive(),
}).strict().superRefine((value,ctx)=>{try{if(['protocol.publish','admin.draft.create','admin.draft.update','protocol.package.derive.preview'].includes(value.action_id))normalized(value.body,0,{n:0},32);else canonical(value.body);}catch{ctx.addIssue({code:'custom',message:'invalid body bounds'});}});
export type KernelCommand=z.infer<typeof commandSchema>;

const pathSegment=z.string().min(1).max(80).refine(v=>!['__proto__','prototype','constructor'].includes(v));
const operand=z.union([
 z.object({source:z.literal('state'),path:z.array(pathSegment).min(1).max(limits.depth)}).strict(),
 z.object({source:z.literal('body'),path:z.array(pathSegment).max(limits.depth)}).strict(),
 z.object({source:z.literal('literal'),value:jsonValue}).strict(),
]);
const guard:z.ZodType<any>=z.lazy(()=>z.union([
 z.object({op:z.literal('eq'),left:operand,right:operand}).strict(),
 z.object({op:z.literal('in'),value:operand,set:z.array(jsonValue).max(limits.listItems)}).strict(),
 z.object({op:z.literal('state_eq'),path:z.array(pathSegment).min(1).max(limits.depth),value:jsonValue}).strict(),
 z.object({op:z.literal('exact_ref'),record_id:token,revision:z.number().int().positive()}).strict(),
 z.object({op:z.enum(['and','or']),rules:z.array(guard).min(1).max(limits.guards)}).strict(),
 z.object({op:z.literal('not'),rule:guard}).strict(),
]));
const effect=z.union([
 z.object({op:z.literal('set'),path:z.array(pathSegment).min(1).max(limits.depth),value:operand}).strict(),
 z.object({op:z.literal('append'),schema:z.string().min(1).max(80),value:operand}).strict(),
]);

export function hash(value:string|Uint8Array){return createHash('sha256').update(value).digest('hex');}
export function manifestDigest(value:unknown){const result=manifestCanonical(value);return {...result,digest:hash(result.canonical)};}
export function assertSized(value:unknown,max:number,code='RESOURCE_EXHAUSTED'){
 const encoded=canonical(value);if(Buffer.byteLength(encoded)>max)throw new ApiError(code,code==='INVALID_PAYLOAD'?400:429);return encoded;
}
