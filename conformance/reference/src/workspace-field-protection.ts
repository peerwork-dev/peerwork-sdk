/** Versioned field declarations shared by manifests, Control and readers. */
import {z} from 'zod';
export const privateFieldTypes=['string','integer','boolean','null','json'] as const;
export const readableFieldTypes=['actor','optional_actor','reference','optional_reference','references','timestamp','tokens','task_status','opaque','item_key','digest','counter','work_status','workspace_reference','optional_workspace_reference'] as const;
const enumValue=z.string().regex(/^[A-Z][A-Z0-9_]{0,39}$/);
export const protectedFieldSchema=z.union([
 z.object({protection:z.literal('e2ee'),type:z.enum(privateFieldTypes)}).strict(),
 z.object({protection:z.literal('server_readable'),type:z.enum(readableFieldTypes)}).strict(),
 z.object({protection:z.literal('server_readable'),type:z.literal('enum'),values:z.array(enumValue).min(1).max(32).refine(v=>new Set(v).size===v.length)}).strict(),
]);
export type DeclaredProtectedField=z.infer<typeof protectedFieldSchema>;
export const fieldDeclarationSchema=z.object({v:z.literal(1),fields:z.record(z.string().min(1).max(80),protectedFieldSchema)}).strict();
export function compatibleFieldType(stored:string,rule:DeclaredProtectedField):boolean{
 if(rule.protection==='e2ee')return stored===rule.type;
 if(stored==='json')return true;
 if(['actor','opaque','item_key','digest','task_status','work_status','enum'].includes(rule.type))return stored==='string';
 if(rule.type==='optional_actor')return stored==='string'||stored==='null';
 if(rule.type==='timestamp')return stored==='integer'||stored==='null';
 return rule.type==='counter'&&stored==='integer';
}
