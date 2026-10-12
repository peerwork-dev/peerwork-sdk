/** Versioned workflow rules shared by encrypted readers and readable structural validation. */
import {z} from 'zod';
import type {DeclaredProtectedField} from './workspace-field-protection.js';
import type {StructureRecord,StructureHead} from './workspace-structure-contract.js';

const name=z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/);
const state=z.string().regex(/^[A-Z][A-Z0-9_]{0,39}$/);
const states=z.array(state).min(1).max(32).refine(v=>new Set(v).size===v.length);
export const workflowSchema=z.object({
  v:z.literal(1),status_field:name,parent_field:name,assignee_field:name.optional(),states,
  transitions:z.array(z.object({action:name,from:state.nullable(),to:state}).strict()).min(1).max(64),
  dependencies:z.object({field:name,satisfied_states:states,gated_states:states}).strict().optional(),
  deadline:z.object({field:name,reminder:z.object({lead_ms:z.number().int().min(0).max(30*86_400_000),active_states:states}).strict().optional()}).strict().optional(),
}).strict().superRefine((rule,ctx)=>{
  if(rule.deadline?.reminder&&(!rule.assignee_field||rule.deadline.reminder.active_states.some(s=>!rule.states.includes(s))))ctx.addIssue({code:'custom',message:'deadline reminder requires an assignee and declared active states'});
  const fields=[rule.status_field,rule.parent_field,...(rule.assignee_field?[rule.assignee_field]:[]),...(rule.dependencies?[rule.dependencies.field]:[]),...(rule.deadline?[rule.deadline.field]:[])];
  if(new Set(fields).size!==fields.length)ctx.addIssue({code:'custom',message:'workflow fields must be distinct'});
  if(new Set(rule.transitions.map(t=>JSON.stringify(t))).size!==rule.transitions.length)ctx.addIssue({code:'custom',message:'duplicate workflow transition'});
  if(rule.transitions.some(t=>t.from!==null&&!rule.states.includes(t.from)||!rule.states.includes(t.to))||
    rule.dependencies&&[...rule.dependencies.satisfied_states,...rule.dependencies.gated_states].some(s=>!rule.states.includes(s)))ctx.addIssue({code:'custom',message:'unknown workflow state'});
});
export type WorkflowDefinition=z.infer<typeof workflowSchema>;
function check(condition:unknown,code:string):asserts condition {if(!condition)throw new Error(code);}
export function workflowCriticalFields(rule:WorkflowDefinition) {return [rule.status_field,rule.parent_field,...(rule.dependencies?[rule.dependencies.field]:[])];}
export function workflowReadable(rule:WorkflowDefinition,fields:Record<string,DeclaredProtectedField>) {
  return workflowCriticalFields(rule).every(field=>fields[field]?.protection==='server_readable');
}
export function workflowDeadlineReadable(rule:WorkflowDefinition,fields:Record<string,DeclaredProtectedField>) {
  return Boolean(rule.deadline?.reminder&&rule.assignee_field&&[rule.status_field,rule.assignee_field,rule.deadline.field].every(field=>fields[field]?.protection==='server_readable'));
}
export function workflowForStructure(rule:WorkflowDefinition,fields:Record<string,DeclaredProtectedField>) {
  if(!workflowReadable(rule,fields))return undefined;
  const visible=structuredClone(rule);
  if(visible.deadline&&fields[visible.deadline.field]?.protection!=='server_readable')delete visible.deadline;
  if(visible.assignee_field&&fields[visible.assignee_field]?.protection!=='server_readable')delete visible.assignee_field;
  if(visible.deadline&&!visible.assignee_field)delete visible.deadline.reminder;
  return visible;
}
export function validateWorkflowFields(value:unknown,fields:Record<string,DeclaredProtectedField>|undefined,required:string[]) {
  const rule=workflowSchema.parse(value);check(fields,'WORKFLOW_FIELD_DECLARATIONS_REQUIRED');
  const typed=(field:string,readable:string,stored:string[])=>{
    const value=fields[field];check(value&&required.includes(field),'WORKFLOW_FIELD_REQUIRED');
    check(value.protection==='e2ee'?stored.includes(value.type):value.type===readable,'WORKFLOW_FIELD_TYPE_INVALID');return value;
  };
  const status=typed(rule.status_field,'enum',['string']);
  if(status.protection==='server_readable'&&status.type==='enum')check(JSON.stringify(status.values)===JSON.stringify(rule.states),'WORKFLOW_STATES_MISMATCH');
  typed(rule.parent_field,'optional_reference',['json']);
  if(rule.assignee_field)typed(rule.assignee_field,'optional_actor',['json','string','null']);
  if(rule.dependencies)typed(rule.dependencies.field,'references',['json']);
  if(rule.deadline)typed(rule.deadline.field,'timestamp',['json','integer','null']);
  const readable=workflowCriticalFields(rule).filter(field=>fields[field]!.protection==='server_readable').length;
  check(readable===0||readable===workflowCriticalFields(rule).length,'WORKFLOW_PARTIAL_DISCLOSURE');
  return rule;
}
type Reference={record_id:string;revision:number};
function reference(value:unknown):Reference {
  const p=value as any;
  check(p&&typeof p==='object'&&!Array.isArray(p)&&Object.keys(p).sort().join(',')==='record_id,revision'&&
    typeof p.record_id==='string'&&/^[A-Za-z0-9_-]{43}$/.test(p.record_id)&&Number.isSafeInteger(p.revision)&&p.revision>0,'WORKFLOW_REFERENCE_INVALID');
  return p;
}
function values(rule:WorkflowDefinition,record:StructureRecord) {
  const fields=record.fields,status=fields[rule.status_field],parent=fields[rule.parent_field];
  check(typeof status==='string'&&rule.states.includes(status),'WORKFLOW_STATUS_INVALID');
  if(parent!==null)reference(parent);
  if(rule.deadline){const time=fields[rule.deadline.field];check(time===null||Number.isSafeInteger(time)&&Number(time)>=0,'WORKFLOW_DEADLINE_INVALID');}
  const assignee=rule.assignee_field?fields[rule.assignee_field]:null;
  check(assignee===null||typeof assignee==='string'&&/^[A-Za-z0-9_-]{43}$/.test(assignee),'WORKFLOW_ASSIGNEE_INVALID');
  const dependencies=rule.dependencies?fields[rule.dependencies.field]:[];
  check(Array.isArray(dependencies)&&dependencies.length<=32,'WORKFLOW_DEPENDENCIES_INVALID');
  return {status,assignee,parent:parent===null?null:reference(parent),dependencies:dependencies.map(reference)};
}

/** Dependencies anchor exact records but follow their entities' current selected heads at this commit. */
export function validateWorkflowGraph(rule:WorkflowDefinition,schema:string,instance:string,protocol:string,
  records:Map<string,StructureRecord>,heads:Map<string,StructureHead>) {
  workflowSchema.parse(rule);
  const selected=new Map<string,StructureRecord>();
  for(const head of heads.values()) {
    const record=records.get(head.record_id);
    if(record?.schema_ref===schema&&record.instance_id===instance&&record.protocol_digest===protocol) {
      check(record.entity_id===head.entity_id&&record.revision===head.revision&&head.instance_id===instance,'WORKFLOW_HEAD_INVALID');
      selected.set(record.entity_id,record);
    }
  }
  const edges=new Map<string,string[]>();
  for(const record of selected.values()) {
    const own=values(rule,record),dependencies:string[]=[];
    for(const ref of own.dependencies) {
      const anchor=records.get(ref.record_id);
      check(anchor&&anchor.revision===ref.revision&&anchor.schema_ref===schema&&anchor.instance_id===instance&&anchor.protocol_digest===protocol,'WORKFLOW_DEPENDENCY_SCOPE');
      check(anchor.entity_id!==record.entity_id&&!dependencies.includes(anchor.entity_id),'WORKFLOW_DEPENDENCY_DUPLICATE_OR_SELF');
      const target=selected.get(anchor.entity_id);check(target,'WORKFLOW_DEPENDENCY_HEAD_REQUIRED');
      const targetValues=values(rule,target);
      if(rule.dependencies!.gated_states.includes(own.status))check(rule.dependencies!.satisfied_states.includes(targetValues.status),'WORKFLOW_DEPENDENCY_NOT_SATISFIED');
      dependencies.push(anchor.entity_id);
    }
    edges.set(record.entity_id,dependencies);
  }
  // Iterative DFS: a long, otherwise valid dependency chain must not overflow the JS call stack.
  const done=new Set<string>(),active=new Set<string>();
  for(const start of edges.keys()) {
    if(done.has(start))continue;
    const stack:{id:string;offset:number}[]=[{id:start,offset:0}];active.add(start);
    while(stack.length) {
      const top=stack.at(-1)!,next=edges.get(top.id)![top.offset++];
      if(next===undefined){stack.pop();active.delete(top.id);done.add(top.id);continue;}
      check(!active.has(next),'WORKFLOW_DEPENDENCY_CYCLE');
      if(!done.has(next)){active.add(next);stack.push({id:next,offset:0});}
    }
  }
}

/** Every workflow revision must replace the selected head through a declared transition. */
export function validateWorkflowChange(rule:WorkflowDefinition,schema:string,instance:string,protocol:string,action:string,
  before:Map<string,StructureRecord>,beforeHeads:Map<string,StructureHead>,after:Map<string,StructureRecord>,afterHeads:Map<string,StructureHead>,changes:StructureRecord[],members?:ReadonlySet<string>) {
  const belongs=(record:StructureRecord|undefined)=>record?.schema_ref===schema&&record.instance_id===instance&&record.protocol_digest===protocol;
  // Changing an entity's schema must not make a terminal task disappear from its workflow.
  for(const head of beforeHeads.values())if(belongs(before.get(head.record_id))) {
    const next=afterHeads.get(head.entity_id),target=next&&after.get(next.record_id);
    check(target&&belongs(target)&&target.entity_id===head.entity_id,'WORKFLOW_ENTITY_SCHEMA_CHANGED');
    check(changes.filter(r=>r.entity_id===head.entity_id).every(belongs),'WORKFLOW_ENTITY_SCHEMA_CHANGED');
  }
  for(const record of changes.filter(r=>r.schema_ref===schema&&r.instance_id===instance&&r.protocol_digest===protocol)) {
    const next=values(rule,record),prior=next.parent?before.get(next.parent.record_id):undefined;
    if(next.assignee!==null&&members)check(members.has(next.assignee),'WORKFLOW_ASSIGNEE_NOT_MEMBER');
    check(next.parent?prior&&prior.revision===next.parent.revision&&prior.entity_id===record.entity_id&&prior.schema_ref===schema&&prior.instance_id===instance&&prior.protocol_digest===protocol&&
      beforeHeads.get(record.entity_id)?.record_id===prior.record_id&&record.revision===prior.revision+1:
      record.revision===1&&!beforeHeads.has(record.entity_id),'WORKFLOW_PARENT_INVALID');
    const previous=prior?values(rule,prior).status:null;
    check(rule.transitions.some(t=>t.action===action&&t.from===previous&&t.to===next.status),'WORKFLOW_TRANSITION_INVALID');
    check(afterHeads.get(record.entity_id)?.record_id===record.record_id,'WORKFLOW_REVISION_MUST_BE_HEAD');
  }
  // A head-selection action cannot bypass transition rules by selecting an older workflow record.
  for(const head of afterHeads.values()) {
    const record=after.get(head.record_id),old=beforeHeads.get(head.entity_id);
    if(record?.schema_ref===schema&&record.instance_id===instance&&record.protocol_digest===protocol&&old?.record_id!==head.record_id)
      check(changes.some(r=>r.record_id===head.record_id),'WORKFLOW_HEAD_SELECTION_DENIED');
  }
  validateWorkflowGraph(rule,schema,instance,protocol,after,afterHeads);
}

/** Full decrypted/plaintext rows always enforce workflow semantics, including fields hidden from Control. */
export function validateWorkflowRows(schemas:Record<string,{workflow?:WorkflowDefinition}>,instance:string,protocol:string,action:string,
  beforeRows:Record<string,any>[],afterRows:Record<string,any>[],beforeHeads:StructureHead[],afterHeads:StructureHead[],changedIds:string[],members?:ReadonlySet<string>) {
  if(!Object.values(schemas).some(schema=>schema.workflow))return;
  const records=(rows:Record<string,any>[])=>new Map(rows.map(row=>[String(row.id),{
    record_id:String(row.id),entity_id:String(row.entity_id),revision:Number(row.revision),instance_id:String(row.instance_id),
    protocol_digest:String(row.protocol_digest),schema_ref:String(row.schema_ref),actor_id:String(row.actor_id),created:Number(row.created),
    fields:typeof row.payload==='string'?JSON.parse(row.payload):row.payload,
  } as StructureRecord]));
  const before=records(beforeRows),after=records(afterRows),oldHeads=new Map(beforeHeads.map(head=>[head.entity_id,head])),newHeads=new Map(afterHeads.map(head=>[head.entity_id,head]));
  const changes=changedIds.map(id=>{const record=after.get(id);check(record,'WORKFLOW_RECORD_MISSING');return record;});
  for(const [schema,definition] of Object.entries(schemas))if(definition.workflow)
    validateWorkflowChange(workflowSchema.parse(definition.workflow),schema,instance,protocol,action,before,oldHeads,after,newHeads,changes,members);
}
