/** Typed coordination statements and service delivery observations are separate. */
import type {StructureRecord} from './workspace-structure-contract.js';
export type CoordinationPolicy={v:1|2;instance_id:string;protocol_digest:string;coordinator:string;initial_delay_ms:number;max_delay_ms:number;escalate_after:number;window_ms:number;workspace_limit:number;sender_limit:number;recipient_limit:number};
export type CoordinationReference={record_id:string;revision:number};
export type CoordinationEvidence={record_id:string;commit_hash:string;sequence:number;author:string};
export type CoordinationWork='PENDING'|'IN_PROGRESS'|'WAITING_FOR_INPUT'|'DEFERRED'|'HANDLED'|'DECLINED';
export type CoordinationItem={
 id:string;workspace_id:string;sender:string;recipient:string;source:CoordinationReference;source_hash:string;source_sequence:number;created:number;reasons:('MENTION'|'REPLY'|'ASSIGNMENT'|'TASK_UPDATE'|'DEADLINE')[];
 schedule?:{kind:'DEADLINE';not_before:number;due_at:number;entity_id:string;instance_id:string};
 lifecycle:'ACTIVE'|'CANCELLED'|'ACCESS_REVOKED'|'SOURCE_EXCLUDED'|'SUPERSEDED'|'POLICY_DISABLED';ack:CoordinationEvidence|null;work:CoordinationWork;version:number;disposition:CoordinationEvidence|null;defer_until:number|null;result:CoordinationReference|null;cancel:CoordinationEvidence|null;
};
export type CoordinationState={items:Map<string,CoordinationItem>;records:Map<string,StructureRecord>};
export const emptyCoordinationState=():CoordinationState=>({items:new Map(),records:new Map()});
export function defaultCoordinationPolicy(instance_id:string,protocol_digest:string,coordinator:string,v:1|2=1):CoordinationPolicy{return {v,instance_id,protocol_digest,coordinator,initial_delay_ms:60_000,max_delay_ms:3_600_000,escalate_after:5,window_ms:60_000,workspace_limit:60,sender_limit:10,recipient_limit:10};}
export function validateCoordinationPolicy(value:CoordinationPolicy):void{
 const fields=['v','instance_id','protocol_digest','coordinator','initial_delay_ms','max_delay_ms','escalate_after','window_ms','workspace_limit','sender_limit','recipient_limit'];
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length||fields.some(k=>!Object.hasOwn(value,k))||![1,2].includes(value.v)||![value.instance_id,value.coordinator].every(x=>/^[A-Za-z0-9_-]{43}$/.test(x))||!/^[a-f0-9]{64}$/.test(value.protocol_digest))throw new Error('COORDINATION_POLICY_INVALID');
 for(const key of ['initial_delay_ms','max_delay_ms','escalate_after','window_ms','workspace_limit','sender_limit','recipient_limit'] as const)if(!Number.isSafeInteger(value[key])||value[key]<1)throw new Error('COORDINATION_POLICY_INVALID');
 if(value.initial_delay_ms<1000||value.max_delay_ms<value.initial_delay_ms||value.max_delay_ms>86_400_000||value.escalate_after>100||value.window_ms<1000||value.window_ms>3_600_000||value.workspace_limit>1000||value.sender_limit>value.workspace_limit||value.recipient_limit>value.workspace_limit)throw new Error('COORDINATION_POLICY_INVALID');
}

export type CoordinationDelivery={attempts:number;last_attempt:number|null;next_retry:number|null;escalated_at:number|null;suppression:null|"IDENTITY_CLOSED"|"ACCESS_REVOKED";observed_at:number};

export const coordinationItemKey=/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}(?:\.deadline)?$/;
export function coordinationAvailable(item:CoordinationItem,at:number,scheduled=false){return scheduled||item.lifecycle!=='ACTIVE'||!item.schedule||item.schedule.not_before<=at;}

export type CoordinationFilter={after?:string;limit?:number;outbox?:boolean;closed?:boolean;coordinator?:boolean;as_of?:number;scheduled?:boolean};
export const coordinationFilterKeys=['after','limit','outbox','closed','coordinator','as_of','scheduled'];
export function validateCoordinationFilterShape(filter:CoordinationFilter){
 if(!filter||typeof filter!=='object'||Array.isArray(filter)||!Number.isSafeInteger(filter.limit??50)||(filter.limit??50)<1||(filter.limit??50)>100||Object.keys(filter).some(k=>!coordinationFilterKeys.includes(k))||['outbox','closed','coordinator','scheduled'].some(k=>(filter as any)[k]!==undefined&&typeof (filter as any)[k]!=='boolean')||filter.after!==undefined&&(typeof filter.after!=='string'||!coordinationItemKey.test(filter.after))||filter.as_of!==undefined&&(!Number.isSafeInteger(filter.as_of)||filter.as_of<0)||filter.coordinator&&filter.outbox)throw new Error('COORDINATION_FILTER_INVALID');
}
export function coordinationFilterFromParams(params:URLSearchParams):CoordinationFilter{
 const result:CoordinationFilter={limit:50},seen=new Set<string>();
 for(const [key,value] of params){
  if(!coordinationFilterKeys.includes(key)||seen.has(key))throw new Error('COORDINATION_FILTER_INVALID');seen.add(key);
  if(key==='limit'||key==='as_of'){if(!/^(0|[1-9][0-9]*)$/.test(value))throw new Error('COORDINATION_FILTER_INVALID');(result as any)[key]=Number(value);}
  else if(key==='after')result.after=value;
  else {if(!['true','false'].includes(value))throw new Error('COORDINATION_FILTER_INVALID');(result as any)[key]=value==='true';}
 }
 validateCoordinationFilterShape(result);return result;
}
