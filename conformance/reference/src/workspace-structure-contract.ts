import type {CoordinationPolicy} from './workspace-coordination-contract.js';
/** The readable contract contains types and state rules, never private protocol prose. */
import type {SecureCheckpoint,SecureJson} from './workspace-secure-contract.js';

export type ProtectedField=import('./workspace-field-protection.js').DeclaredProtectedField;
/** Conservative Owner choices may narrow the supported readable contract. */
export type StructureAdoptionOptions={keep_encrypted?:{protocol_digest?:string;schema:string;fields:string[]}[]};
export type ProtectedSchema={fields:Record<string,ProtectedField>;required:string[];workflow?:import('./workspace-workflow.js').WorkflowDefinition};
export type StructureAction={schemas:string[];roles:string[];capabilities:string[];heads:'NONE'|'APPEND'|'SELECT';task_transition?:{from:string|null;to:string}[]};
export type StructureProtocol={v:1;field_declarations?:1;protocol_digest:string;schemas:Record<string,ProtectedSchema>;actions:Record<string,StructureAction>};
export type StructurePolicy={
 v:1;protocols:StructureProtocol[];coordination?:CoordinationPolicy;
 /** Separate Owner approval; declaring a readable field does not authorize its disclosure. */
 disclosure:{protocol_digest:string;schema:string;fields:string[]}[];
 instances:{instance_id:string;protocol_digest:string}[];
};
export type StructureRecord={
 record_id:string;entity_id:string;revision:number;instance_id:string;protocol_digest:string;
 schema_ref:string;actor_id:string;created:number;fields:Record<string,SecureJson>;
};
export type StructureHead={entity_id:string;record_id:string;revision:number;instance_id:string};
export type StructureEnvelope={
 v:1;mode:'DELTA'|'SNAPSHOT_BEGIN'|'SNAPSHOT_PAGE'|'SNAPSHOT_END';
 records:StructureRecord[];heads:StructureHead[];
 snapshot?:{source:SecureCheckpoint;root:string;records:number;heads:number;offset:number};
};
export type StructureState={records:Map<string,StructureRecord>;heads:Map<string,StructureHead>;snapshot?:NonNullable<StructureEnvelope['snapshot']>};
export const emptyStructureState=():StructureState=>({records:new Map(),heads:new Map()});
