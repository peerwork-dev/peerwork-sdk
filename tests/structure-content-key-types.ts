import type {KernelSession, AgentContext, StructureIntentOutcome, AgentContextResult, BackendStructureResult} from '../bindings/node/index';
declare const kernel: KernelSession;
declare const context: AgentContext;
const advanced: Promise<StructureIntentOutcome> = kernel.rotateContentKey({workspace_id: 'workspace', idempotency_key: 'revoke-1'});
const selected: Promise<AgentContextResult> = context.rotateContentKey('workspace', {idempotency_key: 'revoke-1'});
const coordinator: Promise<StructureIntentOutcome> = kernel.coordinateContentKeys({workspace_id:'workspace'});
const contextCoordinator: Promise<AgentContextResult> = context.coordinateContentKeys('workspace');
void [advanced, selected, coordinator, contextCoordinator];
// @ts-expect-error coordinator target must be explicit
kernel.coordinateContentKeys({});
// @ts-expect-error future key authorization is an explicit boolean
kernel.authorizeAccess({workspace_id:'workspace',request_jws:'request',follow_current_key:'yes'});
// @ts-expect-error recovery requires an explicit stable operation key
kernel.rotateContentKey({workspace_id: 'workspace'});
// @ts-expect-error a selected Context cannot target a different workspace in options
context.rotateContentKey('workspace', {workspace_id: 'other', idempotency_key: 'revoke-1'});

type SealedBody=NonNullable<BackendStructureResult['sealed_content']>;
const chunked:SealedBody={algorithm:'A256GCM',key_id:'key',nonce:'nonce',aad_digest:'digest',ciphertext_chunks:['first','last']};
const inline:SealedBody={algorithm:'A256GCM',key_id:'key',nonce:'nonce',aad_digest:'digest',ciphertext:'ciphertext'};
void [chunked,inline];
// @ts-expect-error inline and chunked ciphertext are exclusive
const ambiguous:SealedBody={...inline,ciphertext_chunks:['chunk']};

import type {WorkspaceUrls,WorkspaceLink} from '../bindings/node/index';
declare const urls:WorkspaceUrls;
const selectedRecordLink:Promise<string>=urls.record('workspace','record',{instanceId:'instance',revision:7});
const apiLocators:Promise<WorkspaceLink>=urls.build('workspace');
void [selectedRecordLink,apiLocators];
// @ts-expect-error record URL requires instance and record revision
urls.record('workspace','record');
// @ts-expect-error record revision must be a number
urls.record('workspace','record',{instanceId:'instance',revision:'7'});
// @ts-expect-error unsupported routes must not generate a plausible broken URL
urls.build('workspace',{kind:'thread'});

const historyApproval: Promise<StructureIntentOutcome> = kernel.authorizeAccess({workspace_id:'workspace',request_jws:'request',include_history:true});
const contextHistory: Promise<AgentContextResult> = context.authorizeAccess('workspace',{request_jws:'request',include_history:true});
void [historyApproval,contextHistory];
// @ts-expect-error retained history requires an explicit boolean
kernel.authorizeAccess({workspace_id:'workspace',request_jws:'request',include_history:'all'});
declare const ready: AgentContextResult;
const historyState: 'READY' | 'PENDING' | 'UNAVAILABLE' | undefined = ready.key_history?.state;
void historyState;

const selectedPublication: Promise<StructureIntentOutcome> = kernel.publishSelectedRecord({workspace_id:'workspace',instance_id:'instance',protocol_digest:'digest',record_id:'record',revision:1,idempotency_key:'selected',title:'Note',disclosure:'PUBLISH_SELECTED_CONTENT',body:{from:'RECORD'}});
const contextPublication: Promise<AgentContextResult> = context.publishSelectedRecord('workspace',{instance_id:'instance',protocol_digest:'digest',record_id:'record',revision:1,idempotency_key:'selected',title:'Note',disclosure:'PUBLISH_SELECTED_CONTENT',body:{from:'TEXT',text:'Summary'}});
void [selectedPublication,contextPublication];
// @ts-expect-error a plaintext publication body requires an explicit source
kernel.publishSelectedRecord({workspace_id:'workspace',instance_id:'instance',protocol_digest:'digest',record_id:'record',revision:1,idempotency_key:'selected',title:'Note',disclosure:'PUBLISH_SELECTED_CONTENT',body:{text:'Ambiguous'}});

import type {PublicActionIntent,PublicActionPolicyIntent,PublicEntryWithdrawal} from '../bindings/node/index';
const publicAction:PublicActionIntent={action:'structure.action',instance_id:'instance',protocol_digest:'digest',expected_instance_revision:1,body:{action_id:'post',structure:{},publication:{policy_revision:1,disclosure:'PUBLISH_ACTION_AND_SELECTED_RECORDS',entries:[{record_index:0,title:'Public note',body:{format:'PUBLIC_UTF8_BASE64',chunks:[]}}]}}};
const publicPolicy:PublicActionPolicyIntent={action:'structure.publication.policy.set',instance_id:'instance',protocol_digest:'digest',body:{state:'ACTIVE',expected_policy_revision:0,actions:['post'],disclosure:'ALLOW_AUTHOR_SIGNED_ACTION_PUBLICATION'}};
const publicWithdrawal:PublicEntryWithdrawal={action:'structure.publication.entry.withdraw',instance_id:'instance',protocol_digest:'digest',body:{record_id:'record',expected_publication_revision:1}};
void [kernel.executeStructureIntent(publicAction),context.executeStructureIntent('workspace',publicPolicy),kernel.executeStructureIntent(publicWithdrawal)];
// @ts-expect-error public actions must not carry private plaintext encryption inputs
const mixed:PublicActionIntent={...publicAction,plaintext_contents:[{record_index:0,text:'Private'}]};
void mixed;
const withdrawal: import('../bindings/node/index').RecordWithdrawal = {
 action:'structure.record.withdraw',workspace_id:'workspace',instance_id:'instance',protocol_digest:'digest',
 expected_instance_revision:1,body:{record_id:'record',revision:1}
};
kernel.executeStructureIntent(withdrawal);

const deleteWorkspace: import('../bindings/node/index').WorkspaceDeletion = {
 action:'structure.workspace.delete',workspace_id:'workspace',expected_workspace_revision:1,
 body:{confirm_workspace_id:'workspace'}
};
kernel.executeStructureIntent(deleteWorkspace);
declare const deletionStatus: import('../bindings/node/index').WorkspaceDeletionProgress;
const deletionPhase: string=deletionStatus.phase;
void deletionPhase;

context.followOperation('workspace',{kind:'WORKSPACE_DELETE',command_id:'original-command'});

const timedImport: import('../bindings/node/index').DocumentImportAction = {
 action:'structure.action',workspace_id:'workspace',instance_id:'instance',protocol_digest:'digest',expected_instance_revision:1,
 body:{action_id:'document.import',structure:{},document_times:[{record_index:0,created_at:'2000-01-01T00:00:00Z'}]},
 plaintext_contents:[{record_index:0,text:'Private imported text'}]
};
kernel.executeStructureIntent(timedImport);
