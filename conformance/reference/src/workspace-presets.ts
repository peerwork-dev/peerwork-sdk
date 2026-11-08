import {manifestCanonical,type Manifest} from './workspace-manifest.js';

const literal=(value:unknown)=>({from:'literal' as const,value});
const body=(...path:string[])=>({from:'body' as const,path});
const state=(...path:string[])=>({from:'state' as const,path});
const actor={from:'auth' as const,field:'actorId' as const};
const ref=(...path:string[])=>({from:'ref' as const,source:'body' as const,path,scope:'INSTANCE' as const});
const workspaceRef=(...path:string[])=>({from:'ref' as const,source:'body' as const,path,scope:'WORKSPACE' as const});
const object=(fields:Record<string,unknown>)=>({from:'object' as const,fields});
const eq=(left:unknown,right:unknown)=>({op:'eq' as const,left,right});
const role=(name:string)=>({op:'has_protocol_role' as const,role:name});
const capability=(name:string)=>({op:'has_capability' as const,capability:name});
const exact=(value:unknown)=>({op:'exact_ref' as const,ref:value});
const set=(path:string[],value:unknown)=>({op:'set' as const,path,value});
const append=(schema:string,value:unknown,extra:Record<string,unknown>={})=>({op:'append' as const,schema,value,relations:[],...extra});
const schema=(fields:Record<string,'string'|'integer'|'boolean'|'null'|'json'>,required=Object.keys(fields))=>({type:'object' as const,fields,required,max_bytes:16_384});
const action=(id:string,reads:string[][],writes:string[][],control:boolean,contentEntities:string[],variants:unknown[])=>({id,reads,writes,revisionEffects:{control,contentEntities},variants});
const base=(name:string,roles:string[],caps:string[],conflicts:[string,string][],schemas:Manifest['record_schemas'],initial_state:unknown,actions:any[],historicalRoleConflicts:[string,string][]=[]):Manifest=>manifestCanonical({name,display_version:'1',semantics:'peerwork.kernel.v1',dependencies:[],protocol_roles:roles,capabilities:caps,role_conflicts:conflicts,historical_role_conflicts:historicalRoleConflicts,record_schemas:schemas,initial_state,actions}).manifest;

export const PRESET_IDS={discussion:'peerwork.discussion.v1',wiki:'peerwork.wiki.v1',task:'peerwork.task.v1',hostedService:'peerwork.service-request.v1',externalService:'peerwork.service-report.v1',outputs:'peerwork.outputs.v1'} as const;

export function discussionPreset(){return base(PRESET_IDS.discussion,['CONTRIBUTOR','EDITOR'],['POST','SUMMARIZE'],[],{
 'discussion.message':schema({message:'string',reply_to:'json',author:'string'}),
 'wiki.revision':schema({title:'string',body:'string',source_refs:'json',author:'string'}),
},{},[
 action('discussion.post',[],[],false,[],[{when:[role('CONTRIBUTOR'),capability('POST')],effects:[append('discussion.message',object({message:body('message'),reply_to:literal(null),author:actor}))]}]),
 action('discussion.reply',[],[],false,[],[{when:[role('CONTRIBUTOR'),capability('POST'),exact(ref('reply_to'))],effects:[append('discussion.message',object({message:body('message'),reply_to:ref('reply_to'),author:actor}),{relations:[{kind:'reply_to',target:ref('reply_to')} ]})]}]),
 action('discussion.summarize',[],[],true,['document'],[{when:[role('EDITOR'),capability('SUMMARIZE')],effects:[append('wiki.revision',object({title:body('title'),body:body('body'),source_refs:body('source_refs'),author:actor}),{recordSlot:'summary',entity:{mode:'new',slot:'document'},selectHead:true})]}]),
]);}

export function wikiPreset(){return base(PRESET_IDS.wiki,['EDITOR'],['EDIT'],[],{'wiki.revision':schema({title:'string',body:'string',author:'string',parent:'json'})},{},[
 action('wiki.create',[],[],true,['document'],[{when:[role('EDITOR'),capability('EDIT')],effects:[append('wiki.revision',object({title:body('title'),body:body('body'),author:actor,parent:literal(null)}),{recordSlot:'revision',entity:{mode:'new',slot:'document'},selectHead:true})]}]),
 action('wiki.revise',[],[],true,['document'],[{when:[role('EDITOR'),capability('EDIT'),exact(ref('parent_ref'))],effects:[append('wiki.revision',object({title:body('title'),body:body('body'),author:actor,parent:ref('parent_ref')}),{recordSlot:'revision',entity:{mode:'revise',slot:'document',parent:ref('parent_ref')},selectHead:true,relations:[{kind:'parent',target:ref('parent_ref')} ]})]}]),
 action('wiki.branch',[],[],true,['document'],[{when:[role('EDITOR'),capability('EDIT'),exact(ref('parent_ref'))],effects:[append('wiki.revision',object({title:body('title'),body:body('body'),author:actor,parent:ref('parent_ref')}),{recordSlot:'revision',entity:{mode:'revise',slot:'document',parent:ref('parent_ref')},selectHead:false,relations:[{kind:'parent',target:ref('parent_ref')} ]})]}]),
 action('wiki.select_head',[],[],true,[],[{when:[role('EDITOR'),capability('EDIT'),exact(ref('expected_head')),exact(ref('target'))],effects:[{op:'select_head',expected:ref('expected_head'),target:ref('target')}]}]),
]);}

export function simpleTaskPreset(){return base(PRESET_IDS.task,['MANAGER','CONTRIBUTOR'],['MANAGE','REPORT'],[],{
 'task.revision':schema({title:'string',description:'string',status:'string',assignee:'json',note:'string',author:'string',parent:'json'}),
 'task.report':schema({task_ref:'json',kind:'string',summary:'string',evidence_refs:'json',author:'string'}),
},{},[
 action('task.create',[],[],true,['task'],[{when:[role('MANAGER'),capability('MANAGE')],effects:[append('task.revision',object({title:body('title'),description:body('description'),status:literal('OPEN'),assignee:body('assignee'),note:literal(''),author:actor,parent:literal(null)}),{recordSlot:'revision',entity:{mode:'new',slot:'task'},selectHead:true})]}]),
 action('task.update',[],[],true,['task'],['OPEN:IN_PROGRESS','IN_PROGRESS:DONE','OPEN:CANCELED','IN_PROGRESS:CANCELED'].map(pair=>{const [from,to]=pair.split(':');return {when:[role('MANAGER'),capability('MANAGE'),exact(ref('task_ref')),eq(body('from_status'),literal(from)),eq(body('status'),literal(to))],effects:[append('task.revision',object({title:body('title'),description:body('description'),status:body('status'),assignee:body('assignee'),note:body('note'),author:actor,parent:ref('task_ref')}),{recordSlot:'revision',entity:{mode:'revise',slot:'task',parent:ref('task_ref')},selectHead:true,relations:[{kind:'parent',target:ref('task_ref')} ]})]};})),
 action('task.report',[],[],false,[],[{when:[role('CONTRIBUTOR'),capability('REPORT'),exact(ref('task_ref'))],effects:[append('task.report',object({task_ref:ref('task_ref'),kind:body('kind'),summary:body('summary'),evidence_refs:body('evidence_refs'),author:actor}),{relations:[{kind:'task',target:ref('task_ref')} ]})]}]),
]);}

/** Opt-in new instance. Existing task preset IDs, digests and histories remain unchanged. */
export function workflowTaskPreset(){
 const states=['OPEN','IN_PROGRESS','DONE','CANCELED'],pairs=['OPEN:OPEN','OPEN:IN_PROGRESS','IN_PROGRESS:IN_PROGRESS','IN_PROGRESS:DONE','OPEN:CANCELED','IN_PROGRESS:CANCELED'];
 const fields={title:'string',description:'string',status:'string',assignee:'json',note:'string',author:'string',parent:'json',dependencies:'json',due_at:'json'} as const;
 const transitions=[{action:'workflow.create',from:null,to:'OPEN'},...pairs.map(pair=>{const [from,to]=pair.split(':');return {action:'workflow.update',from:from!,to:to!};})];
 const taskSchema={...schema(fields),protection:{v:1 as const,fields:{
  title:{protection:'e2ee' as const,type:'string' as const},description:{protection:'e2ee' as const,type:'string' as const},note:{protection:'e2ee' as const,type:'string' as const},
  status:{protection:'server_readable' as const,type:'enum' as const,values:states},assignee:{protection:'server_readable' as const,type:'optional_actor' as const},author:{protection:'server_readable' as const,type:'actor' as const},
  parent:{protection:'server_readable' as const,type:'optional_reference' as const},dependencies:{protection:'server_readable' as const,type:'references' as const},due_at:{protection:'server_readable' as const,type:'timestamp' as const},
 }},workflow:{v:1 as const,status_field:'status',parent_field:'parent',assignee_field:'assignee',states,transitions,dependencies:{field:'dependencies',satisfied_states:['DONE'],gated_states:['IN_PROGRESS','DONE']},deadline:{field:'due_at'}}};
 const taskRef={...ref('task_ref'),schema:'workflow.task'};
 const dependencies={op:'exact_ref_list',source:'body',path:['dependencies'],scope:'INSTANCE',schema:'workflow.task',max:31};
 const values=(status:unknown,parent:unknown)=>object({title:body('title'),description:body('description'),status,assignee:body('assignee'),note:body('note'),author:actor,parent,dependencies:body('dependencies'),due_at:body('due_at')});
 return base('peerwork.workflow-task.v1',['MANAGER','CONTRIBUTOR'],['MANAGE','REPORT'],[],{
  'workflow.task':taskSchema,'workflow.report':schema({task_ref:'json',summary:'string',author:'string'}),
 },{},[
  action('workflow.create',[],[],true,['task'],[{when:[role('MANAGER'),capability('MANAGE'),dependencies],effects:[append('workflow.task',values(literal('OPEN'),literal(null)),{recordSlot:'revision',entity:{mode:'new',slot:'task'},selectHead:true})]}]),
  action('workflow.update',[],[],true,['task'],pairs.map(pair=>{const [from,to]=pair.split(':');return {when:[role('MANAGER'),capability('MANAGE'),exact(taskRef),dependencies,eq(body('from_status'),literal(from)),eq(body('status'),literal(to))],effects:[append('workflow.task',values(body('status'),taskRef),{recordSlot:'revision',entity:{mode:'revise',slot:'task',parent:taskRef},selectHead:true,relations:[{kind:'parent',target:taskRef}]})]};})),
  action('workflow.report',[],[],false,[],[{when:[role('CONTRIBUTOR'),capability('REPORT'),exact(taskRef)],effects:[append('workflow.report',object({task_ref:taskRef,summary:body('summary'),author:actor}),{relations:[{kind:'task',target:taskRef}]})]}]),
 ]);
}

/** New immutable opt-in; existing workflow/task preset digests stay unchanged. */
export function deadlineWorkflowTaskPreset(){
 const manifest=workflowTaskPreset();manifest.name='peerwork.workflow-task-deadlines.v1';
 manifest.record_schemas['workflow.task']!.workflow!.deadline!.reminder={lead_ms:0,active_states:['OPEN','IN_PROGRESS']};
 return manifest;
}

export function hostedServiceRequestPreset(){const reads=[['phase'],['turn'],['ready_scope_ref'],['approval_ref'],['executor_actor']];return base(PRESET_IDS.hostedService,['REQUESTER','TRUSTED','AUTHORIZER'],['PROPOSE','SETTLE','DELIVER','NOTE'],[['REQUESTER','TRUSTED'],['REQUESTER','AUTHORIZER']],{
 'service.message':schema({kind:'string',text:'string',author:'string'}),'service.scope':schema({scope:'string',author:'string'}),
 'service.approval':schema({scope_ref:'json',executor_actor:'string',action_context:'string',author:'string'}),'service.delivery':schema({approval_ref:'json',artifact_refs:'json',summary:'string',author:'string'}),'service.note':schema({kind:'string',summary:'string',evidence_refs:'json',author:'string'}),
},{phase:'OPEN',turn:'requester',ready_scope_ref:null,approval_ref:null,executor_actor:null},[
 action('service.PROPOSE',reads,[['turn'],['ready_scope_ref'],['approval_ref']],true,['scope'],[
  {when:[role('REQUESTER'),capability('PROPOSE'),eq(state('phase'),literal('OPEN')),eq(body('kind'),literal('request'))],effects:[append('service.message',object({kind:literal('request'),text:body('text'),author:actor})),set(['turn'],literal('trusted')),set(['ready_scope_ref'],literal(null)),set(['approval_ref'],literal(null))]},
  {when:[role('TRUSTED'),capability('PROPOSE'),eq(state('phase'),literal('OPEN')),eq(body('kind'),literal('question'))],effects:[append('service.message',object({kind:literal('question'),text:body('text'),author:actor})),set(['turn'],literal('requester')),set(['ready_scope_ref'],literal(null)),set(['approval_ref'],literal(null))]},
  {when:[role('TRUSTED'),capability('PROPOSE'),eq(state('phase'),literal('OPEN')),eq(body('kind'),literal('scope'))],effects:[append('service.scope',object({scope:body('scope'),author:actor}),{recordSlot:'scope',entity:{mode:'new',slot:'scope'},selectHead:true}),set(['turn'],literal('authorizer')),set(['ready_scope_ref'],{from:'produced_ref',slot:'scope'}),set(['approval_ref'],literal(null))]},
 ]),
 action('service.SETTLE',reads,[['phase'],['turn'],['approval_ref'],['executor_actor']],true,[],[
  {when:[role('AUTHORIZER'),capability('SETTLE'),eq(state('phase'),literal('OPEN')),eq(state('turn'),literal('authorizer')),eq(body('value'),literal('yes')),exact(ref('scope_ref')),eq(ref('scope_ref'),state('ready_scope_ref'))],effects:[append('service.approval',object({scope_ref:ref('scope_ref'),executor_actor:body('executor_actor'),action_context:body('action_context'),author:actor}),{recordSlot:'approval',relations:[{kind:'scope',target:ref('scope_ref')}]}),set(['approval_ref'],{from:'produced_ref',slot:'approval'}),set(['executor_actor'],body('executor_actor')),set(['phase'],literal('AUTHORIZED')),set(['turn'],literal('executor'))]},
  {when:[role('AUTHORIZER'),capability('SETTLE'),eq(state('phase'),literal('OPEN')),eq(state('turn'),literal('authorizer')),eq(body('value'),literal('no')),exact(ref('scope_ref')),eq(ref('scope_ref'),state('ready_scope_ref'))],effects:[append('service.message',object({kind:literal('declined'),text:body('reason'),author:actor})),set(['phase'],literal('DECLINED'))]},
  {when:[role('TRUSTED'),capability('SETTLE'),eq(state('phase'),literal('OPEN')),eq(body('value'),literal('no'))],effects:[append('service.message',object({kind:literal('inability'),text:body('reason'),author:actor})),set(['phase'],literal('DECLINED'))]},
  {when:[role('TRUSTED'),capability('SETTLE'),eq(state('phase'),literal('AUTHORIZED')),eq(state('executor_actor'),actor),eq(body('value'),literal('no'))],effects:[append('service.message',object({kind:literal('failure'),text:body('reason'),author:actor})),set(['phase'],literal('FAILED'))]},
  ...['OPEN','AUTHORIZED'].map(phase=>({when:[role('REQUESTER'),capability('SETTLE'),eq(state('phase'),literal(phase)),eq(body('value'),literal('withdraw'))],effects:[append('service.message',object({kind:literal('withdrawn'),text:body('reason'),author:actor})),set(['phase'],literal('WITHDRAWN'))]})),
 ]),
 action('service.DELIVER',reads,[['phase']],true,[],[{when:[role('TRUSTED'),capability('DELIVER'),eq(state('phase'),literal('AUTHORIZED')),eq(state('executor_actor'),actor),exact(ref('approval_ref')),eq(ref('approval_ref'),state('approval_ref')),{op:'exact_ref_list',source:'body',path:['artifact_refs'],scope:'INSTANCE_OR_WORKSPACE',max:32}],effects:[append('service.delivery',object({approval_ref:ref('approval_ref'),artifact_refs:body('artifact_refs'),summary:body('summary'),author:actor}),{relations:[{kind:'approval',target:ref('approval_ref')}]}),set(['phase'],literal('DELIVERED'))]}]),
 action('service.NOTE',[],[],false,[],[{when:[capability('NOTE')],effects:[append('service.note',object({kind:body('kind'),summary:body('summary'),evidence_refs:body('evidence_refs'),author:actor}))]}]),
],[['REQUESTER','TRUSTED'],['REQUESTER','AUTHORIZER']]);}

export function externalServiceReportPreset(){return base(PRESET_IDS.externalService,['BRIDGE'],['REPORT'],[],{'service.external_report':schema({kind:'string',external_ref:'string',summary:'string',reporter:'string',grants_external_authority:'boolean'})},{},[
 action('service.REPORTED_AUTHORIZATION',[],[],false,[],[{when:[role('BRIDGE'),capability('REPORT')],effects:[append('service.external_report',object({kind:literal('REPORTED_AUTHORIZATION'),external_ref:body('external_ref'),summary:body('summary'),reporter:actor,grants_external_authority:literal(false)}))]}]),
 action('service.REPORTED_DELIVERY',[],[],false,[],[{when:[role('BRIDGE'),capability('REPORT')],effects:[append('service.external_report',object({kind:literal('REPORTED_DELIVERY'),external_ref:body('external_ref'),summary:body('summary'),reporter:actor,grants_external_authority:literal(false)}))]}]),
]);}

export function outputsPreset(){return base(PRESET_IDS.outputs,['CURATOR'],['SELECT'],[],{'outputs.selection':schema({collection:'string',mode:'string',label:'string',summary:'string',target_ref:'json',entity_id:'json',selector_actor:'string'})},{},[
 action('outputs.select_pinned',[],[],false,[],[{when:[role('CURATOR'),capability('SELECT'),exact(workspaceRef('target_ref'))],effects:[append('outputs.selection',object({collection:body('collection'),mode:literal('pinned_revision'),label:body('label'),summary:body('summary'),target_ref:workspaceRef('target_ref'),entity_id:literal(null),selector_actor:actor}),{relations:[{kind:'selected',target:workspaceRef('target_ref')} ]})]}]),
 action('outputs.select_following',[],[],false,[],[{when:[role('CURATOR'),capability('SELECT'),exact(workspaceRef('target_ref'))],effects:[append('outputs.selection',object({collection:body('collection'),mode:literal('follow_selected_head'),label:body('label'),summary:body('summary'),target_ref:workspaceRef('target_ref'),entity_id:{from:'resolved_entity',ref:workspaceRef('target_ref')},selector_actor:actor}),{relations:[{kind:'selected',target:workspaceRef('target_ref')} ]})]}]),
]);}

export const COLLABORATION_PRESETS=Object.freeze({discussion:discussionPreset,wiki:wikiPreset,task:simpleTaskPreset,hostedService:hostedServiceRequestPreset,externalService:externalServiceReportPreset,outputs:outputsPreset});

/** Opt-in new protocol. Existing Discussion/Task manifests and digests are unchanged. */
export function coordinationPreset(){
 const scoped=(id:string,recordSchema:string,fields:Record<string,unknown>,withBinding=true)=>action(id,[],[],false,[],(['INSTANCE','WORKSPACE'] as const).map(scope=>{const source={from:'ref' as const,source:'body' as const,path:['source_ref'],scope};return {when:[eq(body('source_scope'),literal(scope)),role('COLLABORATOR'),capability('COORDINATE'),exact(source)],effects:[append(recordSchema,object({...withBinding?{item_id:body('item_id'),source_hash:body('source_hash')}:{},source_ref:source,author:actor,...fields}),{relations:[{kind:'source',target:source}]})]};}));
 return base('peerwork.coordination.v1',['COLLABORATOR'],['COORDINATE'],[],{
  'coordination.request':schema({request_id:'string',message:'string',recipients:'json',source_ref:'json',author:'string'}),
  'coordination.ack':schema({item_id:'string',source_ref:'json',source_hash:'string',author:'string'}),
  'coordination.disposition':schema({item_id:'string',source_ref:'json',source_hash:'string',author:'string',expected_version:'integer',state:'string',defer_until:'json',note:'string'}),
  'coordination.cancel':schema({item_id:'string',source_ref:'json',source_hash:'string',author:'string',note:'string'}),
  'coordination.remind':schema({item_id:'string',source_ref:'json',source_hash:'string',author:'string'}),
 },{},[
  action('coordination.send',[],[],false,[],[{when:[role('COLLABORATOR'),capability('COORDINATE')],effects:[append('coordination.request',object({request_id:body('request_id'),message:body('message'),recipients:body('recipients'),source_ref:literal(null),author:actor}))]}]),
  scoped('coordination.reply','coordination.request',{request_id:body('request_id'),message:body('message'),recipients:body('recipients')},false),
  scoped('coordination.ack','coordination.ack',{}),
  scoped('coordination.disposition','coordination.disposition',{expected_version:body('expected_version'),state:body('state'),defer_until:body('defer_until'),note:body('note')}),
  scoped('coordination.cancel','coordination.cancel',{note:body('note')}),
  scoped('coordination.remind','coordination.remind',{}),
 ]);
}

/** New digest; the pinned v1 manifest above remains byte-for-byte reproducible. */
export function coordinationResultPreset():Manifest{
 const prior=coordinationPreset();
 const variants=(['INSTANCE','WORKSPACE'] as const).flatMap(sourceScope=>(['NONE','INSTANCE','WORKSPACE'] as const).map(resultScope=>{
  const source={from:'ref' as const,source:'body' as const,path:['source_ref'],scope:sourceScope},result=resultScope==='NONE'?literal(null):{from:'ref' as const,source:'body' as const,path:['result_ref'],scope:resultScope};
  return {when:[eq(body('source_scope'),literal(sourceScope)),eq(body('result_scope'),literal(resultScope)),role('COLLABORATOR'),capability('COORDINATE'),exact(source),...(resultScope==='NONE'?[eq(body('result_ref'),literal(null))]:[exact(result)])],effects:[append('coordination.disposition',object({item_id:body('item_id'),source_ref:source,source_hash:body('source_hash'),author:actor,expected_version:body('expected_version'),state:body('state'),defer_until:body('defer_until'),note:body('note'),result_ref:result}),{relations:[{kind:'source',target:source},...(resultScope==='NONE'?[]:[{kind:'result',target:result}])]})]};
 }));
 return manifestCanonical({...prior,name:'peerwork.coordination.v2',display_version:'2',record_schemas:{...prior.record_schemas,'coordination.disposition':schema({...prior.record_schemas['coordination.disposition']!.fields,result_ref:'json'})},actions:prior.actions.map(a=>a.id==='coordination.disposition'?action(a.id,[],[],false,[],variants):a)}).manifest;
}

export function sessionCollaborationPreset():Manifest {
  const local=(name:string,schemaName:string)=>({
    ...ref(name),schema:schemaName
  });
  const shared=(name:string,schemaName:string)=>({
    ...workspaceRef(name),schema:schemaName
  });
  const payload=(reference:unknown,...path:string[])=>({
    from:'resolved_payload',ref:reference,path
  });
  const typed=(a:any,fields:Record<string,unknown>)=>({
    ...a,inputs:{
      fields,required:Object.keys(fields),additionalProperties:false
    }
  });
  const text={
    type:'string',maxBytes:8192
  };
  const localArtifact=local('target_ref','session.artifact'),artifact=shared('artifact_ref','session.artifact'),proposal=local('proposal_ref','session.proposal');
  const exactField=(schema:string,scope:'INSTANCE'|'WORKSPACE')=>({
    type:'exact_ref',schema,scope
  });
  return base('peerwork.session-collaboration.v1',['CONTRIBUTOR','ADOPTER'],['DISCUSS','REPORT','ARTIFACT','PROPOSE','ADOPT'],[],{
    'session.message':schema({
      message:'string',author:'string'
    }),
    'session.report':schema({
      summary:'string',author:'string'
    }),
    'session.artifact':schema({
      title:'string',body:'string',author:'string',parent:'json',source_ref:'json',proposal_ref:'json'
    }),
    'session.proposal':schema({
      target_ref:'json',artifact_ref:'json',summary:'string',author:'string'
    }),
    'session.adoption':schema({
      proposal_ref:'json',target_ref:'json',artifact_ref:'json',author:'string'
    }),
  },{
  },[
  typed(action('session.discuss',[],[],false,[],[{
    when:[role('CONTRIBUTOR'),capability('DISCUSS')],effects:[append('session.message',object({
      message:body('message'),author:actor
    }))]
  }]),{
    message:text
  }),
  typed(action('session.report',[],[],false,[],[{
    when:[role('CONTRIBUTOR'),capability('REPORT')],effects:[append('session.report',object({
      summary:body('summary'),author:actor
    }))]
  }]),{
    summary:text
  }),
  typed(action('session.artifact.create',[],[],true,['artifact'],[{
    when:[role('CONTRIBUTOR'),capability('ARTIFACT')],effects:[append('session.artifact',object({
      title:body('title'),body:body('body'),author:actor,parent:literal(null),source_ref:literal(null),proposal_ref:literal(null)
    }),{
      recordSlot:'artifact',entity:{
        mode:'new',slot:'artifact'
      },selectHead:true
    })]
  }]),{
    title:text,body:text
  }),
  typed(action('session.artifact.branch',[],[],true,['artifact'],[{
    when:[role('CONTRIBUTOR'),capability('ARTIFACT'),exact(localArtifact)],effects:[append('session.artifact',object({
      title:body('title'),body:body('body'),author:actor,parent:localArtifact,source_ref:literal(null),proposal_ref:literal(null)
    }),{
      recordSlot:'artifact',entity:{
        mode:'revise',slot:'artifact',parent:localArtifact
      },selectHead:false,relations:[{
        kind:'parent',target:localArtifact
      }]
    })]
  }]),{
    target_ref:exactField('session.artifact','INSTANCE'),title:text,body:text
  }),
  typed(action('session.propose',[],[],false,[],[{
    when:[role('CONTRIBUTOR'),capability('PROPOSE'),exact(localArtifact),exact(artifact)],effects:[append('session.proposal',object({
      target_ref:localArtifact,artifact_ref:artifact,summary:body('summary'),author:actor
    }),{
      relations:[{
        kind:'target',target:localArtifact
      },{
        kind:'artifact',target:artifact
      }]
    })]
  }]),{
    target_ref:exactField('session.artifact','INSTANCE'),artifact_ref:exactField('session.artifact','WORKSPACE'),summary:text
  }),
  typed(action('session.adopt',[],[],true,['artifact'],[{
    when:[role('ADOPTER'),capability('ADOPT'),exact(proposal),exact(localArtifact),exact(artifact),eq(localArtifact,payload(proposal,'target_ref')),eq(artifact,payload(proposal,'artifact_ref'))],effects:[append('session.artifact',object({
      title:payload(artifact,'title'),body:payload(artifact,'body'),author:actor,parent:localArtifact,source_ref:artifact,proposal_ref:proposal
    }),{
      recordSlot:'artifact',entity:{
        mode:'revise',slot:'artifact',parent:localArtifact
      },selectHead:true,relations:[{
        kind:'proposal',target:proposal
      },{
        kind:'source',target:artifact
      },{
        kind:'parent',target:localArtifact
      }]
    }),append('session.adoption',object({
      proposal_ref:proposal,target_ref:localArtifact,artifact_ref:artifact,author:actor
    }),{
      relations:[{
        kind:'proposal',target:proposal
      },{
        kind:'source',target:artifact
      }]
    })]
  }]),{
    proposal_ref:exactField('session.proposal','INSTANCE'),target_ref:exactField('session.artifact','INSTANCE'),artifact_ref:exactField('session.artifact','WORKSPACE')
  }),
  ]);
}
