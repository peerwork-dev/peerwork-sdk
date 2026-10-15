import type { SecureOwnerWorkspaceSession, HistoricalOwnerAttachmentInput, HistoricalObjectStageIntentInventory, HistoricalObjectStageIntentCandidate, HistoricalOwnerAttachmentResult } from '../bindings/node/index';
declare const owner: SecureOwnerWorkspaceSession;
declare const input: HistoricalOwnerAttachmentInput;
const candidates: Promise<HistoricalObjectStageIntentCandidate[]> = owner.objectStageIntentCandidates(input);
const inspect: Promise<HistoricalObjectStageIntentInventory> = owner.inspectObjectStageIntent(input, 'marker', '{}', '{}');
const attach: Promise<HistoricalOwnerAttachmentResult> = owner.attachObjectStageIntent(input, 'marker', 'digest', '{}', '{}');
const recover = owner.recoverObjectStageIntent('attach','marker');
inspect.then(v=>{ const cursor:number=v.accepted_parts; const hash:string=v.marker_hash;void[cursor,hash]; });
attach.then(v=>{ const hash:string|undefined=v.object_stage_intent_marker_hash;const command:string|null=v.pending_object_stage_command_id;void[hash,command]; });
// @ts-expect-error material must be a string
owner.inspectObjectStageIntent(input, 'marker','{}',123);
// @ts-expect-error attach requires inspected state digest and both source strings
owner.attachObjectStageIntent(input,'marker','{}','{}');
// @ts-expect-error recovery requires exact marker selection
owner.recoverObjectStageIntent('attach');
void[candidates,inspect,attach,recover];
