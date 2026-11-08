import type { SecureOwnerWorkspaceSession, HistoricalOwnerAttachmentInput,
  HistoricalObjectStagePendingInventory, HistoricalOwnerAttachmentResult } from '../bindings/node/index';
declare const owner: SecureOwnerWorkspaceSession;
declare const input: HistoricalOwnerAttachmentInput;
const inspect: Promise<HistoricalObjectStagePendingInventory> = owner.inspectPendingObjectStage(input, 'stage', '{}', '{}');
const attach: Promise<HistoricalOwnerAttachmentResult> = owner.attachPendingObjectStage(input, 'stage', 'digest', '{}', '{}');
const recover: Promise<HistoricalOwnerAttachmentResult> = owner.recoverPendingObjectStage('attach', 'original-stage');
inspect.then(value => {
  const count: number = value.part_count;
  const status: 'PENDING_UNRESOLVED' | 'APPLIED_IN_SIGNED_REPLAY' = value.status;
  void [count, status, value.source_id, value.original_options_hash];
});
attach.then(value => {
  const original: string | null = value.pending_object_stage_command_id;
  const native: string | null = value.pending_object_stage_native_begin_command_id;
  void [original, native, value.pending_object_stage_status];
});
// @ts-expect-error full material must be a JSON string
owner.inspectPendingObjectStage(input, 'stage', '{}', 123);
// @ts-expect-error attachment requires the inspected source digest
owner.attachPendingObjectStage(input, 'stage', '{}', '{}');
// @ts-expect-error recovery selects both attachment and original stage command
owner.recoverPendingObjectStage('attach');
void [inspect, attach, recover];
