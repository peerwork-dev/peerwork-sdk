import type {
  HistoricalOwnerAttachmentInput, HistoricalOwnerAttachmentResult,
  HistoricalPackageStageOrphanInventory, SecureOwnerWorkspaceSession,
} from '../bindings/node/index';

declare const owner: SecureOwnerWorkspaceSession;
declare const input: HistoricalOwnerAttachmentInput;
declare const material: string;

const inventory: Promise<HistoricalPackageStageOrphanInventory> =
  owner.inspectMultipartOrphanPackageStage(input, material);
const attached: Promise<HistoricalOwnerAttachmentResult> =
  owner.attachMultipartOrphanPackageStage(input, material);
inventory.then(value => {
  const index: number = value.part_index;
  const count: number | null = value.part_count;
  const status: 'ORPHAN_NO_PACKET' | 'APPLIED_IN_SIGNED_REPLAY' = value.status;
  void [index, count, status];
});
attached.then(value => {
  const stageId: string | null = value.orphan_replan_stage_id;
  void stageId;
});
// @ts-expect-error full material must be a JSON string
owner.inspectMultipartOrphanPackageStage(input, 123);
