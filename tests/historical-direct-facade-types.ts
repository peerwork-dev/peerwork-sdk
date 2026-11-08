import type {
  HistoricalOwnerAttachmentInput, HistoricalOwnerAttachmentResult,
  HistoricalDirectInstallPendingInventory, HistoricalDirectInstallCompletedInventory,
  SecureOwnerWorkspaceSession,
} from '../bindings/node/index';
declare const owner: SecureOwnerWorkspaceSession;
declare const input: HistoricalOwnerAttachmentInput;
declare const id: string;
declare const digest: string;
declare const options: string;
declare const material: string;
const packet: Promise<HistoricalDirectInstallPendingInventory> = owner.inspectPendingDirectInstallPacket(input, id, options, material);
const completed: Promise<HistoricalDirectInstallCompletedInventory> = owner.inspectCompletedDirectInstall(input, id, options, material);
const attached: Promise<HistoricalOwnerAttachmentResult> = owner.attachCompletedDirectInstall(input, id, digest, options, material);
owner.attachPendingDirectInstallPacket(input, id, digest, options, material);
owner.recoverPendingDirectInstallPacket(id, id);
completed.then(value => {
  const sequence: number = value.end_sequence;
  const begin: string = value.begin_command_id;
  const status: 'COMPLETED_IN_SIGNED_REPLAY' = value.status;
  void [sequence, begin, status];
});
// @ts-expect-error full material must be an explicit JSON string
owner.inspectCompletedDirectInstall(input, id, options, 123);
// @ts-expect-error attachment requires the inspected full-state digest and full material
owner.attachCompletedDirectInstall(input, id, options, material);
// @ts-expect-error explicit packet ID is required
owner.recoverPendingDirectInstallPacket(id);
void [packet, completed, attached];
