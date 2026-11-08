import type {
  SecureSnapshotOptions, SecureReadOptions, SecureOwnerWorkspaceOptions,
  SecureInvitationOptions,
} from '../bindings/node/index.js';

declare const snapshot: SecureSnapshotOptions;
declare const read: SecureReadOptions;
declare const owner: SecureOwnerWorkspaceOptions;
declare const invitation: SecureInvitationOptions;
const snapshots: SecureSnapshotOptions[] = [snapshot, { ...snapshot, maxReplayCommits: 1 }];
const reads: SecureReadOptions[] = [read, { ...read, maxReplayCommits: 102400 }];
const owners: SecureOwnerWorkspaceOptions[] = [owner, { ...owner, maxReplayCommits: 27 }];
const invitations: SecureInvitationOptions[] = [invitation, { ...invitation, maxReplayCommits: 99 }];
// @ts-expect-error The budget is numeric, not a string-valued profile setting.
const invalid: SecureReadOptions = { ...read, maxReplayCommits: '102400' };
void [snapshots, reads, owners, invitations, invalid];
