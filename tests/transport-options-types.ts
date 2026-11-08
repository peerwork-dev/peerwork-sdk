import type { ClientConfig, KernelAccessOptions, PublicCatalogOptions, RecipientEnrollmentOptions,
  SecureIdentityDirectoryOptions, SecureInvitationOptions, SecureOwnerWorkspaceOptions,
  SecureReadOptions, SecureSnapshotOptions, TransportOptions } from '../bindings/node/index';
const transport: TransportOptions = { requestTimeoutMs: 15000, additionalRootPemFiles: ['ca.pem'] };
const config: ClientConfig = { origin: 'https://example', stateDir: '/state', transport: { requestTimeoutMs: 15000, additionalRootPemFiles: [] } };
const kernel: KernelAccessOptions = { origin: config.origin, journalPath: '/j', identityPath: '/i', transport };
const snapshot: SecureSnapshotOptions = { origin: config.origin, kernelJournalPath: '/j', readStatePath: '/r', lifecyclePath: '/l', identityPath: '/i', workspaceId: 'w', authority: 'a', ownerActorId: 'a', ownerKeyId: 'k', transport };
const read: SecureReadOptions = { origin: config.origin, stateDir: '/s', identityPath: '/i', workspaceId: 'w', transport };
const owner: SecureOwnerWorkspaceOptions = { origin: config.origin, stateDir: '/s', transport };
const catalog: PublicCatalogOptions = { origin: config.origin, transport };
const enrollment: RecipientEnrollmentOptions = { origin: config.origin, stateDir: '/s', transport };
const directory: SecureIdentityDirectoryOptions = { ...enrollment, identityPath: '/i' };
const invitation: SecureInvitationOptions = { ...enrollment, workspaceId: 'w', ownerActorId: 'a', ownerKeyId: 'k' };
void [kernel, snapshot, read, owner, catalog, directory, invitation];
// @ts-expect-error unknown transport fields are not public API
const invalid: TransportOptions = { certificateBytes: new Uint8Array() };
void invalid;
