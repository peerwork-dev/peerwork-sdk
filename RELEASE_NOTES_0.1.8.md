# SDK 0.1.8 experimental — existing member recipient-key migration

This release adds the legacy member credential import missing from SDK 0.1.7.
Existing PRIVATE members can retain their original signing identity and import
their P-256 encryption key, signed certificate and historical recipient keys.
Joined, multi-workspace legacy source files no longer require an unjoined-only
internal test helper. Python, Node and CLI expose the operation explicitly.

Select the protected original member state and pin its exact SHA-256, actor and
signing key. The import is offline, checks each certificate/private-key pair,
retains original source files and refuses a different existing native recipient.
A same-source retry returns `ALREADY_IMPORTED`. Prepared legacy key rotations
require their original recovery path; credential import does not recover them.

PRIVATE grant acquisition also supports existing invitation-backed grants.
It retrieves the original invitation and signed ACCEPT, checks their bindings
with the existing grant verifier, and completes authenticated decrypted replay
before activating a keyring. Historical certificates use their matching imported
keys. It does not re-invite, re-accept or post another receipt. Direct-grant
verification is preserved; unrelated delegation proofs are not inferred.

See [the member migration guide](docs/legacy-member-keys.md) for Python sync/async,
Node and CLI examples and explicit failure codes. Generic read profiles bind one
workspace; use a separate protected native directory for each
member/service/workspace. Preserve the original identity when opening another
profile. Owner multi-workspace attachment is a separate interface.

Credential import does not import all old SQLite intents, pending packets,
coordination markers, receipts or checkpoints. Those remain in the protected
source and need their original recovery or explicit review. Keep the old writer
stopped and retain the source backup until that review is complete. No service
deployment, workspace recreation, identity replacement or permission change is
required for this migration.

Qualification uses two generated old members on one machine and two actual
isolated signed/E2EE workspaces. Both members rotate their directory keys while
the workspace grants still address historical certificates. Installed Python
and Node import and retry; CLI imports separate workspace profiles, reopens
without the source directories and submits authorized writes under the original
identities. The checks also reject cross-worker source selection and corrupted
invitation decision signatures. This is scripted engineering acceptance, not a
natural Agent workflow trial. All eight native targets passed. The exact GNU CI
packages passed all 41 cases across the member migration, multi-workspace/lease,
guard-time migration and coordination migration workflows. The public GNU archive
was downloaded anonymously; its CLI, wheel and Node packages matched the consumed
CI packages byte-for-byte. The remaining seven archive digests matched the release
checksum manifest.

Published assets: [v0.1.8-experimental.39420081848](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.8-experimental.39420081848).
Source: `b238caee2f6137041ea902563276396e37b2520c`.
Stable PyPI/npm publication is not implied.
