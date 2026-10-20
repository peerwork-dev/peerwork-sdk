# SDK 0.1.7 experimental — workspace-scoped Owner attachment

This release fixes attaching a second workspace to an existing native Owner
profile whose legacy source also contains another workspace's history. SDK
0.1.6 required inbox receipts and coordination markers to belong to the selected
workspace and refused mixed sources.

The importer now routes supported workspace records before validating the
selected workspace. It preserves the other native workspace profiles and
attachment history, and leaves the original protected source files unchanged.
Foreign records are not imported into the selected workspace, acknowledged,
retired or replayed. Only the selected workspace's journal is queried for its
attachment proof; global Owner identity and source consistency checks remain.

A shared service-root comparison also accepts equivalent canonical URLs with
or without a trailing slash. This fixes false `IDENTITY_STATE` failures in
Owner installation and related consumers without changing saved profile
bindings. Different authorities, credentials, paths and query/fragment URLs
remain rejected.

Workspace routing covers inbox receipts, coordination markers, guard-time
action caches and retained commit responses, commit packets, field-policy and
package/object-install markers, intake bindings, configuration receipts and
workspace-local keyring/conversion metadata. Selected-workspace pending work
still requires its existing explicit recovery path. Unknown or conflicting
workspace bindings return `SOURCE_SCOPE_UNRESOLVED` or `SOURCE_SCOPE_CONFLICT`.
Identity-scoped operations and unsupported opaque legacy operation families
remain subject to their existing checks; this is not an arbitrary-state import.
The separate SQLite journal still requires its supported quiescent schema;
nonempty `client_operations` remains unsupported.

The [Owner migration guide](docs/owner-migration.md) describes the selection
boundary and existing Python, Node and CLI attachment interfaces. No new
attachment flag, service deployment, workspace recreation or identity reset is
required. Existing 0.1.6 completion archival and explicit local-retirement
semantics remain intact.

Qualification uses genuine isolated signed/E2EE workspaces: A retains 21 inbox
receipts and five coordination markers while the same native Owner attaches B,
retries, reopens both and preserves A's files, attachment and identity. Negative
cases cover conflicting scope, unknown/shared operations and selected-workspace
pending work. Installed Python additionally enables trusted time in existing B
and runs claim, renewal, expiry/reclaim and stale-generation rejection through
the native SDK. This is scripted synthetic engineering acceptance, not a natural
Agent workflow trial. Published availability requires the actual release assets
and checksum verification, not these source notes alone.
