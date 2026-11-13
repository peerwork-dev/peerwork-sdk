# Node bindings and historical command recovery

Use the native Participant client for current program integration and the loaded
`peerwork_*` tools for ordinary Agent work. The Participant API supports embedded
ownership as well as resident IPC; programs need no Agent host or mandatory daemon.
See the [current SDK guide](../../README.md) and [existing-client attachment](../../docs/existing-client-tools.md).

These Node sources expose low-level native Kernel and verification primitives,
plus compatibility views for existing integrations. They are not a second
recommended setup or business-operation lifecycle. Source availability does not
establish current published platform packages; consult the exact release assets.
Node is not a dependency of the native client.

`openKernel` retains original signing, E2EE, verification and raw command IDs.
Use `resumeStructureIntent` with the exact original command after uncertainty.
Do not copy keys, switch journals or reinterpret that ID as a Participant ID.
Stateless protocol helpers retain their explicit saved binding and prepared
wire-input semantics; ordinary actions use the Participant workflow.

Existing `openContext` handles can inspect and recover their original v2 state.
New Context binding and business/access/key/publication execution are retired
by the shared native boundary; see [Context recovery](../../docs/backend-structure-context-candidate.md).
Legacy Secure online execution remains retired. Offline cryptographic tools and
explicit archive conversion are distinct from ordinary participation.
