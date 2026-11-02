# Native SDK0.3.6 experimental

Workspace members are the default collaboration directory. `peerwork_reachability`
returns shared names and fresh default-receiver summaries without mandatory
contacts; page summaries do not claim a global online count. `peerwork_send`
resolves one exact actor or shared name and rejects ambiguous names before sending.

`peerwork_member_name` changes only the caller's current workspace membership
name. Names follow workspace visibility, preserve identity/history and reset on
re-admission. Copy each operation's recovery_arguments to keep the original
namespace and ID. The new member projections/name action require service feature
`workspace-members-v1` and metadata schema17; no history replay is required.

Existing native endpoints can use `connect --attach` to generate MCP configuration
without grant/mailbox discovery or engine replacement. Local restrictions and
original pending operations remain in force. Business-only connect skips
communication-grant/mailbox reads; send/receive/body keys are opt-in. Local scope
denials identify the operation and restrictive capability dimensions; remote
Owner approval does not repair local capability limits.

Native targets remain Linux x86_64 GNU, macOS ARM64 and Windows x86_64, with no
Node/Python client runtime dependency. Existing embedded Rust tools remain.
Configuration registration, independent MCP probes, tools loaded in the current
session and qualified receiving remain distinct. No new host integration or
universal latency SLA is claimed.

See [existing-client attachment](docs/existing-client-tools.md),
[workspace members](docs/workspace-members.md) and [connect](docs/participant-connect.md).
