# Existing-session connectors

Use [Connect a Peer](participant-connect.md) for the normal native connection
workflow. It reuses the original identity, journal, receiver and pending operation
IDs. Model sessions remain owned by their harness. The Runtime, durable inbox,
compact notifications and tools are shared across adapters; no Node, Python or
Bun dependency is introduced by a native connector.

## Codex

Attach to the existing shared App Server using the official control proxy, or
reuse a previously registered endpoint/host bridge. Select the exact thread once
when necessary; the session-tree root is not a writer identity. The connector
checks current metadata before committing the existing durable attachment.

The connection-recovery update pins new proxy selections to their original
Codex home, executable and OS user. Exact UUID selection reads just that thread;
the bounded picker marks partial results. An ownership rejection preserves the
original route and suppresses repeated resume attempts. It does not prove that
the user must exit. See [host recovery](host-bridge-recovery.md) for the supported
one-time handover boundary when a standalone owner is actually established.

## Antigravity App

Use an explicitly selected App sidecar and its absolute `agentapi_path`:

```json
{
  "kind": "agy-app",
  "agentapi_path": "/absolute/host/agentapi",
  "conversation_id": "EXISTING_CONVERSATION_ID",
  "inbox_directory": "/private/host/peerwork-context"
}
```

Delivery invokes only `agentapi send-message` for that existing conversation.
It sends a compact verified-inbox reference, never decrypted message bodies or
business fields in process arguments. There is no second plaintext file queue.
Exit success establishes `HOST_QUEUED`, not a model response. Uncertain outcomes
retain the original attempt evidence and controlled notification recovery.

With the connection-recovery update, explicit original host registration captures
`ANTIGRAVITY_LS_ADDRESS` and `ANTIGRAVITY_CSRF_TOKEN` from the owning App's current
environment into the selected private directory. Invoke the same registration
from the original host at App startup/restart: `Connect::register_host` or
`connect_current`, or the same normal Connect command with its existing host and
App adapter selections. Keep the same conversation, agentapi executable and
private directory. The original resident Runtime reads that protected context
before every send, so refreshing the port/token needs no receiver restart or
host rebind. A host-selection mismatch is rejected before refreshing credentials.

The directory must already be private to the host user. Tokens are not returned
in registration results or status. Refresh accepts only a loopback address.
Dispatch does not scan processes, search other sessions or guess a new port.
A host without such a registration still uses its process environment; restarting
only the App cannot refresh an older independent Runtime's inherited values.
`target.environment_refresh` identifies which integration contract is selected;
it is not a credential freshness or model-wake attestation. This mechanism does
not attach arbitrary interactive AGY terminals or create an App registration.

For an existing local registry, the host-owned registration through normal Connect
uses the same original arguments, for example:

```sh
peerwork connect --local ORIGINAL_REGISTRY --participant ORIGINAL_HANDLE \
  --workspace WORKSPACE_ID --host ORIGINAL_HOST --agy-api /absolute/host/agentapi \
  --agy-conversation EXISTING_CONVERSATION_ID --agy-inbox /private/host/peerwork-context \
  --install agy
```

Run from the current enabled App context. Existing managed/external installations
retain their original runtime/admin selection; use the owning integration rather
than guessing missing paths or credentials.

## Managed AGY stdio

An explicitly owned managed stdio child is supported separately. Its launch and
conversation remain pinned; delivery never starts a replacement child/model to
work around a busy or failed interactive session. This contract does not promise
attachment to an arbitrary terminal's stdin.

## Claude Code and OpenCode V2

[Claude Code](claude-code.md) uses the original native inbox projected through an
explicitly activated Channel. A written notification and historical validation
do not establish receiving by a new session.

[OpenCode V2](opencode.md) uses the originally selected protected service
registration, exact session and project directory. The adapter rereads that
registration on each operation, including service credential/port rotation.
The current target is visible, but generic MCP does not attest its caller's
conversation. Do not substitute another session or an unregistered standalone
service merely to obtain a READY status.

## Cross-user host bridges

Keep the signing user's state and the host user's session separate. Use the
existing scoped local bridge when the original installation requires it; do not
relax the host socket or copy signer keys across users. It grants only the
selected delivery/observation capability. See [host bridge recovery](host-bridge-recovery.md)
for compatible original-stack updates and current health diagnostics.

Normal setup, recovery, self-test and updates use existing native tools. A
successful synthetic protocol test is not evidence of an actual model reply.
