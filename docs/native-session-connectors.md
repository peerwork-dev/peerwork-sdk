# Connect an existing Codex or Antigravity App conversation

SDK 0.2.16 adds native existing-session transports and a scoped local host bridge.
The service must advertise `native-host-queue-v1` for Antigravity App queue
receipts. Check actual release assets and discovery before using this capability.
Core SDK identities, E2EE keys, grants and existing receiver checkpoints stay in
their original profile; this is not an identity migration.

## Codex: attach to the original App Server

Use the endpoint of the App Server that actually hosts the selected live thread.
Unix control sockets speak WebSocket over HTTP Upgrade, not JSONL. The connector
performs that handshake, initializes one connection, checks that the exact thread
is already loaded, then subscribes with `excludeTurns: true`. It does not start
another App Server or recreate a stored conversation.

```json
{
  "kind": "codex",
  "endpoint": "unix:///private/codex/app-server-control.sock",
  "thread_id": "EXISTING_THREAD_UUID",
  "expected_session_id": "EXPECTED_SESSION_TREE_ROOT_UUID"
}
```

`expected_session_id` is optional but recommended when the host supplies it.
Use an absolute Unix socket path or a pinned `wss://` endpoint. Plain `ws://`
is restricted to loopback. WebSocket bearer authentication uses
`auth_token_env: "YOUR_HOST_TOKEN_ENV_NAME"`; put the token in that environment,
not the URL or command line. TLS verification is never disabled.

The connector targets the exact active turn when steering; an unknown active
turn does not authorize guessing. Initial active-turn lookup is limited to one
turn with items omitted. Disconnecting the connector closes its own connection,
not the shared App Server. No permission or model overrides are submitted.
Errors distinguish socket access, connection, handshake, initialization and
session binding failures. A failure before a turn submission is not a lost
model acknowledgement.

The previous implicit `codex app-server --listen stdio://` launch is removed.
Users intentionally managing a separate CLI server must select `managed: true`;
that explicit mode retains the stdio adapter, and is not existing-App attachment.
The same explicit opt-in is required for `kind: "agy-cli"`. No adapter silently
falls back to a managed/headless process.

## Antigravity App: native Sidecar API

Run the host adapter within an enabled Antigravity App sidecar. The App supplies
its own `agentapi` command. This is Google's sidecar API, not Coder's archived
same-named terminal wrapper. The adapter invokes only:

```text
agentapi send-message EXISTING_CONVERSATION_ID MESSAGE_REFERENCE
```

It never invokes `new-conversation`, `agy --conversation` or permission-bypass
flags. Example host configuration:

```json
{
  "kind": "agy-app",
  "conversation_id": "EXISTING_CONVERSATION_ID",
  "inbox_directory": "/private/project/.peerwork-host-inbox"
}
```

Inside a sidecar, the adapter resolves the App-supplied executable from PATH;
outside that context, an explicit absolute `agentapi_path` is required. If no
inbox directory is selected, the sidecar's executable data directory is used.
The selected directory must be private. Choose a directory readable under the
original conversation's existing file-access policy; an approval request is not
a reason to bypass that policy.

Private message bodies are written to a 0600 JSON file in this directory.
The native command receives only an opaque file reference, keeping decrypted
content out of process arguments and normal command logs. The prompt identifies
it as external peer data and asks the original Agent to read it using its usual
tools and permissions. The adapter retains these files because API queue
acceptance does not prove the Agent has read them. It caps them at 64 files of
at most 64 KiB and applies backpressure when full. Remove only files whose
processing has been confirmed; no timed cleanup discards unprocessed messages.
This local inbox is separate from workspace storage.

The documented native API establishes queue submission, not model execution.
The adapter therefore reports `HOST_QUEUED`, `execution_state: UNKNOWN`, and
`QUEUED_ONLY` / service `TOOL_ONLY`, never `REALTIME_READY`. Queue acknowledgement
advances the delivery checkpoint without resending the same input. A signed,
correlated application reply is still the evidence that the Agent processed it.
CLI exit failure/timeout has an unknown result and is not blindly retried.
Busy-turn scheduling and permission prompts remain owned by Antigravity App.

## Different system users: scoped local host bridge

When the Peerwork signer is `agent-user` and the original host is Root, keep
them separate. Run the host bridge as the host user; run the receiver as the
Peerwork identity's user. Do not change the original socket's permissions or
move identity/key files. The bridge exposes only health, selected-message input,
pending host requests for its configured conversation. Permission responses
are disabled by default; delegating them requires explicit
`allow_permission_responses: true` in the host-owned bridge configuration and
still rejects requests from any other thread.
It does not expose arbitrary App Server RPC or a shell endpoint.

Create a new capability token **as the Peerwork identity's user**:

```sh
peerwork-host-bridge token /private/master/host-bridge.token
```

The token file is created with 0600 permissions and cannot overwrite an existing
file. Only its path is printed/configured. The bridge user needs permission to
read that file; Root can read it without changing the original identity owner.
If different non-root users need access, explicitly provision the capability to
them through the user's normal mechanism. No global socket permission change is
part of this tool.

Prepare a private bridge configuration for the host user:

```json
{
  "port": 40817,
  "token_file": "/private/master/host-bridge.token",
  "state_directory": "/private/host/peerwork-bridge",
  "host": {
    "kind": "codex",
    "endpoint": "unix:///private/codex/app-server-control.sock",
    "thread_id": "EXISTING_THREAD_UUID"
  },
  "bindings": [{
    "expected_origin": "https://api.peerwork.dev",
    "expected_actor": "EXPLICIT_ACTOR_ID",
    "workspace_id": "WORKSPACE_ID",
    "instance_id": "INSTANCE_ID",
    "protocol_digest": "EXECUTION_SHA256",
    "package_digest": "PACKAGE_SHA256",
    "role": "EXACT_GRANTED_ROLE"
  }]
}
```

For AGY, replace `host` with the `agy-app` configuration and launch this bridge
from the enabled sidecar using an absolute `peerwork-host-bridge` executable
and arguments `["run", "/private/host/bridge.json"]`. Follow the App's normal
explicit sidecar enablement flow; the SDK does not edit user App configuration.

```sh
peerwork-host-bridge run /private/host/bridge.json
```

The bridge binds only 127.0.0.1, requires the capability on every call, rejects
browser-origin requests and pins the full Peerwork binding and host destination.
It prints its endpoint and exact destination, not the token. Configure the
receiver's `host` with that reported destination verbatim:

```json
{
  "kind": "bridge",
  "endpoint": "http://127.0.0.1:40817",
  "token_file": "/private/master/host-bridge.token",
  "destination": {
    "host": "CODEX_APP_SERVER",
    "conversation_id": "EXISTING_THREAD_UUID",
    "endpoint": "unix:///private/codex/app-server-control.sock"
  }
}
```

An AGY destination contains `host: "ANTIGRAVITY_APP"` and its explicit
`conversation_id`; use the bridge's reported object. Keep each receiver's
existing private state directory. Its stored destination digest must match;
changing destinations requires an explicit new selection, not a silent rebind.
No change to a Worker identity or workspace grant is implied.

The bridge durably records attempted input hashes and outcomes. A lost HTTP
response reconciles the original message ID; changed input under the same ID is
refused. An unknown host outcome is retained across bridge restart and requires
the existing explicit receiver resolution flow. It retains up to 256 recent
completed/unknown entries, never evicts unresolved attempts to make room, and
owns one locked state directory. Receiver checkpoints remain the authority for
old committed events; clearing them is not a supported retry mechanism.

## Start and verify

Use Node24 and matching release assets. The host bridge does not open the
Peerwork identity or require native signing keys; only the receiver does.

```sh
peerwork-connect doctor /private/master/delivery.json
peerwork-connect run /private/master/delivery.json
peerwork-connect status /private/master/delivery.json
```

`doctor` checks the host connection without a model turn. Automatic startup
self-testing sends one explicitly identified probe to the original conversation;
it may incur provider cost. Codex can attest host input acceptance. AGY reports
only native queue acceptance, which is reflected in its self-test report.
Neither is a model PONG. Preserve the original pending message/intent when
recovering. Do not reset checkpoints or select a different Agent to make a test
appear successful.

Acceptance uses real Unix WebSocket and HTTP transports, synthetic host peers,
actual cross-UID IPC and real Peerwork HTTP/PostgreSQL/native receipts. This does
not qualify a particular installed Antigravity App/Codex version or the user's
actual live conversation. The user must explicitly enable/register that host
endpoint and conversation; missing endpoints fail rather than creating an Agent.

References: [Codex App Server](https://learn.chatgpt.com/docs/app-server),
[Antigravity Sidecars](https://antigravity.google/docs/sidecars).
