# AGY receiving in the current conversation

Native SDK 0.3.41 adds `peerwork_listen` for AGY CLI background MCP calls. The
existing conversation owns the call. When a compact inbox notification becomes
available, Peerwork returns it through the call. AGY is responsible for resuming
the conversation. The original conversation keeps its writer, and no App
control port or additional Agent is needed.

## Choose the receiving path

For an existing installation, start with `peerwork_delivery` status and keep
the original receiving binding. After a restart or update, request one fresh
self-test and let the original conversation read the batch in response to the
notification. If that works, setup is complete. A current self-test proves the
conversation can wake through its selected transport. The Workspace directory
label describes the transport's assurance.

| Active path | Receiving status when verified and current | What to do |
| --- | --- | --- |
| AGY App (`agy-app`) | `QUEUED` | Keep a working App binding. Queued input can wake the conversation promptly. Verify wake in that conversation. |
| Interactive AGY CLI with an unbound native inbox | `REALTIME` | On a compatible host, arm `peerwork_listen`, read a fresh notification in that conversation, and rearm. |
| Managed AGY ACP | `REALTIME` | Use when you explicitly want the managed host to own the session. Verify a fresh notification in that session. |

An existing `agy-app` receiver keeps its queue on upgrade or reinstall.
`--install agy` preserves the binding. A separate background listener requires
an unbound native inbox. If switching to inbox mode returns
`WATCH_BINDING_MISMATCH` for an already-bound receiver, keep its selected
host. `peerwork_listen` can report
`CLAUDE_CHANNEL_SOURCE_ALREADY_BOUND_TO_ANOTHER_HOST` for the same destination
conflict in AGY. Change transports only for an intentional change with a
supported transition for that receiver.

## Update or restore the current path

For a Peerwork-only update, use the [original stack updater](host-bridge-recovery.md#upgrade-the-original-receiving-stack),
refresh the original MCP entry through AGY's `/mcp` if its frontend is still
old, and check the loaded frontend and runtime versions. For an AGY CLI
update, check the executable path used by the original session launcher and
its `--version` under the original host account. An update run under a
different account can install another copy. Reopen the original conversation
with the selected executable if that session needs the new AGY build.

If an AGY App restart changed the local endpoint or token, refresh the
[original App host registration](native-session-connectors.md#antigravity-app)
from the owning host and keep the receiver, App binding, and conversation.
An externally managed installation that inherits its launch environment uses
its original launcher with the current App context. Keep credentials private.
Verify a fresh notification in the original conversation. `READY` and a
successful host queue write describe their own stages of delivery.

## Connect an interactive CLI

Use this path for an original native inbox without another host destination,
on an AGY installation that can complete a background MCP call in the same
conversation. Use the original Peer selection and existing grants.

```sh
peerwork connect --workspace WORKSPACE_ID --receive-mode inbox --install agy
```

Include `--local` and `--participant` only when selecting a known original
installation is necessary. Missing access or body keys follow the normal single
approval exchange; this transport creates no additional Workspace permission.

Refresh that MCP entry in AGY's `/mcp` manager. An existing conversation can keep
running; it needs its tools refreshed, not a new identity or a managed session.
The installer configures only the owned server entry:

```json
{
  "timeoutSeconds": -1,
  "tools": {
    "peerwork_listen": {"eager": true, "background": "always"}
  }
}
```

AGY's [MCP configuration](https://antigravity.google/docs/mcp) defines these
settings. `background: always` makes the call nonblocking on hosts that support
it. `timeoutSeconds: -1` disables AGY's MCP connection and tool timeouts. AGY
can still end a background task under its own task lifecycle. If that happens,
check the current listener state and rearm once when it is no longer armed.
If background execution is unavailable, use the inbox on demand.

The interactive wake test passed on AGY CLI 1.5.9. Interactive tests with
1.5.10 and 1.5.12 did not complete the session read. These observations apply
to the tested background MCP installations. Verify your current release and
receiving path in the original session. Starting a background task, or reading
its batch manually to check the inbox, does not verify automatic wake.

## Receive, work, and rearm

1. Call `peerwork_listen` with `{}` once. It watches the configured inbox aliases;
   an optional `scope` selects one. Keep working or end the turn. Do not wait on
   the background task, poll status, or start another listener.
2. On completion, read the returned `read.arguments` with `peerwork_inbox`. Only
   the compact reference is in the notification; bodies stay in the native inbox
   until that bounded read.
3. Rearm `peerwork_listen` with the returned `rearm.arguments` after the successful
   batch read and before handling the work. This preserves the original scope
   selection. A call completes after one notification. Reading the batch
   acknowledges the notification without consuming the work.
4. Handle the request and explicitly consume handled item references. For long
   work, acknowledge the next step and continue with the listener already armed.
   Self-tests need only the indicated inbox read and rearming.

The native receiver stores new messages while the model is busy or the listener
is being rearmed. Ordinary send/read/reply and pause tools remain available
during a wait. Cancelling a background task preserves pending work. Manual
pause/stop remains authoritative. With compatible0.3.43 components, arming the
listener opts this connection into receiving for its selected original source.
The latest committed activation receives; a superseded listener cannot reclaim
ownership by rearming or retrying. Ordinary tool calls do not replace receiving.
Claude Channels shares this source ownership. Legacy frontends need their normal
refresh or drain before replacement; the original inbox and pending work remain.

## Verify this conversation

With a listener armed, request `peerwork_delivery` `self_test`, then let the
background completion arrive. Read that exact batch through this conversation's
MCP tools and rearm. Once its receiver heartbeat is current, the Workspace
directory can report `REALTIME`. `host_channel` reports `MCP_BACKGROUND_TOOL`,
whether a listener is armed, and this connection's observed batch read. A previously
verified native inbox or another session's read does not qualify this connection.
Use a real second-Peer message and reply to test the service path separately.

`peerwork_delivery` status reports the loaded frontend and runtime versions.
Once this connection has armed the background listener, it also reports whether
that listener is armed and whether a notification is waiting for a batch read.
`RECOVERING` with an armed listener lets the same call retry a transient error.
`BACKGROUND_NOTIFICATION_READ_PENDING` means Peerwork wrote a completion to
this connection and is waiting for the conversation to read its batch.
`BACKGROUND_LISTEN_NOT_ARMED` means the current conversation should rearm once.

If the installed frontend is newer than the version reported by the current
conversation, refresh the original Peerwork entry in AGY's `/mcp` manager.
Then arm it once and run a fresh self-test. Keep a compatible runtime running.
If a completion stays unread despite reaching MCP, inspect or refresh that
entry through the same manager. Keep any working App or managed host binding.

## Resume an explicitly managed AGY session

Use this path when you intend to transfer session ownership to a managed
host. For a newly selected managed binding, Connect uses AGY's ACP
`session/resume` with the original session ID and project directory.

```sh
peerwork connect --workspace WORKSPACE_ID --agy-managed \
  --agy-executable /absolute/path/to/agy --agy-conversation ORIGINAL_SESSION_ID \
  --project /absolute/path/to/project --install agy
```

Use an AGY build that advertises ACP session resume and an authenticated host
account with writable AGY state. The managed process owns the selected session
while running. Release any previous owner using the host's ordinary lifecycle
before transferring control. The exact native MCP registration follows the
selected original Peer and Workspace. Managed ACP permits the selected native
MCP reads and ordinary collaboration tools for the active turn through the
host's one-call approval. Owner approvals, runtime controls and other tools
keep their normal host restrictions. Existing working stream-json and AGY App
bindings retain their selected adapter. See [host recovery](host-bridge-recovery.md).

Host acceptance starts an ACP prompt for the selected session. A read of the
exact inbox reference independently confirms notification delivery. An uncertain
host result leaves its original message readable and allows a later message to
advance after backoff. Use a second Peer's new signed message after restart to
verify the session you are relying on.
