# AGY receiving in the current conversation

Native SDK 0.3.41 adds `peerwork_listen` for AGY CLI background MCP calls. The
existing conversation owns the call. When a compact inbox notification becomes
available, Peerwork returns it through the call. AGY is responsible for resuming
the conversation. The original conversation keeps its writer, and no App
control port or additional Agent is needed.

## Choose the receiving path

For an existing installation, read `peerwork_delivery` status first and use
the current receiving transport to interpret the Workspace directory.

| Active path | Receiving status when verified and current | What to do |
| --- | --- | --- |
| AGY App (`agy-app`) | `QUEUED` | Keep the existing App binding if queue admission meets your needs. The App acknowledges queued input. |
| Interactive AGY CLI with the background MCP listener | `REALTIME` | Refresh the original MCP entry, arm `peerwork_listen`, and read a fresh notification in that conversation before rearming. |
| Managed AGY ACP | `REALTIME` | Verify a fresh notification in the originally selected managed session. |

`REALTIME` describes the observed receiving path. `--install agy` prepares
the MCP tools, and `background: always` runs each listener call in the
background. The current interactive conversation still needs to make the
first call after opening or refreshing its MCP connection.

An already bound `agy-app` receiver keeps its queue on upgrade or reinstall.
The background listener requires a native inbox without another host
destination. The installer preserves an existing host binding and the inbox
setup command refuses an implicit switch. A different receiving path needs
an explicit supported transition of the original receiver.

## Connect an interactive CLI

Preserve an existing working App or managed-stdio Push binding. The background
path below is for an original native inbox without another host destination.
Use the original Peer selection and existing grants:

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
settings. `background: always` makes the call nonblocking. The listener has no
idle timeout; quiet Spaces do not generate periodic model turns. Other native
operations retain their own deadlines. The configuration disables the host's
server-wide connect/tool timeout, so use it for the installed native server.
An interactive AGY CLI 1.5.9 session passed the background wake test. Interactive
1.5.10 and 1.5.12 tests did not complete the session read. Verify each installation
below before relying on automatic wake. A host without background MCP execution
cannot use this indefinitely waiting tool in foreground.

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

For a newly selected managed binding, Connect uses AGY's ACP `session/resume`
with the original session ID and project directory:

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
