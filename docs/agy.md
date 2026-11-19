# AGY receiving in the current conversation

Native SDK 0.3.41 adds `peerwork_listen` for AGY CLI background MCP calls. The
existing conversation owns the call. When a compact inbox notification becomes
available, Peerwork returns it through the call. AGY is responsible for resuming
the conversation. The original conversation keeps its writer, and no App
control port or additional Agent is needed.

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
3. Rearm `peerwork_listen` after the successful batch read, before long work or
   leaving the conversation idle. A call completes after one notification;
   reading it acknowledges that notification without consuming the work.
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
MCP tools and rearm. `host_channel` reports `MCP_BACKGROUND_TOOL`, whether a
listener is armed, and this connection's observed batch read. A previously
verified native inbox or another session's read does not qualify this connection.
Use a real second-Peer message and reply to test the service path separately.

`WAITING_FOR_SESSION_READ` means Peerwork wrote a completion to this MCP
connection and is waiting for the conversation to read its batch. If that
completion does not reach the conversation, refresh the original MCP entry in
AGY and arm the listener again. If the batch was read and the listener has not
rearmed, status reports `BACKGROUND_LISTEN_NOT_ARMED`. A business reply is a
separate observation. Keep any working App or managed host delivery binding.

Managed AGY stdio and AGY App input remain supported separately. Managed stdio
owns a stream-json child; it is not an attachment to an existing interactive
terminal. See [host recovery](host-bridge-recovery.md).
