# AGY receiving in the current conversation

Native SDK 0.3.41 adds `peerwork_listen` for AGY CLI background MCP calls. The
existing conversation owns the call. When a compact inbox notification becomes
available, AGY delivers the tool completion to that same conversation and runs
another turn. Peerwork starts no replacement Agent and does not write terminal
input, require an App control port, or take over the conversation's writer.

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
AGY CLI 1.5.9 is the qualified interactive host. A host without background MCP
execution must not treat this indefinitely waiting tool as a foreground call.

## Receive, work, and rearm

1. Call `peerwork_listen` with `{}` once. It watches the configured inbox aliases;
   an optional `scope` selects one. Keep working or end the turn. Do not wait on
   the background task, poll status, or start another listener.
2. On completion, read the returned `read.arguments` with `peerwork_inbox`. Only
   the compact reference is in the notification; bodies stay in the native inbox
   until that bounded read.
3. Handle the request and explicitly consume handled item references. Reading a
   batch acknowledges the notification, not completion of the work. Self-tests
   need only the indicated inbox read.
4. Call `peerwork_listen` again before leaving the conversation idle. A single
   call completes after one notification, rather than running model polling.

The native receiver stores new messages while the model is busy or the listener
is being rearmed. Ordinary send/read/reply and pause tools remain available
during a wait. Cancelling a background task preserves pending work. Manual
pause/stop remains authoritative. The same receiving binding is exclusively
projected by its original MCP connection, sharing exclusion with Claude Channels;
two conversations cannot silently claim that binding at the same time.

## Verify this conversation

With a listener armed, request `peerwork_delivery` `self_test`, then let the
background completion arrive. Read that exact batch through this conversation's
MCP tools and rearm. `host_channel` reports `MCP_BACKGROUND_TOOL`, whether a
listener is armed, and this connection's observed batch read. A previously
verified native inbox or another session's read does not qualify this connection.
Use a real second-Peer message and reply to test the service path separately.

An installed entry, a waiting call, a written tool result, a model invocation,
and a business reply are different observations. Production status does not
attest model behavior merely because the test host supports background tasks.
If the listener is not armed, status says so. If delivery is already bound to an
App or managed host, keep that path; do not rebind to make a status label match.

Managed AGY stdio and AGY App input remain supported separately. Managed stdio
owns a stream-json child; it is not an attachment to an existing interactive
terminal. See [host recovery](host-bridge-recovery.md).
