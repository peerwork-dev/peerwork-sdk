# Launch local Peer sessions

A coordinator can start independent Peers on Linux through one owner-local
interface. The existing resident Peerwork runtime keeps the Peer identities,
mailboxes, journals, and delivery routes. A managed Codex session uses a
private App Server. Managed OpenCode V2 sessions use the original registered
service in the selected project. Managed AGY uses ACP to resume the selected
conversation in its original project.

## Authorize the selected installation

Use the original private Connect registry. Prepare one enrolled Peer with its
own inbox for each independently addressable session. Commit the harness
installation for each Peer in the chosen project. Use existing Space rights
and body keys. If those rights are missing, complete the ordinary enrollment
before enabling launch. The registered resident runtime must support live
receiver rebind. Keep the coordinator's frontend pinned to its own participant
and Space.

As the local installation owner, put a private file named
`session-launch.json` in that registry. This example authorizes the
`coordinator` frontend to use the listed Peers.

```json
{
  "format": "peerwork.session-launch.v1",
  "controller": "coordinator",
  "workspace_id": "REPLACE_WITH_EXACT_WORKSPACE_ID",
  "peers": {
    "builder": {"harness": "codex"},
    "reviewer": {
      "harness": "opencode",
      "service_file": "/path/to/original/opencode/service.json"
    },
    "researcher": {
      "harness": "agy",
      "executable": "/path/to/agy",
      "conversation_id": "REPLACE_WITH_EXACT_AGY_CONVERSATION_ID"
    }
  }
}
```

The file must be owner-private. Launch selects the Peer’s existing unique
committed project for the chosen harness. OpenCode must expose the intended
Peerwork MCP entry for that project without a conflicting Peerwork entry. For
AGY, enroll the intended Peer with its native inbox and commit its AGY MCP
installation. Select an existing ACP-resumable conversation from that project
that is available to the local owner. The resident runtime must support managed
AGY rebind. The harness uses the local account's model login and tool approval
policy. Space membership does not authorize host execution.

## Launch, verify, and stop

Call `peerwork_session` from the authorized local MCP frontend. Its schema
lists the handles the installation owner has configured for this coordinator.
For a Peer that is already receiving, use ordinary Space messaging.

```json
{"request":{"mode":"start","operation_id":"audit-builder","peer":"builder"}}
```

Or use the same operation through the owner CLI.

```sh
peerwork session --local /path/to/registry start --id audit-builder --peer builder
peerwork session --local /path/to/registry status --id audit-builder
peerwork session --local /path/to/registry stop --id audit-builder
```

Use a second ID and Peer for another session. A start returns `STARTING`
until the selected local route reports that the new session has actually read
a fresh probe. Wait for `READY` before dispatching work. Then use the ordinary
Space protocol with separate task operation IDs. A ready session has verified
automatic receiving. Its work completion is a separate protocol outcome.

Follow the response's `next_action` using the original launch ID. A pending
start can need another `start` for the exact original Peer or a later `status`
check while the receiving probe is in progress. A duplicate start reports the
original launch. If the Peer has an existing receiving route, check that route
and use it when ready. To move this Peer's receiving deliberately, use
[Codex handoff](host-bridge-recovery.md#move-this-peers-receiving-to-a-successor-codex-session)
where supported.

Stop pauses notification dispatch on just the selected managed route and waits
for a verified idle state. Follow the returned `next_action` with the original
ID. The `stop_effect` in the final response reports whether the dedicated Codex
App Server exited or the OpenCode or AGY receiving route retired. OpenCode and
AGY preserve the selected conversation and stop dispatching Peerwork input to
it. The identity, inbox, and operation journal remain available. A stopped ID
stays stopped.
For new work use a new launch ID with an available enrolled Peer.
