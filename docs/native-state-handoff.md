# Native state, identity and session transitions

Use the native0.3 experimental interface and the matching public release.
The service must advertise `native-mailbox-v1`; a physical session change also
requires `native-mailbox-rebind-v1`. These operations use the original selected
identity, encryption material and durable operation IDs. They are operator
interfaces, not capabilities granted to ordinary Peer MCP tools.

| Change | Interface | What stays unchanged? |
| --- | --- | --- |
| Replace a native binary | Stop its owning runtime, replace the executable, restart the same configuration | Original identity/key paths, state, profiles and selected session |
| Move an existing native engine's local indexes | `runtime transfer-engine` | Original identity, native journal/body-key paths, cursors and selected host |
| Select a different physical Agent session | `runtime rebind-host` | Original logical participant, encryption material, mailbox history and original calls |
| Preserve a published Node receiver/bridge's local evidence | `runtime import-node-delivery` | Original source retained; old facts are archived, never relabelled as native mail |
| Update a business protocol | Its declared publish/adopt/action interfaces | Client identity and existing native state do not migrate implicitly |

## Replace a native binary

Stop the runtime that owns the selected state using its protected admin
endpoint. Replace only the installed executable and restart the same runtime
configuration. Do not clear a journal, generate another identity, move key files
or replay unknown operations as a substitute for recovery. `LOCAL_READY` proves
only local ingress; observe current receiver/host facts after restart.

This is different from starting another consumer. When changing from an older
client family, first identify its actual state format and supported transition.

## Move native indexes on the same host

Stop the selected runtime or embedding program first:

```sh
peerwork runtime transfer-engine /private/runtime.json peer-1 /private/peer-next
peerwork runtime run /private/peer-next/transferred-runtime.json
```

Start only after `TRANSFER_READY`. The command snapshots encrypted local indexes
and preserves actor/Origin, authority, grants, mailbox identities, cursors and
original queued/accepted/unknown facts. It does not change the Agent session.
Identity, journal and body-key paths remain at their original locations; retain
those files even after indexes move. Cross-host/key relocation is outside this
command. On interruption repeat the exact original command and destination;
never clear source/target fences or copy over later target writes.

## Change the selected physical session

Prepare and authorize the target host adapter. Stop the selected runtime and
any other writer of its engine/journal. Keep the original configuration and
protected state in place. Select one existing engine and host-group name from
that configuration. For example, a protected request file can contain:

```json
{
  "format": "peerwork.host-rebind.v1",
  "operation_id": "move-peer-session-1",
  "engine": "peer-1",
  "host": "peer-session",
  "adapter": {
    "kind": "codex",
    "endpoint": "unix:///private/codex/control.sock",
    "thread_id": "explicit-loaded-thread-id",
    "expected_session_id": "session-id-returned-by-the-host"
  }
}
```

Use a host-supported endpoint on the selected platform. The example is a Unix
socket; Windows configurations use the selected WebSocket endpoint. AGY CLI
uses its scoped host-user bridge adapter, not a fabricated App Sidecar path.
The operator selects the real target conversation and grants its access;
this request does not discover or start a replacement model.

```sh
peerwork runtime rebind-host /private/runtime.json /private/rebind.json
```

One invocation finishes the selected engine's subscriptions, including bounded
internal pages. It owns report flushing, exact signed remote continuation,
local binding commit and configuration update. It retains encrypted frames,
receiver keys, cursors and original host-call facts. Scopes can commit in stages;
this is not one global transaction across every mailbox.

`HOST_REBIND_READY` means the configuration committed. Restart the owning runtime
with that updated configuration and observe current delivery readiness. It does
not attest model output or business completion. After interruption or an unknown
remote outcome, repeat the **same configuration/request/operation ID**. Do not
switch host selection or invent another operation to escape uncertainty.

### Recover a definite rejection

An explicit no-effect rejection can be retried using a protected decision file:

```json
{
  "format": "peerwork.host-rebind-recovery.v1",
  "decision_id": "retry-rejected-claim-1",
  "action": "RETRY_REJECTED"
}
```

```sh
peerwork runtime recover-host-rebind /private/runtime.json /private/rebind.json /private/decision.json
```

The SDK verifies the retained rejection before allowing a new attempt. Unknown
claims keep their original IDs. `ABORT` is the other explicit decision action;
it is allowed only before a replacement commits. Once any mailbox changed,
finish the original operation forward. An abort returns `HOST_REBIND_ABORTED`
and preserves the original configuration for restart. Recovery never converts
an old unknown input into a new automatic injection.

Rust applications can use `participant_rebind::HostRebindRequest`,
`rebind_host` and `recover_host_rebind` from `peerwork-runtime`; their schemas and
state transitions are the same as the CLI.

## Published Node evidence and custom listeners

Use `runtime import-node-delivery` only for the published Node receiver/bridge
format with its exact binding and an explicitly stopped original owner. The
[selection reference](participant-runtime-candidate.md#selected-published-node-delivery-evidence-import)
describes `source_stopped`, source/archive directories and identity binding.
Keep the source lock and records; the importer will refuse a live owner.
It preserves selected original strings, statuses, receipts and hashes as
`LOCAL_LEGACY_EVIDENCE_NOT_REVERIFIED`. It creates no native message, service ACK
or model-completion claim. A later physical host change is a separate operation.

A custom Python/Node poller's JSON files are not that receiver format. Preserve
its own checkpoints and outstanding work; do not submit them to the Node
importer or reinterpret a business-event cursor as a native mail cursor.
Enabling native mailbox communication is a separate explicit grant under the
original participant. Communication grants, business roles and body-key access
remain separate. Moving custom application waiting work requires its own
supported handoff; a binary upgrade does not silently rewrite the application.

## Shared ancestors in native0.3.4

A shared project ancestor is not a reason to replace an identity or copy history.
See the [current connect guide](participant-connect.md#shared-projects-and-private-state-native034)
for protected user bookkeeping and the original local registry's one-time
OS-owner confirmation. Full paths stay local; Workspace Owners approve remote
permissions, not filesystem configuration.
