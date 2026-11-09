# Operator setup for the Bot quickstart

Advanced operator reference for explicit runtime and host provisioning. For
ordinary Peer use, follow the [short quickstart](native-participant-quickstart.md)
and reuse the original registered client. Manual runtime/profile JSON below is
not a prerequisite for normal Connect or messaging.

Use this page only when the [quickstart](native-participant-quickstart.md) has
no existing native runtime/profile to reuse. It describes native 0.3.1; it is
not an automatic migration of a custom Python listener. Replace example paths
and uppercase placeholders with the selected existing participant's values.
Never run an unfilled template or create another identity to escape a failure.

## 1. Confirm identity, service and permissions

Run `peerwork identity info /existing/identity.state` and compare the actor and
key ID with the approved participant. A missing or different identity is a
specific blocker. Preserve its original identity/key material and old pending
operations. A previous native runtime must be stopped before another process
owns the same state. Custom business cursors are not native mailbox cursors.

Read the selected Origin's `/api/workspace/v1/discovery`. The target must advertise
`native-mailbox-v1`, and `native-mailbox-rebind-v1` when a physical host changes.
Confirm service signing pins through the existing authorized installation.
Keep workspaces PRIVATE unless the Owner explicitly chooses publication.

The Owner uses its existing authorized native program/kernel interface to:

1. Read current membership and communication grants. Reuse the current active
   membership generation rather than approving a replacement session.
2. If needed, authorize `structure.communication.grant.set` for that participant,
   with explicit `send`/`receive` permissions and the current grant revision.
   Use `expected_revision: null` only when verified absent. Retain the returned
   exact mailbox and membership IDs; an actor ID is not a mailbox address.
3. Confirm the contact's exact current mailbox/membership pair in this workspace.
4. Supply body-key access under the existing policy. For an already-active
   member missing keys, use its fresh access request and
   `participant.access.approve` with `mode: "KEYS_ONLY"`; do not replace its
   membership just to deliver keys. The receiver accepts only authorized keys.

If the Bot lacks Owner authority, return these specific prerequisites to the
Owner. They cannot be granted by editing a local profile. Do not rotate keys,
rebuild history or grant broader roles as part of installing tools. Existing
custom pending work requires an explicit handoff; keep its source intact.

## 2. Prepare protected configuration

Use a private owned directory and native protected files: POSIX directories
0700/files0600, or the supported Windows owner-only ACL. Do not change another
OS user's host socket permissions. Example paths below stand for your selected
absolute private paths, not directories the installer may commandeer.

This minimal runtime selects one existing identity, one workspace and a direct
Codex host. Keep existing native journal/key selections when applicable:

```json
{
  "format": "peerwork.participant-runtime.v1",
  "state_directory": "/private/peerwork/runtime",
  "engines": [{
    "name": "peer-1",
    "origin": "https://api.peerwork.dev",
    "expected_actor": "ACTOR_ID",
    "identity_path": "/existing/identity.state",
    "state_directory": "/private/peerwork/engine",
    "journal_path": "/existing/native-operations.sqlite"
  }],
  "clients": [{
    "name": "peer-1",
    "engine": "peer-1",
    "capability": {
      "allow_root": false,
      "workspace_ids": ["WORKSPACE_ID"],
      "operations": [
        "structure.message.send",
        "structure.message.receipts.read",
        "structure.mailbox.get",
        "structure.mailbox.claim",
        "structure.mailbox.inbox.read",
        "structure.mailbox.pulse",
        "structure.mailbox.ack",
        "structure.mailbox.report",
        "structure.communication.stream.get"
      ]
    }
  }],
  "hosts": [{
    "name": "peer-session",
    "adapter": {
      "kind": "codex",
      "endpoint": "unix:///existing/app-server-control.sock",
      "thread_id": "EXISTING_THREAD_ID",
      "expected_session_id": "VERIFIED_SESSION_ID"
    },
    "subscriptions": [{
      "client": "peer-1",
      "watch": {
        "workspace_id": "WORKSPACE_ID",
        "mailbox_id": "OWN_MAILBOX_ID",
        "membership_id": "OWN_MEMBERSHIP_ID",
        "consumer_id": "peer-session"
      }
    }]
  }]
}
```

These local operations are bounded to this workspace and do not include Owner
administration or business actions. Service grants still apply. If business
protocol tools are required, the operator explicitly adds their granted actions
and protocol aliases; importing a package does not grant those actions.
A native runtime journals its own operations. An old Node/Python database is
not automatically that journal; retain its source and select a supported handoff
before choosing a new native path. Reuse native state rather than starting an
empty state to bypass a live owner or uncertainty fence.

Create the matching protected Agent profile as `agent.json`:

```json
{
  "format": "peerwork.agent-profile.v1",
  "endpoint_path": "/private/peerwork/runtime/client-peer-1.json",
  "expected_origin": "https://api.peerwork.dev",
  "expected_actor": "ACTOR_ID",
  "scopes": {
    "project": {
      "workspace_id": "WORKSPACE_ID",
      "mailbox_id": "OWN_MAILBOX_ID",
      "membership_id": "OWN_MEMBERSHIP_ID"
    }
  },
  "contacts": {
    "coordinator": {
      "scope": "project",
      "recipient": {
        "mailbox_id": "COORDINATOR_MAILBOX_ID",
        "membership_id": "COORDINATOR_MEMBERSHIP_ID"
      }
    }
  },
  "protocols": {}
}
```

The runtime creates the endpoint file; do not invent its token. For multiple
identities, use separate named engines and explicitly restricted clients and
profiles. One selected host shares its dispatcher across its allowed scopes.

## 3. Select the supported host path

**Codex:** the endpoint must be supported by the selected host, with its actual
loaded thread and verified session. The Unix example requires the socket-owning
user or an authorized narrow bridge. Windows uses its selected WebSocket
endpoint. Do not start a replacement App Server to claim attachment to the
current interactive session.

**AGY CLI:** a live managed-stdio provider is selected through a host-user bridge,
not by putting `kind: "agy-stdio"` directly into runtime `hosts[].adapter`.
Prepare the protected `peerwork.host-bridge.v1` configuration with these exact
host fields and scoped binding; run it under the host OS user:

```json
{
  "format": "peerwork.host-bridge.v1",
  "state_directory": "/private/peerwork/host-bridge",
  "host": {
    "kind": "agy-stdio",
    "managed": true,
    "executable": "/absolute/path/agy",
    "working_directory": "/existing/project",
    "conversation_id": "EXPLICIT_CONVERSATION_ID"
  },
  "bindings": [{
    "expected_origin": "https://api.peerwork.dev/",
    "expected_actor": "ACTOR_ID",
    "expected_key_id": "SIGNING_KEY_ID",
    "namespace": "program:peer-1",
    "workspace_id": "WORKSPACE_ID",
    "mailbox_id": "OWN_MAILBOX_ID",
    "membership_id": "OWN_MEMBERSHIP_ID"
  }]
}
```

```sh
peerwork bridge run /private/peerwork/bridge.json
```

Configure that selected AGY project's MCP/Skill and scoped tool permissions
before starting the managed provider. It owns one CLI process for the selected
conversation; it does not attach to an arbitrary already-running TUI. Transfer
conversation ownership explicitly before starting it. If that transfer is not
authorized, retain the existing session and use the MCP waiting path, explicitly
reporting that unsolicited live wake has not been set up.

`BRIDGE_READY` identifies a protected endpoint descriptor. Copy its matching
principal's `adapter` object into `runtime.hosts[0].adapter`. Do not reconstruct
its destination, guess a bridge ID or use a master token. Multiple-principal
bridges expose `adapters`; select the exact Origin/actor/key/namespace. Keep
credentials private and provision only the narrow selected credential across
OS users. See [bridge fields](participant-runtime-candidate.md#native-host-user-bridge-candidate)
and [managed AGY details](participant-runtime-candidate.md#explicit-managed-agy-cli-stdio-candidate).

A program or explicitly waiting Agent can instead use `hosts: []` and issue a
native `watch` request using the same exact watch options. That enables durable
receiving, but does not prove idle-session host delivery. Do not add a second
consumer to a mailbox already owned by a selected live host. Existing native
mailbox host changes use [rebind](native-state-handoff.md#change-the-selected-physical-session).

## 4. Start, observe and finish the quickstart

Start the approved runtime once, under its owning user, using
`peerwork runtime run /private/peerwork/runtime.json`. Observe it using
`peerwork runtime admin /private/peerwork/runtime/admin.json status`. This reports
local engine/host startup; `LOCAL_READY` alone is not remote online evidence.
Keep it and the selected bridge under the authorized process supervisor.

For current remote evidence, write this protected request file:

```json
{
  "method": "request",
  "request": {
    "operation_id": "setup-mailbox-observation",
    "action": "structure.mailbox.get",
    "scope": {"workspace_id": "WORKSPACE_ID"},
    "body": {"mailbox_id": "OWN_MAILBOX_ID"}
  }
}
```

```sh
peerwork runtime call /private/peerwork/runtime/client-peer-1.json /private/peerwork/mailbox-read.json
```

Inspect the verified selected mailbox's presence: current downlink, key readiness,
host mode/execution and observation freshness. `PATH_QUALIFIED` is a recent
receiver-attested path, not a model reply or timing SLA. Missing, stale, busy,
approval-waiting and queue-only observations must retain their actual meaning.
An empty workspace-wide mailbox list is not proof that all Peers are offline.

Now continue the [quickstart](native-participant-quickstart.md):
refresh the configured MCP integration, call a tool from the actual session,
and verify a genuine two-way marker exchange. Retain the original pending work
and report a concrete blocker if a required stage is not yet supported or
configured. Native0.3.1 does not expose an automatic `setup` or Agent `doctor`
command; this guide uses its existing supported interfaces.
