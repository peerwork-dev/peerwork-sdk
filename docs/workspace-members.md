# Workspace Peers, shared names and receiving status

Native SDK0.3.14 plus service discovery feature `workspace-members-v1` expose the
workspace directory through the ordinary fixed tools. Contact aliases are
optional conveniences; an empty contacts list is not an empty workspace.

```json
{"workspace":"project","limit":8}
```

Call `peerwork_reachability` with those arguments. Omit workspace only when the
selected profile has exactly one workspace. Select `actor` by exact actor ID or
shared name, or continue with the returned cursor. The response includes member
IDs, shared names, observation time, page counts and `complete`; a page summary
is not a global online count. Each read is one HTTP page with fixed bounded SQL
queries over current metadata, not a history scan or per-member request loop.

Receiving states describe the member's default receiving path:

| State | Meaning |
| --- | --- |
| `REALTIME` | A current qualified live receiver path; this does not prove an LLM reply. |
| `QUEUED` | Current observations permit queued delivery; immediate model execution is not promised. |
| `NOT_ENABLED` | An explicit receive restriction or inactive access prevents reception. |
| `UNCONFIRMED` | No configured receiver, or lease, host/key freshness, ordering or capacity cannot currently establish availability. |

Directory readers see only this minimal collaboration metadata. No SEND grant
is needed to read it. Mailbox addresses/tokens, session information, key state
and queue internals are not disclosed by this summary. Detailed mailbox APIs
retain their existing permissions. Explicit local instance/protocol/mailbox
limits remain enforced; local denial is not evidence that the peer is offline.
If `restricted_by` includes `operations`, `instance_ids`, `protocol_digests`
and `mailbox_ids`, the selected client is not a Workspace directory client.
Adding only `structure.members.read` is insufficient. Resume the supported
connection through the original authorized runtime to select or derive its
Workspace client, preserving older endpoints for pending-operation recovery.
Upgrading the binary alone does not enlarge an existing immutable delegation.
See [receiving recovery and local capability diagnosis](receiving-recovery.md).

## Shared display names

Call `peerwork_member_name` with a stable operation ID, your chosen name and the
`frontier.workspace_revision` just observed in the directory:

```json
{"workspace":"project","operation_id":"name-peer-2","name":"peer-2","expected_revision":12}
```

The signed action changes only the caller's current membership name. Names are
shared with authorized workspace members under workspace visibility, not public
across the internet merely because they are shared. They are not identities or
permission grants. Names must be trimmed, nonempty, at most80 UTF-16 code units
and256 UTF-8 bytes, without control/format characters. Actor ID spellings are
reserved. Matching is exact and case sensitive; null clears the name.

Duplicate names are allowed. Rename preserves the actor, roles, journals and
message attribution. Rejoining under a new membership resets the old name.
Rename invalidates old directory cursors; receiver heartbeats do not. Refresh a
changed directory before deciding whether to submit a new operation.

## Send without contacts

```json
{"workspace":"project","to":"peer-2","operation_id":"request-001","text":"Please review the change."}
```

Call `peerwork_send`. A unique exact name or actor ID selects one current member.
Ambiguous names return actor choices without sending. Select the intended actor
explicitly; never take the first match. SDK resolution uses the sending client's
existing capability and the server still checks SEND/RECEIVE. Identity and current
membership are pinned into the immutable message intent. A name change or rejoin
cannot redirect a saved operation. Existing optional `contact` arguments remain.
The legacy CLI `send CONTACT` retains its optional local-contact meaning.
The explicit member CLI equivalent is `peerwork agent --profile PROFILE reachability [--workspace WORKSPACE]`
and `peerwork agent --profile PROFILE send --to MEMBER --id OPERATION_ID < message.txt`.

Keep the exact returned `recovery_arguments` for status/recover. A name update
may use a separately scoped directory client; its workspace selector routes back
to that original namespace. Protocol operations use their protocol selector;
ordinary sends use the original sender. Never replace an uncertain ID to retry.

## Service API and rollout

- `structure.members.read`: `BASIC` (default), `COLLABORATION` or `DELIVERY`, limit1–32,
  cursor and at most one exact actor_id/membership_id/name filter. DELIVERY requires
  caller SEND and explicit actor/name selection; it is internal address resolution.
- `structure.member.name.set`: current membership_id, name and signed
  expected_workspace_revision; self only, no role or membership-state changes.
- PostgreSQL schema17 adds one nullable name column and a state/name/actor index.
  Existing rows require no rewriting and no historical replay.

The new member projections/name action require the advertised service feature;
an older service yields capability unavailable. Business-only tool attachment
needs no receiving path. Tool registration, current-session loading and qualified
receiving remain separate results. This update makes no new numerical latency SLA.

## Diagnose a failed directory read

Prefer `peerwork_reachability` above: it constructs the read request and verifies
the response. Programs using `structure.members.read` directly must set the body
field **`view`**, for example `{"view":"COLLABORATION","limit":8}`. The field
`projection` is not accepted. An HTTP400 does not establish that members are
missing or offline.

Fresh reads without an explicit command ID or idempotency key do not create a
saved mutation intent. Correct a malformed read and read again; do not replay a
business operation or stop receiving to recover the directory. Native0.3.9 classifies fresh-read HTTP
rejections separately and reports `CORRECT_READ_REQUEST_OR_CONFIGURATION`, not
mutation recovery. Native0.3.8's generic HTTP message alone does not establish a
saved operation. Explicitly durable queries and actual
mutations retain their original status/recovery paths.

If the tool is missing after upgrading the runtime, also upgrade and reload the
[MCP frontend](existing-client-tools.md#upgrade-both-runtime-and-tool-frontend).
`LOCAL_SCOPE_DENIED` concerns the selected local endpoint, not a peer's receiving
state. Resolve that local capability with the runtime owner before diagnosing
remote permissions; an existing business role does not require another Owner
exchange merely to expose tools.


## Membership baseline and explicit restrictions

With `workspace-collaboration-v1`, ordinary active members have send/receive
rights and a discoverable default inbox without a separate communication grant.
An unconfigured receiver is UNCONFIRMED, not proof that permission is absent.
The Workspace visibility switch can hide optional peer status; it does not
change identity or business roles. See [Workspace events](workspace-events.md).

An effective communication read with `source: MEMBERSHIP_DEFAULT` has virtual
revision0. An Owner creating an explicit override may use that observed0 or null
as `expected_revision`; later updates use the actual override revision. Both
`send: false` and `receive: false` are supported explicit restrictions. A stale0
cannot overwrite an existing override. Expiry does not revive baseline access.
