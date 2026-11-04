# Upgrade a protocol without replacing its instance

This guide targets native SDK0.3.13 and a matching service advertising
`protocol-instance-upgrade-v1` in discovery. Check the exact
[release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.13)
and service capability before use; native0.3.12 does not provide this operation.

Keep the workspace, instance, participant identities, receiver and original
journal. An instance has a changeable default version; existing work retains the
execution version that owns it. Authored packages and historical signatures stay
immutable.

## Normal Agent and program workflow

1. Inspect the target package and its role instructions with the existing tools.
2. Submit one semantic `protocol.upgrade` operation, selecting the instance,
   exact target package or authored bundle, and a stable operation ID. Include
   the explicitly intended target member/role/action grants when creating a new
   execution version. Explicit read-only activation is also possible.
3. Read the result or resume that same operation. The SDK selects and freezes the
   current binding/CAS inputs, handles optional target registration and verifies
   the accepted result. Do not assemble signatures, context IDs or new profiles.
4. Continue using the same instance and logical protocol alias. The ordinary
   current-record page includes old and new work. Selecting an existing record
   routes its instructions, action schema, state and writes to its original
   execution context. New root creation selects the current default version.

MCP, CLI and programs use the same native implementation. Exact remote grants
and the original local capability ceiling still apply. The normal Connect flow
prepares authorized immutable views internally; it does not ask a Worker to
create an alias for each version. A genuinely changed business role or missing
permission is a meaningful authorization choice, not private configuration to
exchange with another Agent.

## What an upgrade changes

| Selection | Result |
| --- | --- |
| A different role package with the same execution digest | Update that context's future instruction/tool reads; retain business state, work and grants |
| A new execution digest with a verified generation-isolation contract | Create its execution state and activate it as the instance default; retain all old work and state |
| A package belonging to an existing execution context | Reactivate the original context with its original state; do not initialize another copy |

A role update can target existing work in a nondefault version. That update
compares the selected old binding, and does not invalidate the unrelated current
default merely because old instructions changed. Already submitted host inputs
and pending intents keep their original package/context pins. Updating role
prose does not prove a model has loaded or followed it.

Reactivation increases the default revision even for v1 → v2 → v1. Revoked,
expired or replaced memberships/grants do not become valid again. Work created
under v2 remains executable under v2 after v1 becomes the default again.

## Authoring independent version generations

A manifest must explicitly declare its work-root actions, continuation references
and version-local state. The compiler checks those declarations against effects
and exact inputs. The declaration does not create a general ticket abstraction
for arbitrary existing programs.

All work in one version generation may share that generation's state; each
individual ticket does not need its own state object. The pre-upgrade instance
remains the authoritative original context. Old records with no context column
resolve to it, without rewriting records, ciphertext or original author intents.

A protocol where the instance itself represents one work item cannot create a
second independent claim merely by selecting a new initial state. Changing the
rules of that existing work requires an explicit conversion. Cross-version
shared writable business state is not implicitly copied or partitioned.
Workspace membership, revocation, capacity and other service-wide constraints
continue to apply across versions.

## Interruption and concurrent changes

- The same operation ID first finds its original saved selection. Recovery never
  resolves a newer default and silently changes the original intent.
- A concurrent default or binding change can produce a verified no-effect CAS
  refusal. Inspect the new binding before choosing a new operation; do not retry
  blindly or rebase to different business rules.
- New-root intents are fenced to the selected default revision. An old unsent
  creation need not succeed after that default changes. An already committed
  operation still returns its original receipt on retry.
- Existing-root continuations use their immutable ownership metadata. They do
  not need a network default lookup on every operation.
- Missing target writers keep activation from being reported as ready unless
  the caller explicitly chooses read-only activation. Installed grants indicate
  authority; they do not promise that a particular business predicate will pass.

Current lists use bounded indexed pages over the original and newer current-record
indexes. They do not replay history or require callers to enumerate every
version and merge their own pages. A state read selects a real execution context;
it never returns a fabricated merged state for all versions.

## Advanced wire contract

The signed workspace operation is `structure.protocol.upgrade`. Its explicit
wire inputs include the instance, exact target package, expected package and
binding revision, optional selected context, and explicit target grants or
read-only intent. A previously unbound instance uses package `null`, revision0.

Programs using raw wire inputs retain responsibility for selecting exact business
scope and consent. Prefer the shared semantic helper for ordinary use: CAS,
membership-generation selections and original-operation persistence are software
work. Context selectors are internal routing data, not a prerequisite for a
Worker to participate.

## Fixed-tool example

After inspecting the target package, an authorized administrator can use
`peerwork_manage` with a writer selection such as:

```json
{
  "mode": "invoke",
  "operation": "protocol.upgrade",
  "protocol": "tickets",
  "operation_id": "tickets-upgrade-v2",
  "body": {
    "target_package_digest": "EXACT_INSPECTED_PACKAGE_DIGEST",
    "grants": [{
      "actor_id": "EXACT_AUTHORIZED_MEMBER_ACTOR_ID",
      "actions": ["ticket.create", "ticket.revise"],
      "protocol_roles": ["WORKER"],
      "capabilities": ["WRITE"],
      "expires_at": null
    }]
  }
}
```

The action, role and capability names above illustrate the qualification fixture;
use the names from your inspected target package and the actual authorized
members. The SDK reads and freezes `membership_id` and
`expected_grant_revision`; do not query or assemble them manually for this
semantic operation. Use `read_only: true` instead of writer grants only when
read-only activation is intentional. Same-execution instruction updates need
neither new grants nor read-only activation.

Preparing up to 32 selected writers uses one exact member batch and at most one
grant-revision batch, rather than a network request per member or a directory
scan. Grant-revision observations are signed current-state CAS metadata, not
permission grants. The final upgrade checks current membership and grant
revisions against the administrator's explicit authorization.

For an instruction update to old work, include its `body.record_id` with the
target package. For subsequent business work, keep using `peerwork_protocol`,
`peerwork_read` and `peerwork_act` on the same alias; select an existing record
before choosing its continuation action. Use the returned `recovery_arguments`
for status/recovery. An operation ID is unique within this local participant's
workspace and instance, including aliases for that same instance. Reusing it
with changed business inputs is a conflict, not a new submission.

## Program API

A program uses its existing `ParticipantClient`, without Connect, an Agent host
or an Agent profile. The same semantic operation is available through `Invoke`:

```rust,ignore
use peerwork_runtime::participant::{Invoke, Scope};
use serde_json::json;
use std::time::Duration;

let request = Invoke::new(
    "tickets-upgrade-v2",
    "participant.protocol.upgrade",
    Scope { workspace_id: Some(workspace_id), ..Default::default() },
    json!({
        "instance_id": instance_id,
        "target_package_digest": target_package_digest
    }),
);
let operation = client.invoke(request, Duration::from_secs(5)).await?;
```

This minimal body is suitable for a same-execution instruction update. Include
the explicit `grants` or intentional `read_only` selection above for a new
execution version. The wait budget bounds this call, not the lifetime of the
operation. A pending result retains its original ID and is observed or resumed
through the same client's operation API; never create a replacement ID merely
because the wait budget elapsed.

The service independently validates the actual target manifest, package, current
membership and grants. A new default does not copy a v1 action permission to a
different v2 action merely because their names match.
