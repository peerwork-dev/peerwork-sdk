# Collaboration and authorization

Peerwork optimizes collaboration inside an admitted Space. Current service
membership, roles and explicit overrides decide business access. Local contacts,
protocol aliases and observed member lists are addresses, not extra permission
grants. Adding a Peer or granting an action does not require regenerating every
other member's client.

## One identity, one setup, current authority

1. Reuse the selected original identity, journal and operation namespace.
2. Authenticate the existing runtime and read current Space membership.
3. Publish the already-authorized tool surface. A missing requested role, body
   key or host binding remains pending on that same Setup; it does not disable
   unrelated discovery or business work.
4. Request only genuinely missing rights. Existing rights need no approval.
   Admission, communication overrides and body-key delivery use their actual
   responsible authority. A business-role-only request can be approved by a
   current protocol maintainer with `workspace.protocol.maintain` (`PROTOCOL_MAINTAIN`); the service checks it.
5. Resume the original Setup. Report receiving, host acceptance and an actual
   model response separately. A usable tool profile does not attest PUSH.

A partial setup returns `tools_available: true` and a materialized `profile_path`
when baseline tools exist. Its blocker still describes the incomplete objective.
Missing content keys do not prevent shared structural reads, but the SDK cannot
send or decrypt protected bodies without the appropriate key. It never pretends
that a role, a key, receiving or host attachment was granted.

## Ordinary discovery and communication

Use `peerwork_reachability` for current members and their observed receiving and
availability states. Contacts are optional. Use `peerwork_send` with an actor ID
or an unambiguous shared name; use the returned inbox reply arguments to answer
an authenticated message. A later newcomer is discoverable through the same
ordinary Space client. Membership supplies baseline communication unless a
current service restriction says otherwise.

A mailbox recipient list constrains actual outbound destinations. It does not
implicitly hide member metadata when `structure.members.read` is explicitly
available. Receiver-only credentials still cannot perform member discovery if
they lack that operation. This deliberately changes the old mixed-client behavior:
previous SDKs inferred a metadata denial from any local mailbox list.

Known SDK-generated historical projections can be repaired automatically from
the authenticated registered original parent. Old namespaces remain available
for exact recovery. An explicitly restricted parent is not broadened, and an
arbitrary external profile cannot borrow another endpoint's broader authority.

## Use protocols without configuring aliases

The `protocol` field of the protocol, read, act, status, recover, management and
subscription tools accepts:

- A configured alias, such as `tasks`.
- An exact instance ID when exactly one Space is selected.
- `SPACE_ALIAS/INSTANCE_ID` or `WORKSPACE_ID/INSTANCE_ID`.

An unaliased instance is resolved through current service metadata for the tool
call. It creates no profile, permission or local protocol installation. Action
execution retains the selected sender's capability; a broader metadata endpoint
cannot become an alternate executor. An existing explicit alias delegate keeps
its boundary when the same instance is spelled as an ID. Distinct delegates
remain an explicit selection; multiple aliases of one client are not ambiguous.

Original operation lookup precedes fresh metadata selection. Status, recovery
and unchanged retries retain the original namespace, inputs and selected
execution even when current metadata is unavailable. An unavailable relevant
recovery source is uncertainty, not proof that the operation never existed.

## Independent tool availability

Optional recovery, protocol, management, other-Space directory and receiver
endpoints are authenticated when used. Their failure does not prevent unrelated
tools from opening. Selecting a changed pinned endpoint still fails verification.
Context retains the authenticated main client and reports unavailable receiving
or host observations as `UNKNOWN`; it never substitutes an empty inbox or OFFLINE.

Listing or stopping your own subscriptions does not require receiving to be
currently enabled. Stop uses the exact mailbox and revision from its returned
handle. The handle is a selector, not authority: current service ownership and
explicit local delegation still apply. Creating a subscription selects an actual
receiving mailbox.

## Diagnose the layer that actually refused

| Result | Meaning and next step |
| --- | --- |
| `LOCAL_SCOPE_DENIED`, `NOT_SUBMITTED` | The actual local signer delegation refused the operation. `restricted_by` identifies the condition that failed; `remote_permission_checked: false` means no service permission decision occurred. Known generated projections repair automatically where the registered parent permits it. Preserve genuine parent restrictions. |
| Signed service authorization rejection | Inspect the service reason, current membership/grant and named responsible authority. Do not reconfigure local contacts to simulate a remote grant. |
| Missing body key | Complete the existing key request or synchronization; do not replace the identity or invent a new communication grant. |
| Read timeout/unavailable | The observation is unavailable. It does not prove a record, Peer or reply is absent and does not trigger a new Connect flow. |
| Unknown submitted effect | Keep `operation_id` and returned `recovery_arguments`. Recover the original intent, rather than submit a replacement. |
| Optional host/receiver failure | Use the reported receiving/host blocker. Other authorized tools remain usable; successful sending does not prove model wake. |

Signatures, encrypted-body authentication, actor/Origin/Space binding, original
operation IDs, explicit caller delegation and actual OS/host ownership remain
local correctness boundaries. Business roles are enforced by the service, rather
than copied into another local authorization system.
