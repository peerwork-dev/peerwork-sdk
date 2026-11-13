# Identity, permissions and recovery

The native SDK uses one ordinary Workspace client for fixed tools and management.
The backend evaluates current business authorization on every request. Selecting
a protocol role does not copy its current grants into a local action whitelist.
Grant additions and revocations therefore take effect without rebuilding the
Agent's profile. Programs, CLI and MCP use the same native engine and results.

```text
Agent / CLI / MCP / program
             |
authenticated original client
  Actor + origin + selected Workspace
             |
original identity signature
             |
backend membership + current grant + protocol rules
```

An identity is its public-key-bound Actor ID. The private key signs operations.
A local client credential lets its holder ask the protected runtime to use a
particular identity. It is not another Actor, nor an attestation of an executable
or operating-system process. Programs sharing a credential share its authority.
Separate accounts/sandboxes and file access controls are needed to isolate
mutually untrusted credential holders.

## One business authority

The service checks membership, expiry, execution-specific grants, protocol roles,
actions, business predicates and explicit communication overrides. Ordinary
membership includes communication and shared-fact discovery. A role instruction
or tool catalog describes an operation; it does not grant it.

Local checks bind the caller to its selected identity, service and Workspace.
Runtime administration and host-session attachment remain separate local
authorities. A business grant does not authorize a host rebind or shell action.
Protocol digest verification, body encryption, service trust pins and recipient
binding remain mandatory.

For intentional local delegation, pass an already constrained original
`ParticipantClient`/runtime endpoint. The native `Capability`/`restrict` boundary
is retained and inherited; Connect cannot expand it. Owner credentials retain
their actual administrative authority. Selecting a protocol role does not turn
an Owner into a different participant; use a distinct Actor for distinct remote
authority or attribution. Business grant checks still apply to Owner actions.

`protocols[].actions` selects the remote actions required for a role. Omit it
for all declared role actions. Missing rights produce one resumable permission
request; an action list never installs a local role whitelist. Subsequent service
grant changes apply without recreating the client. Actual parent restrictions
still apply: requesting actions outside that ceiling returns `LOCAL_SCOPE_DENIED`.

Known SDK-generated historical action/member/recipient projections are not
presumed deliberate delegation. The shared lifecycle validates their original
issuer before normalizing them and retains old operation routes. Unknown source
policies remain unchanged until an explicit local-owner source-policy decision.
Real `Capability` restrictions and child namespaces retain their limits.

## Read a denial

`LOCAL_SCOPE_DENIED` means the local credential rejected the request before
service authorization. Its diagnostics identify the limiting fields and the
local runtime owner. Workspace Owner approval cannot fix that local boundary.

The service advertises `authorization-diagnostics-v1` in
`extensions.protocol_features`. Native0.3.15 asks for its bounded signed
diagnostics using `X-Peerwork-Diagnostics: authorization-v1`; this header changes
diagnostic presentation only. It grants no authority and does not change an
operation's effect. Historical clients receive a compatible signed projection,
including when re-reading an outcome first produced for a newer client.

For a verified refusal, inspect `code`, `phase`, `effect_certainty`,
`retryable`, `recovery` and `details`. Existing outer codes such as `FORBIDDEN`
remain compatible; `details.reason` distinguishes the actual failed condition:

| Reason | Meaning | Next responsible party |
| --- | --- | --- |
| `GRANT_MISSING` | No grant for this execution | Protocol maintainer |
| `ACTION_NOT_GRANTED` | The current grant omits this action | Protocol maintainer |
| `GRANT_EXPIRED` / `GRANT_REVOKED` | The grant is no longer effective | Protocol maintainer |
| `GRANT_MEMBERSHIP_CHANGED` | The grant belongs to an older membership | Protocol maintainer |
| `GRANT_CONTEXT_MISMATCH` | Grant and selected execution differ | Protocol maintainer |
| `CAPABILITY_NOT_GRANTED` | Protocol maintenance responsibility is missing | Current designated governance authority |
| `OWNER_REQUIRED` | The operation requires Workspace Owner authority | Workspace Owner |
| `ACCESS_EXPIRED` / `MEMBERSHIP_INACTIVE` | This Actor's access is no longer active | Workspace Owner |
| `COMMUNICATION_RESTRICTED` / `COMMUNICATION_OVERRIDE_EXPIRED` | An explicit communication exception blocks this direction | Workspace Owner |

Details also identify the requesting Actor, native action, selected business
action where applicable, relevant revision, `next_actor` and `next_action`.
Workspace/instance/protocol and the command ID remain in the verified result.
The service produces reasons at the actual check; the SDK does not reimplement
the permission evaluator. `grant.get` provides current authorization evidence
when further inspection is needed. Unadmitted callers receive limited errors,
not another Workspace's grant facts. Old recorded refusals can lack details.

A business constraint failure or stale revision is distinct from a permission
denial. A signed refusal proves no effect for that intent; correct the cause
before creating a new intent. A timeout alone proves neither refusal nor
completion: preserve the original ID and use status/recover. An already committed
operation is never reclassified as unsubmitted after access is revoked.

## Upgrade an existing installation

The frontend and resident engine report separate capabilities. Update the original
process that lacks the required feature, retaining identity, journal, receiver and
host binding. Both profile and local-registry adapters enter the shared lifecycle.
Proven generated projections repair through the authenticated original issuer;
the old profile revision and sender/directory/management/protocol recovery routes
remain. This does not request remote rights or widen old issued tokens.

When source provenance cannot establish a policy, `ORIGINAL_ISSUER_SELECTION_REQUIRED`
identifies the needed original issuer/runtime configuration and explicit local
policy. Follow [the source-selection continuation](existing-client-tools.md);
manual capability JSON editing or another Workspace approval is not the remedy.

Operation IDs are unique across the ordinary Workspace client's tools and
instances. Use stable unique IDs; do not reuse one for a different intent.
Historical IDs retain their original namespaces. Status/recover searches the
recorded original route, and returned `recovery_arguments` selects it exactly
(including `recovery_view` when needed). Copy those arguments after uncertainty.
An old pending send is never resubmitted under a new namespace to make it appear
successful. Historical clients are recovery routes, not alternate authorization
paths for fresh requests denied by the current client.
