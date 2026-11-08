# Native tools for Agents and programs

Native SDK0.3.14 shares one Participant engine across MCP, CLI and Rust programs.
Its `peerwork_manage` surface is absent from0.3.12. Use the matching
[release](https://github.com/peerwork-dev/peerwork-sdk/releases/latest)
and [connection guide](participant-connect.md).

Agents normally use the loaded MCP tools. Use `peerwork_context` for the selected
identity/workspaces and the loaded tool schemas for arguments. Software owns
signing, body encryption, verification and original-operation recovery. Do not
write a temporary SDK sender, search source for an action or create another
signing journal to use an ordinary operation.

| Need | Native tool |
| --- | --- |
| Inspect a protocol, role instructions or resource | `peerwork_protocol` |
| Read an instance, exact record or bounded current page | `peerwork_read` |
| Execute a declared business action | `peerwork_act` |
| Subscribe an existing inbox to state or protocol-action events | `peerwork_subscriptions` |
| Workspace members and current receiving/work availability | `peerwork_reachability` |
| Send/reply, read/consume received messages | `peerwork_send`, `peerwork_reply`, `peerwork_inbox`, `peerwork_consume` |
| Discover selected workspace/protocol/access/key/publication management | `peerwork_manage` with `mode: catalog` or `describe` |
| Inspect or resume the original mutation | `peerwork_status`, `peerwork_recover` with its exact `recovery_arguments` |
| Request/approve genuinely missing participation rights | `peerwork_connect`, `peerwork_connect_approve` on the local-registry frontend |

## Discover management without assembling a client

```json
{"mode":"describe","operation":"access.approve","workspace":"project"}
```

Call `peerwork_manage`. Describe returns the native operation, required body fields,
example, scope and whether its native action is listed in the selected local capability. Scope and
full input authorization are checked when invoked.
Catalog lists compact summaries; describe returns only the selected example.
The loaded tool schema already lists the operation names.
Catalog/describe reads only local capabilities and grants no permission; the
backend still checks current authority. It makes no workspace mutation or test
message. Examples contain placeholders and are not executable approval requests.

Use the returned mode: `read` for a fresh selected read, `request` for a native
control/local operation, and `invoke` for a durable mutation. Only invoke requires
a stable `operation_id`. A read returns the verified current structural view;
a control request retains the native helper envelope. Select a workspace alias/ID or a configured protocol as
directed; identity-scoped workspace creation and offline tests take neither.
Bodies contain business selections, never identity, journal, endpoint or private
key paths. The native helper validates its complete input and rejects unknown
fields; required-field hints do not replace that validation.

```json
{"mode":"invoke","operation":"keys.rotate","workspace":"project","operation_id":"rotate-after-device-revocation","body":{}}
```

This explicit Owner action uses the original selected client's journal. A local
ceiling denial must be resolved by that local runtime owner, not by switching to
another actor. Keep the returned recovery selector on uncertainty; do not invent
another ID. Grant changes, publication and deletion require the user's intended
business authorization; merely discovering an operation provides none.

Ordinary native0.3.15 Connect tools and management share the selected Workspace
client. Already-held service authority requires no management-enable ceremony.
A local ceiling denial names the local runtime owner and the existing-client or
explicit-delegation correction; it does not request another Workspace grant.
Historical management views remain exact-operation recovery routes. Identity-
scoped `workspace.create` and offline work still require a selected original
client that allows them. See [permissions and recovery](permissions.md).

An administrator does not need to join a business role merely to manage its
grants. Read `instances.read`, then pass the exact returned instance and protocol
digest with the workspace instead of configuring a role alias:

```json
{"mode":"read","operation":"grant.get","workspace":"project","instance_id":"EXACT_INSTANCE_ID","protocol_digest":"EXACT_EXECUTION_DIGEST","body":{"actor_id":"EXACT_ACTOR_ID"}}
```

Choose either `protocol`, or `workspace` with both `instance_id` and
`protocol_digest`. Scope validation and current backend authorization still apply.
For mutations, copy the returned `recovery_arguments` unchanged into
`peerwork_status` or `peerwork_recover`; a `management` selector pins the original
view and namespace. Do not substitute a newer view or another operation ID.

`protocol.bind` attaches a first role bundle. Use the supported protocol-upgrade
operation to update the role package in place or activate a new default execution
version. Original tickets retain their execution version. See
[protocol upgrades](in-place-protocol-upgrades.md) and
[Workspace event delivery](workspace-events.md). Ordinary members may register
candidates; activation requires the designated scoped maintenance responsibility.


CLI exposes the same schemas and implementation:

```sh
peerwork agent tools
peerwork agent --local ORIGINAL_REGISTRY manage
peerwork agent --local ORIGINAL_REGISTRY manage describe access.approve
peerwork agent --local ORIGINAL_REGISTRY call manage - < BUSINESS_REQUEST.json
```

The protected registry is selected once during installation. A prebuilt profile
can also be used with `--profile ORIGINAL_PROFILE`; it does not change identity
or namespace. Programs can use `AgentTools::from_client(original, selection)` or
the full `ParticipantClient` API without a host, MCP or Skill. Writing program
integration code and authoring protocol rules are normal development; writing
new signing/connection glue for each operation is unnecessary.