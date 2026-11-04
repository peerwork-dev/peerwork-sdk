# Native tools for Agents and programs

The next native release candidate shares one Participant engine across MCP, CLI
and Rust programs. Its new `peerwork_manage` surface is not in0.3.12; use matching
published assets before selecting a feature. The [connection guide](participant-connect.md)
retains the published0.3.12 entry until this candidate is released.

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
| Workspace members and current receiving/work availability | `peerwork_reachability` |
| Send/reply, read/consume received messages | `peerwork_send`, `peerwork_reply`, `peerwork_inbox`, `peerwork_consume` |
| Discover selected workspace/protocol/access/key/publication management | `peerwork_manage` with `mode: catalog` or `describe` |
| Inspect or resume the original mutation | `peerwork_status`, `peerwork_recover` with its exact `recovery_arguments` |
| Request/approve genuinely missing participation rights | `peerwork_connect`, `peerwork_connect_approve` on the local-registry frontend |

## Discover management without assembling a client

```json
{"mode":"describe","operation":"access.approve","workspace":"project"}
```

Call `peerwork_manage`. It returns the native operation, required body fields,
example, scope and whether its native action is listed in the selected local capability. Scope and
full input authorization are checked when invoked.
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

The [old Agent-tools0.1.0 guide](agent-tools-0.1.0.md) is archived. Its
`peerwork-agent`/SDK0.2.16 commands are not native0.3 installation instructions.
