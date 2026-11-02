# Attach tools to an existing client

Native0.3.6 adds direct existing-endpoint attachment and workspace member tools.
Native0.3.5 introduced the embedded tool entry. Use the exact
[release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.6)
for published binaries and source; a source snapshot alone is not an installed
upgrade. Native0.3.4 does not expose `serve_client`.

Tool access, state takeover and host-session delivery are separate operations.
An existing client that can already perform an operation does not need an Owner
to generate another Agent profile, mailbox or identity merely to expose MCP.

## Choose the existing interface

| Existing client | Tool entry | State migration |
| --- | --- | --- |
| Native resident runtime with a protected client endpoint/profile | `peerwork agent --profile ORIGINAL_PROFILE.json mcp` | None; reuse the original endpoint and its namespace. |
| Already-open Rust `ParticipantClient` in the owning program | `agent_mcp::serve_client` | None; attach to that exact client. |
| Unrelated custom engine/listener without a reusable native interface | Add an explicit supported adapter in its owning program | Not automatically required. A readable signing key alone does not establish a reusable client interface. |

Do not stop a working client or import its history just to install tools.
Replacing its execution engine is a separate, explicitly selected transition.
Existing remote rights require zero Owner exchanges. Missing rights still use
the normal request/approval path; MCP itself confers no remote permission.

## Reuse an existing endpoint without discovery reads (native0.3.6)

A locally working native endpoint can generate the protected profile directly:

```sh
peerwork connect --local PRIVATE_REGISTRY --participant worker \
  --client ORIGINAL_ENDPOINT.json --origin https://api.peerwork.dev \
  --actor ORIGINAL_ACTOR_ID --workspace WORKSPACE_ID --attach \
  --protocol tasks:INSTANCE_ID:PROTOCOL_DIGEST --install codex
```

Use `--install agy` for AGY; omit `--protocol` for workspace metadata tools.
Separate multiple known bindings with commas. This selects known aliases; it
claims no role or remote permission. `--attach` performs local authenticated
binding checks, generates the profile; adding `--install` registers the fixed tools. It does not
run workspace, communication-grant or mailbox discovery; grants remain checked
when a tool executes. An existing active setup is preserved rather than silently
replaced. Repeating the same attachment is safe.

Use the endpoint owned by the original runtime and OS user. A Node/Python
wrapper around the official native CLI is not inherently an unsupported client:
identify its actual engine, journal and namespace first. Automatic `connect`
bootstrap and explicit `peerwork runtime run` have separate path checks. A
bootstrap refusal does not prove the explicit native entry is unusable. If only
one-shot native CLI calls exist, have the original local owner start the official
runtime with the exact original identity/journal/transport, then select its
endpoint. Starting that runtime is not evidence that an unrelated operation
namespace was inherited. Keep raw kernel command IDs in their original recovery
path; never turn them into new Participant operation IDs.

`LOCAL_ATTACHED` means a profile was generated over the original endpoint.
Registration, an independent MCP probe, tools loaded in the current host session,
and live receiving are separate observations. Refresh the host configuration
when needed, then actually call `peerwork_context`. No Owner-issued profile,
new mailbox, Rust rewrite, copied credentials or shared-parent chmod is needed.

## Already-open Rust client

The program that owns the original client can expose the normal fixed MCP tools:

```rust
use peerwork_runtime::{
    agent_mcp,
    agent_tools::AgentSelection,
    participant::{ParticipantClient, Result, Scope},
};

async fn expose_existing_client(original: ParticipantClient,
                               workspace: String,
                               instance: String,
                               protocol_digest: String) -> Result<()> {
    let mut selection = AgentSelection::for_client(&original);
    selection.protocols.insert("tasks".into(), Scope {
        workspace_id: Some(workspace),
        instance_id: Some(instance),
        protocol_digest: Some(protocol_digest),
    });
    agent_mcp::serve_client(
        original,
        selection,
        tokio::io::BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    ).await
}
```

Integrate this once in the owning program's MCP mode. Workers then use the fixed
`peerwork_*` tools; they do not write an SDK script per message. The program must
reserve stdout for MCP JSONL. The API also accepts another owned reader/writer;
it does not create a remote listening socket or install a harness automatically.

`AgentSelection` contains only pinned actor/Origin and local workspace, contact
and protocol aliases. It contains no key/state/journal paths or endpoint token.
It is not a grant. Pass a suitably restricted **original** client. Do not call
`restrict` simply to attach tools: `restrict` intentionally creates a child
operation namespace. An already restricted client is attached unchanged.

The entry validates the actor/Origin, retains the client's capabilities and
revocation state, and shares its live engine and original operation namespace.
It does not reopen the signer, copy/replay history, create an installation ledger,
create a mailbox or derive another operation namespace. Original status/recovery
uses the same operation ID. Unknown effects remain unknown; reconnecting tools
never authorizes resubmitting a replacement intent.

For an in-process tool API without MCP, use
`AgentTools::from_client(original, selection)` and `AgentTools::call`.
Both embedded and resident tools share the same client-request implementation.
Closing/cancelling MCP ends that tool transport's observation; it does not close
the original client or cancel its admitted durable operations. The owning program
retains responsibility for the engine's final shutdown.

Connected MCP entries list executable tools. `peerwork_connect` and
`peerwork_connect_approve` are exposed only by the separate local-registry
onboarding entry, where those operations can actually be performed.

## Interpret discovery correctly

`NO_SUPPORTED_LOCAL_CLIENT_FOUND` replaces the misleading
`NO_LOCAL_IDENTITY_FOUND` discovery state in native0.3.5. Its diagnostic says:

```json
{
  "meaning": "NO_SUPPORTED_LOCAL_CLIENT_DISCOVERED",
  "identity_existence": "NOT_DETERMINED",
  "tools_require_state_migration": false
}
```

It means the bounded supported providers found no candidate. It does not mean
that a key is absent, that identity creation is required, or that history must
be migrated before tools can be used. The next options distinguish selecting
an existing native endpoint, attaching to an open Rust client, and adapting an
unsupported custom client. Do not invent an installation record or a namespace.

If the old client has no reusable native endpoint or `ParticipantClient`, this
release does not claim automatic compatibility. Adapt that client's actual
interface or plan an engine replacement separately, preserving its original
recovery path and unresolved operations. Selecting a newly configured engine is
not proof that another client's pending operations have been transferred.

## Host delivery remains separate

Serving MCP makes tools available when the host loads them. It does not identify
the current Codex thread, attach an AGY conversation, activate mailbox receiving,
wake an idle model or prove online reachability. Configure and qualify the
supported host interface only when those capabilities are requested. Ordinary
tool use must remain available without them.
