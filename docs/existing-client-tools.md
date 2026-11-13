# Use tools on the original client

Use the [Connect quickstart](native-participant-quickstart.md) for installation,
then the loaded `peerwork_*` tools for daily work. Begin with `peerwork_context`.
The native CLI and MCP adapters use the same selected-client lifecycle. Updating
an old `--profile` launch does not select a different authority or operation
namespace merely because its configuration predates Connect.

## Existing installations

Keep the original profile, endpoint, identity, journal, receiver and pending IDs.
The shared lifecycle authenticates the selected client and uses supported local
provenance to associate an old generated profile with its original issuer. A
proven generated projection can be repaired through that issuer; deliberate
parent restrictions remain. Do not edit action lists, switch to an Owner client,
create another journal or install a second operational MCP to clear a denial.

If the original issuer or its policy cannot be established, follow the returned
local-source continuation. An endpoint cannot widen its own authority, and a
readable key/path is not evidence of a reusable client. This is distinct from a
missing Workspace permission. Already-held remote rights need no Owner exchange.

`ORIGINAL_ISSUER_SELECTION_REQUIRED` means the missing facts are the original
issuer/runtime configuration and an explicit local policy. The authorized local
owner selects one existing source using the returned continuation:

```sh
peerwork connect --profile ORIGINAL_PROFILE --runtime-config ORIGINAL_RUNTIME_CONFIG --adopt-policy inherit-engine
```

Or, when the original issuer endpoint is already known:

```sh
peerwork connect --profile ORIGINAL_PROFILE --issuer ORIGINAL_ISSUER_ENDPOINT --adopt-policy inherit-issuer
```

These are explicit local source-policy changes, not Workspace approval or routine
MCP arguments. Without a policy choice the old source limits remain. An older
runtime missing `source-client-adoption-v1` may require the same-config upgrade
identified by the continuation, keeping the original state. Existing host launch
commands can retain their profile selection and reuse the saved association.

The frontend and resident runtime are separate processes. Inspect their actual
capabilities in `peerwork_context`; update the original runtime when the requested
capability requires it. Reload the MCP connection using the host's supported
mechanism. A changed executable path or standalone probe does not prove that an
existing process or intended session adopted the update. Preserve its state and
host destination when updating.

Current host installers use the shared lifecycle. Older `--local` and `--profile`
launch spellings are compatibility selectors for that lifecycle, not separate
business workflows. Use `peerwork connect --help-all` only for an explicitly
selected custom installation or local issuer decision.

## Embedded programs

A program that already owns a `ParticipantClient` can expose tools directly:

```rust
use peerwork_runtime::{
    agent_mcp,
    agent_tools::AgentSelection,
    participant::{ParticipantClient, Result},
};

async fn expose_existing_client(original: ParticipantClient,
                               workspace: String) -> Result<()> {
    let mut selection = AgentSelection::for_client(&original);
    selection.workspaces.insert("project".into(), workspace);
    agent_mcp::serve_client(
        original,
        selection,
        tokio::io::BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    ).await
}
```

The program keeps its original client, capability and operation namespace. It
needs no daemon, Connect registry, copied signing key or history migration to
attach tools. `AgentTools::from_client` supplies the equivalent in-process view;
normal programs may use the full typed Participant API directly, including
operation results, bounded watches, inbox, consumption and shutdown.

Do not call `restrict` merely to attach tools: it intentionally creates a child
operation namespace with narrower authority. An existing restricted client stays
restricted. Closing MCP stops that transport's observation, not its owning client
or admitted durable operations. The program owns final client shutdown.

Only expose setup tools when the selected lifecycle can actually perform setup.
Unsupported custom clients need an adapter in their owning application; do not
invent their operation namespace or infer identity absence from failed discovery.

## Recovery and host delivery

Use `peerwork_status` or `peerwork_recover` with the exact returned
`recovery_arguments`. Original operations remain in their original namespace
across profile/runtime updates. Old raw Kernel command IDs retain their Kernel
recovery path; never turn them into new Participant operation IDs.

Tools loaded in a host do not prove receiving, exact-session input acceptance or
a model reply. Keep an already-working PUSH binding. Same-target delivery repair
belongs to its original receiver/host lifecycle; changing the actual destination
is explicit. See [host recovery](host-bridge-recovery.md).
