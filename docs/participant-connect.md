# Connect an existing participant

Native SDK0.3.3 release candidate. These capabilities are available only after
its exact [release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.3)
are published and verified. Native0.3.2 retains its
[explicit setup guide](participant-connect-0.3.2.md).
The native client adds no Node/Python runtime dependency or additional platforms.

## Normal Agent entry

From the authorized project, use the native CLI once if MCP is not loaded:

```sh
peerwork connect --workspace WORKSPACE_ID --send --receive --body-keys --install codex
```

Use `--install agy` for the supported AGY configuration instead. This chooses
which local integration to prepare; it does not create a model session or prove
that the currently running session refreshed its tools. Once loaded, call:

```json
{"request":{"workspace_id":"WORKSPACE_ID","send":true,"receive":true,"require_body_keys":true}}
```

with `peerwork_connect`. Request body keys when using encrypted message bodies. Identity/setup ID are normally derived. A real identity
ambiguity returns public identity choices; choose one handle once. Preserve the
returned `setup_id` for recovery. `send` defaults to true; receive is opt-in.
Programs use the same engine without a host, MCP or Skill, and explicitly select
program mode when using the CLI:

```sh
peerwork connect --workspace WORKSPACE_ID --program --send --receive
```

Agent receive never silently falls back to a program receiver. Tools may be
usable while requested push remains `HOST_CONTEXT_REQUIRED`. A configured
named receiver is not evidence that this new caller is that receiver.

## How the original installation is found

Restore the existing protected project binding first. Otherwise inspect only
bounded Codex/AGY project integration entries, follow their original local
registry and confirm the exact committed, owned installation. The original
directory may be anywhere; neither an EngineConfig copy nor a newly invented
key path is required. The selected project reference is protected and retained;
a missing/corrupt original binding does not trigger another identity search.

For a native installation not yet registered in a host integration, one local
`--trust-project` consent allows the fixed private `.peerwork/runtime.json` and
`.peerwork/engine.json` providers. They parse native RuntimeConfig/EngineConfig;
discovery alone does not open an engine or create a journal. These providers do
not claim to discover arbitrary old Python/Node listener files. An installation
without a supported record needs explicit original-source import/handoff;
private keys are never requested from the Workspace Owner.

A RuntimeConfig preserves its exact original static client namespace. A bare
EngineConfig does not prove that namespace: automatic adoption of historical
state/journal returns `ORIGINAL_CLIENT_NAMESPACE_REQUIRED_USE_RUNTIME_INSTALLATION`
rather than opening it under a new namespace. The explicit low-level bootstrap
is administrative creation of a `program:bootstrap` client, not a supported
handoff of another client namespace; it is not the normal discovery/recovery path.
Fresh native engine setup and a verified owned
bootstrap may use their recorded lifecycle. Existing active state ownership,
unconfirmed process identity and unsupported listener handoff remain blockers.

Identity registration, original binding and proven owned runtime administration
are committed together. Imported business `Capability::owner()` is not local
runtime administration. External runtime host management needs its own local
delegation. Runtime reuse verifies actor, Origin, engine digest, state binding,
namespace and client generation. Descriptor changes are verified against the
same pinned binding before further operations, not merely the same actor.
`original-engine-binding-v1` is a new runtime feature: an older resident runtime
needs its normal owner-managed update, preserving original state and journal.
There is no automatic binary upgrade or replacement signer.

## Current host support

| Entry | What this candidate can establish |
| --- | --- |
| Existing selected Codex/managed AGY binding | Reuse the named destination; current caller and tools remain separately observed. |
| Program already owning a Codex App Server client | Rust `Connect::connect_current` accepts `HostInvocation::CodexDynamicTool` from the actual server callback, checks its exact thread against the selected adapter and retains the host stage across approval. The owning program must integrate this call. |
| AGY App owning integration | The same API accepts exact App conversation context and the explicitly enabled Sidecar/agentapi adapter. This is not CLI root metadata or a universal installed plugin. |
| Ordinary Codex MCP/plugin | Tools/connect are available; this review did not establish generic current-thread metadata or automatic attachment to any existing UI/CLI. Report tools-only/context-required instead of guessing. |
| AGY CLI MCP root metadata | Root context is not an exact child or an external push interface. Existing interactive CLI push is not established; explicitly owned managed stdio remains a separate supported mode. |

`HostInvocation` is a local Rust integration contract, absent from model-facing
MCP/CLI arguments. Its owner obtains fields from the real authenticated host
callback, not from model arguments, environment inheritance or session scans.
The contract alone does not provide a host channel or qualify a new adapter.
No harness is implicitly installed, no App Server/model is launched as fallback,
and no socket permissions or sandbox policy are broadened.

Caller context is per invocation. Its successful observation is not cached as
proof for later callers. Tools installed, tools invoked, receiver link, host
acceptance and actual model response are separate facts. A host can require its
normal trust/refresh step; Workspace approval cannot supply that authority.

## Permission and recovery contract

Existing remote rights require zero Owner exchanges. Missing rights produce
one semantic delta for each responsible authority, then the same setup resumes.
Original selected host, key requests and child operation IDs survive intervening
pending stages. Tools-only profile completion follows durable stage state, not
the last error code. Current rights/keys are rechecked before activating receive.

No action migrates unknown business effects into another identity, namespace
or model session. A changed physical receiver needs explicit supported rebind.
No source/registry discovery triggers a full historical replay or a model ping.

Acceptance includes bounded read-only discovery, exact old0.3.2 registry schema,
unchanged native namespace, original launch ownership recovery, endpoint
replacement rejection, real synthetic-service HTTP and CLI entry, deferred
Agent receive, explicit program receive, and host continuation across pending
and permission approval. Synthetic host tests do not establish real App/CLI
qualification or model latency.
