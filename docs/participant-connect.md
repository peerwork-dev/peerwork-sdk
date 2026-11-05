# Connect an existing participant

Use native SDK0.3.14 and its exact published
[release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.14).
Native0.3.2 retains its
[explicit setup guide](participant-connect-0.3.2.md).
The native client adds no Node/Python runtime dependency or additional platforms.

In0.3.14 ordinary active membership includes in-Space send/receive and self-
subscription. Connect requests both by default; explicit restrictions remain.
Use `--tools-only`, `--no-send` or `--no-receive` for intentional narrower use.
See [messages, broadcasts and subscriptions](workspace-events.md).

## Ordinary client authority (native0.3.15)

Tools, role actions and management share the selected original Workspace client.
The service checks current business grants; role changes require no local
permission refresh. Existing ordinary setups normalize locally on Connect,
preserving receiver/host bindings and original-operation recovery. Explicit
parent ceilings and historical explicit-action profiles are preserved. See
[identity, permission diagnostics and recovery](permissions.md).

## Attach an existing Codex conversation (native0.3.12)

This entry targets the official shared-daemon control
interface, not `--no-daemon` sessions or arbitrary App/IDE integrations.
The control protocol is qualified on Linux with daemon0.166.0 and the official
proxy from CLI0.160.0 and0.166.0. These checks use an isolated loaded thread and
start no inference turn; they do not qualify a model-response latency SLA.

From an already authorized project, discover loaded conversation titles:

```sh
peerwork connect --workspace WORKSPACE_ID --codex --install codex
```

Select the conversation once by its exact title (or exact thread ID if titles
are ambiguous):

```sh
peerwork connect --workspace WORKSPACE_ID --codex --codex-chat "Worker 2" --install codex
```

Use the original `--local` and `--participant` handles when the project does not
already select that installation. A candidate list is `PENDING` with exit code2;
it does not change the receiver. Discovery reads bounded loaded-thread metadata,
not transcripts or workspace history. It never chooses the newest conversation.

The native client uses the trusted `codex` executable on the local user's PATH
and runs only `codex app-server proxy`. It starts no replacement Codex server,
conversation or model. The Codex user must already be able to access the daemon;
cross-user installations retain the existing scoped host bridge. Do not change
socket permissions or pass identity files to another user to make setup pass.
Select an already registered Codex bridge/native host by its local handle:

```sh
peerwork connect --workspace WORKSPACE_ID --codex --codex-host REGISTERED_HOST --install codex
```

This uses the host owner's registered destination instead of trying to open
their control socket under the signing user's account. The bridge grant is
still enforced for the selected identity and mailbox.

With a0.3.13 resident runtime, the same durable operation reads the original
**receive** endpoint's binding and subscriptions and changes only the selected
host scope without restarting the process. The engine, receiver client/namespace,
mailbox, keys, journal and pending command IDs stay in their original stores.
An older runtime can use its existing offline transaction with an authorized
restoration path, as described below. An ordinary client endpoint does not
authorize stopping an external process. A shared host group covering additional
subscriptions requires an explicit group selection.

Repeat the same command after an interruption. Keep its original arguments and
operation; do not reset state, invent a new receiver or resend pending commands.
The SDK reconciles a committed rebind even if its completion response was lost.
Existing rights require no Owner exchange. For a first connection, include the
needed `--join` and `--body-keys` flags; genuinely missing rights use
the existing consolidated authorization flow. Attaching an existing INBOX keeps
its prior requested rights and adds explicitly requested roles/send/key rights.
The old INBOX setup remains historical; its completed receiver is reused by the
new PUSH setup rather than derived again.

MCP registration, current-session tool loading, verified receiving/host readiness
and an actual model reply remain separate results. Installation reports the host
refresh step when needed. `model_response: NOT_ATTESTED` is not a failed model
test or a successful PONG. A controlled message/reply test establishes that last
stage independently.

The official [App Server](https://learn.chatgpt.com/docs/app-server) distinguishes
thread IDs from live session-tree roots. [Hooks](https://learn.chatgpt.com/docs/hooks)
can report a parent's session ID for a subagent; they are not an exact-thread
selection mechanism. Ordinary MCP registration does not itself supply a current
conversation control channel.

## Explicit original runtimes and resident rebind (native0.3.13)

These additions are not in0.3.12. Selecting an authenticated original runtime admin
is sufficient management authority; a Connect launch receipt is not required.
For a first receiving path, native host attachment uses the online admin interface
without stopping the runtime. Actual existing receiver bindings are inspected
before treating missing Connect metadata as an empty installation.

If an older directly managed runtime already has an INBOX, select its original
protected config once when no trusted local source has recorded it:

```sh
peerwork connect --local ORIGINAL_REGISTRY --participant worker --workspace WORKSPACE_ID --codex --codex-chat "Worker 2" --runtime-config ORIGINAL_DIRECT_RUNTIME.json --install codex
```

The config supplies the exact original admin/client selection; a single-client
runtime can also be registered from that config without hand-entering endpoint,
actor or journal paths. A conflicting existing selection is never replaced.
This option authorizes the directly managed runtime's necessary temporary stop
and restoration through the existing sealed rebind. It creates no identity,
journal or receiver. Do not use it to bypass an external supervisor's lifecycle
or to restart an uncoordinated shared runtime. Repeating the same invocation
continues the original attachment. Ordinary tools and management operations do
not require this maintenance option.

The0.3.13 resident runtime advertises `resident-scope-rebind-v1`. With that
feature, the authenticated original admin selection suffices for an existing
receiver: Connect retains the same engine process and rebinds the selected
subscriptions through the same sealed operation. No source config pathname is
required. Unrelated participants continue running; an upstream event connection
may reconnect, so this is not a claim of uninterrupted network delivery.
Unknown original host calls stay at their original destination and are not
replayed into the newly selected conversation.

Normally repeat the unchanged Connect invocation to observe or resume. A verified
no-effect claim refusal explicitly reports that a recovery decision is required.
For a resident attachment, repeat the original invocation and add
`--binding-recovery RETRY_REJECTED --decision-id STABLE_DECISION_ID`, or choose
`ABORT`. Keep that decision ID on interruption. An unknown remote result must
first be reconciled with the original claim; it cannot be aborted or retried
under a new claim. Abort is rejected after a replacement has committed. These
flags do not start another attachment or select a new destination. Older offline
attachments retain their original native `runtime recover-host-rebind` interface.
Use the exact matching release artifact; a source snapshot is not an installed upgrade.

## Tool access without state takeover

If an existing client already works, [attach tools to that client](existing-client-tools.md)
instead of migrating its identity/history merely to obtain MCP. Native resident
profiles need no installation ledger; native0.3.5 adds the direct embedded
Rust entry. State replacement and exact host-session delivery remain separate.

## Choose the required outcome

For live Agent collaboration, follow the normal entry below and request sending,
receiving and any required encrypted-body access. The SDK reuses existing grants;
only missing rights require approval. Do not turn these options off merely to
make setup succeed, or treat working business tools as live receiving.

Use the business-only entry later in this guide when the caller intentionally
needs protocol operations without live communication. Capability flags default
to false to avoid implicitly requesting rights; this is not a requirement to
complete a tools-only stage before connecting for live collaboration.

## Normal Agent entry for live collaboration

From the authorized project, use the native CLI once if MCP is not loaded:

```sh
peerwork connect --workspace WORKSPACE_ID --join --send --receive --body-keys --install codex
```

Use `--install agy` for the supported AGY configuration instead. This chooses
which local integration to prepare; it does not create a model session or prove
that the currently running session refreshed its tools. Once loaded, call:

```json
{"request":{"workspace_id":"WORKSPACE_ID","send":true,"receive":true,"require_body_keys":true,"request_membership":true}}
```

with `peerwork_connect`. Request body keys when using encrypted message bodies. Identity/setup ID are normally derived. A real identity
ambiguity returns public identity choices; choose one handle once. Preserve the
returned `setup_id` for recovery. `send`, `receive` and body-key requests default to false. Request only the
capabilities needed; business-only setup reads no communication grants or mailboxes.
Programs use the same engine without a host, MCP or Skill, and explicitly select
program mode when using the CLI:

```sh
peerwork connect --workspace WORKSPACE_ID --program --send --receive
```

Agent receive never silently falls back to a program receiver. Tools may be
usable while requested push remains `HOST_CONTEXT_REQUIRED`. A configured
named receiver is not evidence that this new caller is that receiver.

Report tools loaded, sending permitted, receiving path verified, host binding
and body-key readiness separately. Setup that exposes only business tools is
useful but does not complete a request for live communication. A transport or
host acknowledgment does not prove that the model processed a message.

## One portable permission request (native0.3.10)

Existing grants are reused without an Owner exchange. If explicitly requesting
membership with `--join` / `request_membership: true`, an access denial returns
one public request for admission plus the selected communication, role and key
rights. It does not prove why access was denied or disclose a private workspace.
The Owner verifies the requested identity, workspace, rights and any lease, then
approves once. Internal admission and dependent writes keep their own original
operation IDs; interrupted or partial approval resumes the same outer
`approval_id`. Invalid roles are rejected before admitting a new member.

Pass the returned `authorization_code` (prefix `PW-AUTH-1.`) or
`authorization_request` object through your existing handoff. The code is a public
request, not a secret or permission token; it cannot join a workspace or approve
itself. It contains no local endpoint/profile/journal paths or private key.
Do not hand another machine a path to a local request file.

The Owner calls `peerwork_connect_approve` with the returned `approval.arguments`
and adds their own registered `participant` handle. The `request` argument accepts
the code or object. CLI approval also accepts a code directly or through stdin:

```sh
peerwork connect --local OWNER_REGISTRY --participant OWNER --id APPROVAL_ID --approve-code PW-AUTH-1.CODE
# Or paste the public request code/JSON into stdin, then close stdin:
peerwork connect --local OWNER_REGISTRY --participant OWNER --id APPROVAL_ID --approve-request -
```

After approval, continue the original participant setup. Existing members and
read-only sessions do not gain rights automatically. Expired sessions require
their explicit admission/renewal path. Sender grant expiry, rejoin generations,
local capabilities and body-key authorization remain independently enforced.
This release does not introduce a server-hosted approval queue or automatically
wake an arbitrary host session after an Owner approves.

## Explicit inbox consumption without host push

For an Agent intentionally using MCP inbox/wait, select
`receive: true, receive_mode: "INBOX"`, or CLI `--receive --receive-mode inbox`.
It reuses the native receiver without requiring an Agent host or starting a
replacement model. It does not establish unsolicited model wake.

Omitting `receive_mode` preserves the Agent PUSH requirement. Explicit `PUSH`
also requires an actual host when selected by a program. A missing destination
remains pending. Neither mode takes over an existing live consumer or changes
its host implicitly; changing a previously active inbox to PUSH requires the
supported explicit rebind. Existing setups without these new fields retain their
original IDs and request digests.

## Receiving self-test (native0.3.10)

Connect observes the actual receiving path before reporting it ready. INBOX
requires a currently verified receiver link. PUSH additionally requires fresh
body-key readiness and a live, ready selected host. A quarantined, reconnecting
or stopped path is pending even if an older successful observation remains.
The result includes `self_test` and a concrete receiving blocker; already
configured business tools remain usable. Cached setup results refresh this
observation instead of treating an earlier setup success as current readiness.

Connect waits up to two seconds for startup observations, then returns pending
while the resident runtime continues. This is a caller wait budget, not a
latency guarantee or a reason to recreate the identity, mailbox or setup.
Resume the same setup after repairing its reported blocker. Self-test readiness
does not attest that the current model session loaded MCP or produced a reply.
A real signed application reply is a separate end-to-end observation.

An existing INBOX can acquire its first selected host through the stopped-runtime
[explicit first-host operation](participant-runtime-candidate.md#first-host-binding-for-an-existing-inbox).
The original receive endpoint, consumer, journal and pending operation IDs stay
in place. Missing host integration remains explicit; ordinary MCP cannot invent
a current-session control endpoint.

## Observe an explicitly completed host replacement

Native0.3.11 verifies an explicitly selected Codex `expected_session_id` against
the actual host destination, even when endpoint and thread ID are unchanged.
Cached and saved-PENDING setups pinned to the old session remain pending after
replacement; they cannot claim the new session's readiness. Persistent host group
keys and stored host-call evidence are unchanged.

After the explicit runtime rebind completes, register/select the new supported
host and run the corresponding setup. Connect recognizes its committed binding
and reuses the original receive endpoint, client generation, consumer and
namespace. It does not create another receiver claim or reinject old model input.
Existing native0.3.10 resident-runtime metadata supports this client-side check;
a further runtime restart is not required solely for the stricter session pin.

## Optional business-only entry

Reuse a working endpoint with the [direct attachment command](existing-client-tools.md).
It does not require broader discovery permissions. When intentionally selecting
only an existing business role through normal connect:

```sh
peerwork connect --workspace WORKSPACE_ID --tools-only --role tasks:INSTANCE_ID:CONTRIBUTOR --install codex
```

Membership supplies baseline communication rights. This tools-only entry does not establish a receiver or host binding; body-key readiness remains explicit. `LOCAL_SCOPE_DENIED` reports
`details.action`, `restricted_by` and, during preflight, `missing_operations`.
The local runtime owner selects a suitable existing local capability; remote
Owner approval cannot repair a local operation/scope denial. Do not remove
instance, protocol or mailbox restrictions or grant Owner privileges just to pass
setup. Tools already configured for another scope remain available. This mode
does not establish realtime delivery, but does not disable a separately configured
receiver either.

## Shared projects and private state (native0.3.4)

Ordinary shared ancestry, including a POSIX0775 parent, is not a private-state
root. New connect and installation bookkeeping automatically uses the protected
OS-user state directory: XDG_STATE_HOME (or HOME/.local/state) on Linux,
HOME/Library/Application Support on macOS, and LOCALAPPDATA on Windows, under
peerwork. Do not place credentials in project references. A custom OS state-root
environment must be consistent between the local CLI and its host process.

The selected project's identity and existing participant binding are pinned.
MCP configuration remains executable configuration under the host's normal
workspace trust. The installer verifies its directories/files and uses anchored
filesystem operations; it does not change shared ancestors' permissions. New
project installation references are nonsecret; a format marker prevents an old
installer from establishing another ownership ledger. Existing ownership ledgers
are reused in place with their original lock. Older installers must be upgraded
before modifying an installation adopted by this version.

An existing private registry under writable ancestry is never silently adopted.
Its local OS owner may confirm that exact existing registry once:

```sh
peerwork connect --local ORIGINAL_REGISTRY --context --confirm-original
```

This is a local selection/association, not a Workspace permission approval or a
security-disable option. It requires an existing valid registry with its private
owner/file protections, takes the original writer lock, and pins its directory
identity in protected user state. It creates no signer or replacement identity,
copies no journal, and leaves source state and pending IDs in place. A changed
confirmed directory is rejected. If the original writer is busy, retain that
binding and retry after its existing operation completes. Programs can invoke
Rust Connect::confirm_original with equivalent local authority; MCP cannot
supply paths or perform this confirmation.

A verified live compatible runtime can be reused without repairing unrelated
admin metadata. Auto-start still requires the original identity/state/journal
namespace to pass strict private-path protection. ORIGINAL_RUNTIME_OWNER_START_REQUIRED
means its local owner must start/upgrade the original runtime; it does not
permit a new signer or copied history. Runtime support requires the existing
original-engine-binding-v1 feature (native0.3.3 or later), not a server migration.

CLI errors include a local_diagnostic with operation, policy, failed component,
actual effective UID and reason. Full paths stay local; MCP exposes only the
sanitized blocker. Distinguish ancestor-write, owner mismatch, symlink and OS
access denial. Never chmod/chown another user's directories to clear a blocker.

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
