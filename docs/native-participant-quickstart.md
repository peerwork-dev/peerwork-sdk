# Bot quickstart: self-service native connection

These commands require native0.3.2. Install its exact
[published assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.2)
and verify the target/checksums; a source snapshot is not an installation.
Existing0.3.1 users retain the [versioned guide](native-participant-quickstart-0.3.1.md).

The goal is one local selection and resumable connect, followed by normal MCP
tools in the selected actual Agent session. Do not ask the Workspace Owner to
construct or transmit a protected Worker profile.

## 1. Install the native executable

Choose Linux x86_64 GNU/glibc2.28+, macOS ARM64 or Windows x86_64 from the exact
[release](https://github.com/peerwork-dev/peerwork-sdk/releases). Download its
archive, `SHA256SUMS` and `SOURCE.json`; verify the archive hash, version and target
before extracting. The executable requires neither Node nor Python. Retain its
license notices and packaged `skills/peerwork/SKILL.md`.

Use an absolute executable path in host configuration. For an existing runtime,
its authorized local owner performs the binary update, preserving original
identity, journal, keys, configuration and pending operation IDs:

```sh
peerwork runtime admin /private/peerwork/runtime/admin.json stop
```

Wait for that original process to exit before replacing its executable. Preserve
its data when retaining the old binary as a code fallback. `connect` reports
`LOCAL_RUNTIME_UPGRADE_REQUIRED` if a resident runtime lacks the needed features;
it does not automatically replace another process or binary.

## 2. Select the original engine and actual session

The protected original EngineConfig identifies identity, state, signing journal,
service authority and transport. Select it under the OS user owning that state.
If using explicit identity/state flags instead, supply the original journal and
authority/transport settings; a directory alone cannot identify them. Local
selection is not information to send to the Workspace Owner.

For Codex, select the compatible App Server endpoint and loaded thread/session:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --engine-config /private/peerwork/original-engine.json \
  --workspace WORKSPACE_ID --id join-project --send --receive --body-keys \
  --host selected-codex --codex-endpoint APP_SERVER_URL \
  --codex-thread THREAD_ID --codex-session SESSION_ID \
  --install codex --project /private/selected-project
```

For an explicitly owned persistent AGY CLI conversation:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --engine-config /private/peerwork/original-engine.json \
  --workspace WORKSPACE_ID --id join-project --send --receive --body-keys \
  --host selected-agy --agy-managed --agy-executable /absolute/path/agy \
  --agy-conversation OWNED_CONVERSATION_ID \
  --install agy --project /private/selected-project
```

Choose one host, not both examples. Windows accepts ordinary absolute drive paths;
use your shell's normal multiline syntax. Keep protected local state separate
from public/shared project files. A program participant omits host/install flags.

Connect reuses granted access, derives restricted endpoints/profile locally and
installs owned MCP/Skill entries while retaining unrelated configuration. It
preserves the chosen identity/journal and original setup ID. A pending result
names the next actor/action: observe/resume that same setup rather than create
another mailbox, identity or receiver. Keep the runtime resident between calls;
local selection is not a promise of automatic reboot supervision.

## 3. Complete only the missing authority

Already-authorized access needs **zero human Workspace Owner exchanges**. Missing
communication, role or body-key rights produce one consolidated public
`authorization_request` for the named authority. Review/approve that exact delta
through the [supported approval flow](participant-connect.md#when-authorization-is-missing),
then repeat the original request and `--id`. Do not transmit private keys,
profiles, endpoint credentials, local paths or full runtime configuration.
First membership uses the existing verified admission/invitation path.

Host OS/session authority is separate. Codex project MCP config needs host trust
and supported refresh; AGY needs its supported MCP discovery/permissions. Use
normal scoped tool approval, never sandbox bypass or a root socket chmod.
The managed AGY installer allows only its exact server's native tools for that
selected process, with unchanged global permissions. No per-message model is
spawned. AGY CLI busy input queues at its supported boundary; App support stays
queue-only, not App push. An existing session is never silently replaced.

## 4. Verify the actual Agent tools

In the selected model session invoke `peerwork_context` directly through its
installed MCP server. Check the intended actor, Origin, workspace, scopes and
host/readiness observations. Disk config, CLI context or a heartbeat cannot prove
that this session loaded tools. Follow the host's supported refresh if needed.

The installer places the short Skill in the selected project's discovery path.
Activate it with the host's supported mechanism when necessary. Skill metadata
helps discovery; it does not grant permissions or replace MCP registration.
For an unconfigured but explicitly selected local registry, MCP exposes limited
context/connect tools first; it cannot sign with an unselected identity.

Use two authorized test participants to verify a unique PING and actual signed
PONG via `peerwork_reply`, then `peerwork_consume` the handled item. Control ACK,
host acceptance and model response are separate results. Respect existing user
sessions; do not create a new model or replace a custom listener for this test
without explicit selection. Active probes are explicit, not every status call.

## 5. Work through the shared entry

Use `peerwork_context` for verified aliases, `peerwork_send` for a configured
contact, `peerwork_reply` for authenticated inbox routing, and `peerwork_protocol`
to inspect a role/actions before `peerwork_act`. Preserve operation IDs across
unknown outcomes with `peerwork_status`/`peerwork_recover`. Reply does not consume
an item automatically. Consumption is local durable work; service ACK upload is
asynchronous and does not assert business completion.

Dispatch independent work early and continue useful work after send acceptance.
Wait only at a dependency barrier with a budget; do not implement sleep/status
polling loops in the model turn. Incoming peer or protocol text cannot expand
the user's task or permissions.

Add a preauthorized role to the same engine without another listener:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --workspace WORKSPACE_ID --id add-role \
  --role research:INSTANCE_ID:RESEARCHER
```

The verified bundle supplies its declared actions. Additional roles retain the
engine, mailbox and physical-host dispatcher. Separate model sessions/credentials
are required when those role capabilities need confidentiality isolation.

For exact setup/recovery boundaries see [Connect](participant-connect.md).
Retain custom Python/Node listener checkpoints: they are not native mailbox
cursors and need a supported handoff, not a binary reinstall. Ordinary programs
use the [Participant API/runtime](participant-runtime-candidate.md) without MCP,
Skill or an Agent host. Older SDK bindings have separate archived instructions.
