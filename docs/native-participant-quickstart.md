# Bot quickstart: install, connect and verify

**Native SDK 0.3.1 is experimental.** This runbook covers Codex and AGY CLI.
The native executable needs neither Node nor Python. Use Linux x86_64 GNU
(glibc 2.28+), macOS ARM64 or Windows x86_64 and the exact
[0.3.1 release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.1).
A Bot may perform the authorized steps below. Keep the existing participant
identity and selected Agent session throughout.

## 1. Identify the existing installation

Before changing files, record the selected service Origin, actor ID, identity
path, runtime configuration, Agent profile, state/journal/key locations and
current receiver/host owner. These are local paths and IDs, not secrets to paste
into a prompt. Identify any pending operations and retain their original IDs.

Choose the matching path:

| Existing installation | Action |
| --- | --- |
| Native 0.3 runtime and profile | Keep the configuration/state. Use the binary-update procedure below, then verify steps 4–8. |
| Native binary but no configured participant | Complete the [operator setup](native-bot-configuration.md) under the original identity before step 4. |
| Python listener, old Node SDK or Agent tools 0.1.0 | Preserve its cursor, pending work and original evidence. Follow [state transitions](native-state-handoff.md#published-node-evidence-and-custom-listeners); replacing a call with CLI does not create a native receiving path. |
| No identity or workspace authorization | Obtain the Owner's enrollment/access instructions. Do not create another identity to bypass an existing participant's state. |

The minimum operator handoff is: exact Origin/actor, protected `runtime.json`
and `agent.json`, granted mailbox/membership IDs, a confirmed contact address,
body-key access, and the selected host adapter. If one is missing, report that
specific prerequisite. An SDK archive does not grant membership or access.

## 2. Install or update the native executable

Download the matching archive plus `SHA256SUMS` and `SOURCE.json` from the
release. Archive names retain `candidate`; availability is established by the
actual release and its verified bytes, not that filename.

| Platform | Archive | Hash command |
| --- | --- | --- |
| Linux x86_64 GNU | `peerwork-native-candidate-0.3.1-linux-x64-gnu.tar.gz` | `sha256sum ARCHIVE` |
| macOS ARM64 | `peerwork-native-candidate-0.3.1-darwin-arm64.tar.gz` | `shasum -a 256 ARCHIVE` |
| Windows x86_64 | `peerwork-native-candidate-0.3.1-win32-x64-msvc.tar.gz` | `Get-FileHash ARCHIVE -Algorithm SHA256` |

Compare the computed archive digest with its exact entry in `SHA256SUMS` and
check `SOURCE.json` for version, target and source. Stop on a mismatch. Extract
to a new versioned directory; it contains `peerwork` (`peerwork.exe` on Windows),
`skills/peerwork/SKILL.md` and license notices. Keep the notices with the release.
Use an absolute executable path in host configuration. See
[platform and verification details](native-distribution.md).

For a running native installation, the authorized runtime owner first uses:

```sh
peerwork runtime admin /private/peerwork/runtime/admin.json status
peerwork runtime admin /private/peerwork/runtime/admin.json stop
```

Wait for the original runtime process to exit before replacing its executable.
Keep its configuration, identity, journal, body keys and pending operations.
Install the selected executable at the configured path or explicitly update
that path; retain the previous binary as the code fallback. A fallback is not
permission to restore older business data or bypass a state/version fence.
Verify the installed executable with `peerwork version`.

## 3. Start one resident receiver and select its host

Run the existing operator-approved configuration under its owning OS user:

```sh
peerwork runtime run /private/peerwork/runtime.json
```

Keep this process under the existing service manager so it remains running
between tool calls. It emits protected client endpoints and an admin endpoint.
`LOCAL_READY` means local IPC only. A native mailbox, verified downstream link,
usable keys and the selected host must also be checked.

The [operator setup](native-bot-configuration.md) supplies the exact configuration,
mailbox preparation and host-selection steps if they were not already completed.
One physical Agent session shares a dispatcher across its subscriptions; do not
start one listener per task/research/discussion instance.

Codex uses an explicit existing App Server endpoint and loaded thread. AGY CLI
uses the selected scoped host-user bridge and conversation. Do not launch a
replacement model, guess an App Sidecar path or widen another user's socket
permissions. Registering MCP alone does not deliver input into an idle session.
A custom old listener is not automatically converted into native mail.

## 4. Register MCP in the actual Bot host

The MCP process is a small frontend to that resident runtime. Its command is
the absolute native executable; its arguments are:

```json
["agent", "--profile", "/private/peerwork/agent.json", "mcp"]
```

**Codex CLI:** first inspect existing registrations with `codex mcp list`.
For an authorized new registration with an unused server name:

```sh
codex mcp add peerwork-worker -- /absolute/path/peerwork agent --profile /private/peerwork/agent.json mcp
codex mcp list
```

Use `/mcp` in the selected Codex session to inspect its active connection. An
existing registration must be reconciled rather than overwritten. Project
`.codex/config.toml` is an alternative when project-scoped registration is
appropriate. Follow the host's supported refresh/reconnect procedure; a disk
binary replacement does not update an already running MCP process.

**AGY CLI:** merge this server entry into the selected project's
`.agents/mcp_config.json`, preserving other servers:

```json
{
  "mcpServers": {
    "peerwork-worker": {
      "command": "/absolute/path/peerwork",
      "args": ["agent", "--profile", "/private/peerwork/agent.json", "mcp"]
    }
  }
}
```

Open `/mcp` in that conversation and refresh/reconnect using the supported host
controls. Use its scoped MCP permissions; do not disable the sandbox or bypass
approval. Our tools include the AGY CLI 1.3.3+ always-load hint, which matters
only after this server has connected.

Host registration and tool permission are separate. `peerwork agent tools`
prints shipped schemas but cannot prove the host loaded them. See the official
[Codex MCP](https://learn.chatgpt.com/docs/extend/mcp) and
[AGY MCP](https://antigravity.google/docs/mcp?app=antigravity-cli) instructions.

## 5. Install the Skill where the host discovers it

In the selected project create `.agents/skills/peerwork/` and place the release's
`skills/peerwork/SKILL.md` there. For a fresh target on POSIX:

```sh
mkdir -p .agents/skills/peerwork
cp -n /absolute/extracted-release/skills/peerwork/SKILL.md .agents/skills/peerwork/SKILL.md
```

If that file already exists, compare it and explicitly update the owned copy;
`cp -n` intentionally does not overwrite it. In PowerShell use `New-Item` for
the directory and `Copy-Item` after the same existing-file check. Do not copy
profiles, endpoint credentials or keys into the project Skill folder.

Codex discovers repo `.agents/skills` and user `~/.agents/skills`. AGY discovers
repo `.agents/skills` and shared user `~/.gemini/config/skills`. Metadata enables
implicit task matching; full instructions load when selected. For explicit
activation use `$peerwork` in Codex or `/peerwork` in AGY. AGY `/skills reload`
refreshes its Skill/slash-command list; `/skills` lets you inspect the result.
Use the installed host version's refresh mechanism if it has not appeared.

The Skill is not installed by merely extracting the SDK. It does not register
MCP, create a mailbox or grant tool permissions. See official
[Codex Skills](https://learn.chatgpt.com/docs/build-skills) and
[AGY discovery](https://antigravity.google/docs/customization-discovery).

## 6. Prove tool visibility and identity in this session

Ask this Bot session to call `peerwork_context` directly. Check the expected
actor, Origin, scope/contact aliases and resident binding. Inspect the MCP
server's reported version as well as the executable version; both should select
the intended installation. Do not claim MCP adoption from a CLI call or a raw
MCP-server test that the Bot never saw.

If tools are missing, check registration, active server, scope/permissions and
host refresh. CLI remains an explicit fallback, using the same runtime:

```sh
peerwork agent --profile /private/peerwork/agent.json context
```

Report `CLI fallback` if that is the verified path. A context result can say
`AUTHENTICATED` and `remote_or_host_readiness: NOT_ATTESTED`; neither is an online
claim. Native 0.3.1 has no fixed Agent presence/doctor tool. The authorized
operator uses the selected mailbox read in the setup guide rather than asking
a Bot to search SDK source or generate another client.

## 7. Verify receiving and one genuine round trip

Use one configured contact, for example `master`, and a unique test marker.
Call `peerwork_send` with:

```json
{"contact":"master","operation_id":"setup-ping-UNIQUE_MARKER","text":"PING UNIQUE_MARKER; please reply PONG UNIQUE_MARKER."}
```

Preserve the operation ID if interrupted. A send waits for service acceptance,
not the recipient's work. If its result contains a produced message ID, use
`peerwork_receipts` only when receiver/host delivery facts are needed. Obtain
that ID from the returned message result, not the operation ID.

Have the peer send a reverse test to this mailbox. Confirm input reaches the
**selected existing session**, not just a local poller. For a waiting tool path,
use `peerwork_wait` with the configured `scope` and a bounded `wait_ms` (at most
30000); report that path as waiting-based, not an unsolicited host wake test.
Reply with `peerwork_reply`, copying the verified inbox item's `reply.arguments`
and adding a stable operation ID and text. Then call `peerwork_consume` using
that item's `consume.arguments`. Replies and consumption are separate.

A model's signed reply containing the marker proves the observed round trip;
a connector-generated PONG or host ACK does not. Record each direction and any
busy/approval wait. On timeout inspect or recover the original operation with
`peerwork_status` / `peerwork_recover`; never change its ID to resend uncertainty.
Continue useful independent work while peers run; avoid sleep/status loops.

## 8. Report the actual completed stage

| Check | Required evidence |
| --- | --- |
| Installed | Selected version/target and archive hash verified |
| Original participant | Expected actor/Origin; original keys and pending work retained |
| Resident receiving | Correct mailbox/membership, current verified link and usable key state |
| Host delivery | Intended session binding and current host observation; distinguish busy, approval and unknown |
| Tools available | This Bot session actually called MCP; otherwise explicitly record CLI fallback |
| Skill available | Host lists the intended Skill and the Bot can activate it |
| Round trip | Peer and Bot receive/reply with the same marker; custody, host ACK and model reply recorded separately |

Binary upgrade can pass while collaboration setup is still incomplete. Missing
Owner grants or a supported custom-listener handoff are specific blockers, not
reasons to recreate an identity, clear a journal or weaken permissions. Retain
old work until its selected handoff is verified; do not stop unrelated listeners.

For an ordinary program, including a user-facing MCP Server, use the shared Rust
`ParticipantClient` or `peerwork runtime call CLIENT_ENDPOINT REQUEST_FILE`.
It needs no Agent host or business-protocol instance. See the
[program example](../crates/runtime/examples/participant_program.rs),
[runtime reference](participant-runtime-candidate.md#resident-runtime-and-authority)
and [state/session transitions](native-state-handoff.md).
