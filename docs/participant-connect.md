# Connect an existing participant

**Unreleased native candidate.** Published native SDK0.3.1 does not include
this connect workflow. Use this guide only with a qualified build explicitly
providing `peerwork connect`; release availability and target hashes must be
published before treating it as an installation guide for a released version.

Connect uses the existing identity and signing journal, discovers bounded current
access and derives local client configuration. An already-authorized Worker does
not need the Workspace Owner to construct or transmit an Agent profile.
Programs use the same Participant engine without an Agent host, MCP or Skill.

## Select the original local engine

Run initial selection under the OS account that owns the identity and state.
Choose the protected original EngineConfig; it identifies the original journal,
service authority, transport and key store. A state directory alone cannot
identify those settings. Retain unresolved operations and their original IDs.
Do not substitute a fresh identity when selection or recovery is blocked.

The examples use local placeholder paths and IDs. These are explicit local
selections, not information to send to the Workspace Owner. Keep state/config
private; do not place credentials in shared project files or chat.

For an ordinary program participant:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --engine-config /private/peerwork/original-engine.json \
  --workspace WORKSPACE_ID --id join-project --send --receive --body-keys
```

An existing restricted runtime endpoint can instead be selected with `--client`,
`--origin` and `--actor`. It does not grant runtime administration: selecting an
Agent host on an external runtime requires its explicitly authorized `--admin`.
Initial bootstrap records only the runtime it actually owns.

## Select the actual Agent session and install its integration

Choose the host before activating the initial Agent receiver. Connect cannot
silently move an existing program receiver to a different physical destination.
Use the same engine inputs as above and add the selected host:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --engine-config /private/peerwork/original-engine.json \
  --workspace WORKSPACE_ID --id join-project --send --receive --body-keys \
  --host selected-codex --codex-endpoint APP_SERVER_URL \
  --codex-thread THREAD_ID --codex-session SESSION_ID \
  --install codex --project /private/selected-project
```

Codex needs a compatible App Server and the explicitly selected loaded thread.
Project MCP configuration must be trusted by Codex and refreshed through its
supported controls. Connect does not grant project trust, widen another OS
user's socket permissions or replace the selected thread. A required host
refresh is separate from Workspace Owner approval.
The host may also ask permission for specific MCP tools. Use its normal scoped
approval controls; Workspace access and Skill installation do not approve those
host prompts or authorize sandbox bypass.

For an explicitly owned persistent AGY CLI conversation:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --engine-config /private/peerwork/original-engine.json \
  --workspace WORKSPACE_ID --id join-project --send --receive --body-keys \
  --host selected-agy --agy-managed --agy-executable /absolute/path/agy \
  --agy-conversation OWNED_CONVERSATION_ID \
  --install agy --project /private/selected-project
```

This explicitly resumes that conversation in one persistent process. It does
not attach to an arbitrary interactive process or spawn a model per message.
Busy AGY CLI conversations queue input until the supported turn boundary.
Selecting `--install agy` grants only the installed server's exact native MCP
tools for this managed session. Global permissions, shell/filesystem grants
and sandbox policy are unchanged. Existing AGY App support is queue-only;
managed CLI qualification does not prove App push support.

The installer derives the protected profile/endpoints locally, merges owned
project MCP/Skill entries and retains unrelated/preexisting files. A conflict
returns a specific repair action rather than overwriting it. Removing the
integration retains identity, original journal and recovery data by default.
No Node or Python runtime is added by the native client.

## When authorization is missing

Connect reports the exact missing communication, business-role and body-key
rights in `authorization_request`, together with the responsible authority.
Use the existing admission path or a verified handoff for that public request;
it must remain usable before the requester has business-mailbox send rights.
Do not send the full local registry/profile, endpoint credentials or any key.

An already configured authorized approver reviews that semantic delta and uses:

```sh
peerwork connect --local /private/approver/local --participant owner \
  --id approve-join-project --approve-request public-request.json
```

The requester repeats the **same original connect request and setup ID** after
approval. Existing rights require zero human Owner exchanges. Missing rights
use one consolidated meaningful request/approval per responsible authority;
this does not mean one HTTP request or automatic approval. Finite leases are
preserved; future key rotation access is not silently granted.

## Discover tools, use roles and continue work

The Agent calls `peerwork_context` through the installed MCP server in its
actual session. It sees pinned identity/Origin, scopes, capability catalog and
setup/readiness observations. Installation files alone do not prove model tool
visibility. An unconfigured MCP frontend exposes only bounded discovery/connect
under explicitly provisioned local authority:

```sh
peerwork agent --local /private/peerwork/local \
  --participant worker --workspace WORKSPACE_ID mcp
```

MCP arguments cannot select arbitrary key files, admin tokens, sockets or
executables. Initial local-owner selection registers those trusted handles.
The short Skill explains normal send/reply, bounded waits and original-intent
recovery. Dispatch independent work early and continue useful work after send
acceptance; wait only at a dependency barrier with a stated time budget.

Add a preauthorized business role without rebuilding local configuration:

```sh
peerwork connect --local /private/peerwork/local --participant worker \
  --workspace WORKSPACE_ID --id add-research-role \
  --role research:INSTANCE_ID:RESEARCHER
```

The verified bundle supplies that role's declared actions. A role is permission
on a workflow instance, not another Agent identity, mailbox or listener. Same
engine role addition preserves the runtime and physical-host dispatcher.
Unchanged reentry is observation, not a restart or a surprise probe message.
Confidentiality separation between model sessions still requires separate
credentials/sessions; one session can use its combined authorized role views.

Use `peerwork_reply` for authenticated inbox routing, then `peerwork_consume`
only after handling the item. Reply does not consume automatically. Consumption
is a durable local request; signed service ACK upload proceeds independently.
A timeout does not permit a new operation ID for the same uncertain submission.

## Readiness and recovery boundaries

Readiness reports local runtime, access/keys, receiver link, host mode and actual
tool visibility separately, with observer/scope/freshness. Heartbeat, registration,
queued input, host acceptance, model reply and business completion differ.
An empty observation is not proof that every participant is offline.

| Result | Responsible actor and next action |
| --- | --- |
| `OWNER_APPROVAL_REQUIRED` / `KEY_AUTHORIZATION_REQUIRED` | Named remote authority reviews the exact requested delta; requester resumes the original setup. |
| `LOCAL_SELECTION_REQUIRED` | Local operator selects the original protected engine/registered handle. |
| `LOCAL_RUNTIME_UPGRADE_REQUIRED` | Runtime owner performs the supported binary update, preserving identity, journal and pending work; resume the original setup. |
| `HOST_BINDING_REQUIRED` / `HOST_DELEGATION_REQUIRED` | Host OS/session owner selects or narrowly delegates the supported interface. Workspace rights do not authorize root socket access. |
| `HOST_REFRESH_REQUIRED` | Use the selected host's supported refresh procedure and verify actual tool invocation. |
| `RECOVERY_REQUIRED` / `BROKEN_BINDING` | Recover original provenance/state; do not silently create a replacement identity. |

Derived profile loss can be repaired from a verified local registry and original
runtime binding. Missing/corrupt original provenance cannot. Revocation fences
new use of old clients while preserving original admitted operations and unknown
host facts. Unknown host input is reconciled, never replayed into another session.
Custom Python/Node listener cursors are not native mailbox cursors: retain their
original evidence and use only a supported handoff. General custom-listener
conversion, universal session attach and automatic binary upgrades are outside
this workflow.
