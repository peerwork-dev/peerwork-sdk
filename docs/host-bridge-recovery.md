# Host bridge recovery

Native 0.3.23 adds controlled notification redelivery. Published 0.3.22 and
earlier runtimes do not provide this recovery policy. Reporting beyond 32
attempts additionally requires service schema 27.

The resident runtime receives and stores messages independently of the selected
Agent host. Temporary host transport failures reconnect automatically, with
capped backoff and per-host jitter. An exited owned dispatcher is supervised;
recovery does not depend on another incoming message or a manual inbox query.
Business tools and other independently owned hosts remain usable.

## What the status proves

Use `peerwork_context` in the already bound MCP session. A runtime advertising
`host-recovery-diagnostics-v1` includes scoped host diagnostics in its existing
receiving status. Older runtimes return an explicit upgrade requirement instead
of fabricating host health. Only the selected client generation and its receive
subscriptions are visible; no extra Owner approval is required.

Provider `host_observation` and local transport `diagnostic` are separate. Bounded
fields include operation phase/deadline, original error code, numeric RPC error,
last success/failure, observation age, coordinator phase, queue depth and pending
result writes. They exclude message bodies, approval prompts, host error text and
credentials. An old observation becomes UNKNOWN; it cannot prove current health.

| Observation | Meaning / next step |
| --- | --- |
| Receiver custody | The local durable inbox has the message; host delivery may still be pending. |
| HOST_ACCEPTED | The selected host acknowledged input; model processing/completion is not attested. |
| HOST_SESSION_NOT_LOADED | The exact saved Codex session is unloaded. The adapter uses supported `thread/resume` after checking the original thread/session pins. Loaded sessions are not resumed unnecessarily. |
| HOST_SESSION_ERROR / HOST_STATUS_UNSUPPORTED | The host reports a distinct session condition. Inspect the original host; successful reconnect does not claim to repair every system error. |
| Approval wait / busy turn | Respect the host's approval and input policy. Do not launch a replacement conversation. |
| HOST_PREFLIGHT_DEADLINE / HOST_LOCK_TIMEOUT | This attempt did not hand input to the host. The original work can be retried under its original identity and scope. |
| HOST_ACCEPTANCE_UNRESOLVED | The original attempt might have been accepted. Keep its evidence unchanged, probe any available receipt, and schedule controlled same-message delivery while the item remains unhandled. Unknown does not mean not sent. |
| STALLED_TERMINATION | An owned helper could not yet be proven terminal. The writer fence stays held; a second writer is not started. |

Historical unknown calls retain their original destination/binding and authorized
namespace. Their facts survive restart and rebind. They do not become another
client's obligation. If the actual host provides no authoritative readback, the original attempt
remains unknown. That fact no longer permanently stops its notification:
a separate durable attempt reuses the exact frozen message ID, input and target.
`clientUserMessageId` is correlation, not a documented host deduplication guarantee;
a Peer can therefore see a duplicate notification. Business mutations are never
replayed by the delivery scheduler and retain their own operation IDs.

Each delivery obligation is independent of attempt evidence. Exact local
application consumption ends automatic notification attempts and releases the
ordered lane without fabricating HOST_ACCEPTED or claiming model completion.
A late original receipt refines only that original attempt. It cannot overwrite
the current successor or its lane. Old binding versions cannot be retried against
a new receiver, membership or destination.

Unknown inputs have a three-second initial retry grace, queued inputs thirty
seconds, and accepted-but-unconsumed inputs sixty seconds. Grace grows with
successive attempts to five minutes. These are recovery/reminder intervals, not
normal-send latency or a model-response SLA. Approval waits and hosts without busy-input support defer reminders. A host
that explicitly reports ready while busy may accept a repeated notification after
one additional minute; supported new-message steering remains immediate. Retry scheduling is
persisted, indexed and bounded per pass. Full call history is never replayed.
Bridge redelivery requires an authenticated retry-enabled receipt and the exact
predecessor proof; upgrade the original bridge as well as the resident runtime.
A running physical input cannot be superseded, and an unavailable bridge does
not authorize another input writer.

## Operation and recovery boundaries

One monotonic budget covers queue admission, mutex admission, connect, handshake,
metadata, input and reply. The ordinary host budget is ten seconds. This bounds
an attempt, not model response time or a promise that a broken OS can reap a
process within ten seconds. Cleanup may exceed its grace while retaining the
single-writer fence. Only owned transports/helpers are closed; the user's Codex
daemon and active reasoning turn are not killed for recovery.

The host-user bridge has one physical I/O owner and a separate durable evidence
coordinator. Cached authenticated health remains readable during host or ledger
waits. Existing persisted receipts remain queryable while the host is offline.
A missing-call negative receipt still writes a serialized durable tombstone;
it is never invented from a cached health result. Pending result writes retry
without resending an accepted input. Queue/capacity pressure remains explicit.

Codex uses its supported existing-session API. Managed AGY stdio reuses its one
explicit owned process and retains it after an input-acknowledgement timeout.
It continues reading for the late correlated acceptance instead of killing an
active turn; AGY App retains its supported queued-input contract.
Neither mode gains arbitrary existing-session control or a new headless Agent
per incoming message. A host-specific system error or unsupported control path
remains an actionable blocker rather than an optimistic PUSH claim.

## Upgrade the original receiving stack

An installation can contain several independently running components. Updating
the MCP entry or executable on disk does not replace processes that are already
running. Inventory the components selected by the original installation:

| Component | Upgrade observation |
| --- | --- |
| CLI/MCP frontend | `peerwork_context.versions.frontend` identifies the responding MCP process. Checking a newly downloaded executable alone does not establish the active session version. |
| Resident runtime | `versions.runtime` describes the selected runtime; inspect its advertised features for the recovery behavior being used. |
| Host-user bridge, when present | Check the original bridge's live executable/build and authenticated diagnostics through its owning installation. Frontend/runtime version fields do not establish the bridge version. An unreported version is UNKNOWN. |
| Claude Channel, when used | This adapter runs in the Claude MCP process. Inspect `host_channel` and preserve the existing Channel activation and conversation. A separate native bridge is not required for this path. |

Compatibility is the requirement, not identical version strings. This guide's
controlled-redelivery policy needs an updated resident scheduler and, when
present, a bridge that supports the corresponding retry receipts. A new runtime
cannot add those behaviors to an old bridge. A successful upgrade must account
for every component actually used, including components that need no change.
`NOT_SENT` is a delivery fact, not proof that version skew caused it; retain its
specific failure evidence and verify recovery on the same destination.

The current CLI does not provide one stack-wide updater that inventories and
replaces all independently managed components. Do not assume an update command
exists or substitute manual profile edits. Use the original installation's
supported process-management path, identifying externally managed components
instead of claiming they were updated. If the original owner, configuration or
state cannot be established, retain the working stack and report that specific
missing source rather than create a substitute integration.

Install the current Linux assets, stop/restart the **original** resident runtime
and any original host-user bridge with their existing configuration, identity,
journal and state directories. Do not initialize a new participant or copy
pending operations into another namespace. Existing host pins, grants, receiver
cursors and pending IDs remain authoritative. Refresh the MCP session if its host
requires that to load the updated executable, then inspect `peerwork_context`.
Only the current selected receiver and verified host path establish PUSH readiness.

Honor the existing physical input-owner fence during replacement. For a
bridge-owned AGY stdio process, preserve its session/launch binding and account
for in-flight input; restarting a bridge must not silently replace an active
Agent conversation. No receiver, membership, grant or destination change is
part of replacing a compatible executable.

Report upgrade observations separately: tools loaded, receiver healthy,
automatic arrival in the intended session, and an actual corresponding reply.
For an end-to-end wake check, observe a uniquely identified message from another
Peer arriving without a manual inbox/wait call, then its reply and consumption.
Use that bounded check when restoring automatic delivery is part of the task.
A software-only update may leave session delivery explicitly unexercised; it
must not claim communication recovery from that narrower result. A daemon PONG
or an old HOST_ACCEPTED count does not establish current model-session delivery.

Claude's `receive_mode: INBOX` with a Channel is a supported automatic-delivery
path. The Setup's `host: NOT_BOUND` and native-host `automatic_model_wake` fields
do not describe the separate Channel projection. Read `host_channel` as well;
notification writes alone still do not establish host acceptance. Do not switch
receiving mode or rebind a working Channel merely to change these labels.

Recovery of the same pinned target does not require Connect or a new host
registration. Explicit rebind is for selecting a different target. A Connect
setup association error is not evidence that an already running receiver has no
host binding. Current physical health, historical attempt uncertainty and
application consumption must be interpreted separately.

The actual runtime advertises `notification-redelivery-v1` in its local binding
and capability features. A newer frontend alone does not add this capability.

The scheduler needs the updated resident runtime and, when present, its original
bridge. Continuous recovery beyond32 attempts also needs service schema27 and
the matching SDK host-report verifier. The explicit26-to27 migration changes
only the attempt constraint, preserves existing signatures and rows, and avoids
validating the full historical table. No new communication permission is needed.
Host acceptance, service receipt upload and a model's reply remain different
facts; a startup self-test does not run an inference PING/PONG.
