# Host bridge recovery

## Installed startup recovery

Native 0.3.35 adds `automatic-runtime-startup-v1`. An installed receiving
integration restores its original owned runtime when the normal MCP/harness
starts, without a Context, Connect, inbox or resume call. The same task observes
a later runtime exit while MCP remains active. It uses the original installation,
launch proof, namespace and writer fence; it does not create another identity,
receiver, model process or conversation.

Runtime startup intent is separate from observed liveness and notification
pause. Installation preserves an existing disable. A normal runtime admin stop
records disable before stopping; update/rebind maintenance keeps startup intent
and excludes concurrent recovery. The installation or explicit updater commits
one verified startup artifact; the runtime never rewrites that target. An older
installation without a supported artifact needs the original-stack update,
not repeated setup or Owner approval. A dead legacy
installation without startup policy requires one explicit original recovery;
its absent PID cannot establish whether the user stopped it.

Temporary failures continue with bounded frequency and backoff. Initialization,
tools and pause remain independent of the recovery loop. Several installed MCP
frontends share the same original runtime. An interrupted compatible update
resumes its recorded artifact and operation; a changed artifact is a blocker.

`local_startup` is a cached installation observation in Context/delivery and a
deduplicated transition hint in ordinary tool results. `RUNTIME_RUNNING` proves
only process liveness; use current delivery health for receiver and host facts.
Repeated tool calls do not add health requests or self-tests. Stderr also reports
bounded transitions. These surfaces cannot notify a model when its harness is
not running, and MCP instructions are not a guarantee of model attention.

Notification pause remains durable and retains pending work. Explicit
`peerwork_delivery` resume may restore the original installed runtime and resume
notifications. Host-required activation, including Claude Channels opt-in, still
belongs to the original host. Endpoint changes do not authorize another session.
External supervisors and embedded clients keep their existing lifecycle;
no OS service or new client dependency is installed automatically.

## Native0.3.34 current host health

`current-host-delivery-health-v1` gives Context, Delivery status and Connect the
same interpretation of current receiving and selected-transport observations.
`state` describes current readiness; `control_state` retains scheduling intent.
`last_verified_at` and `historical_verification` describe a previous bounded local
inbox read, not permanent availability or a model response. A fresh required host
blocker overrides that history. Cached observation age includes local residence.
Claude Channel polling and AGY App queued input retain their own capability
contracts; neither requires a fictitious Codex host or attests model processing.

Codex's selected endpoint must actually own the pinned conversation. A stored
thread ID alone is insufficient. If that host rejects resume because another
writer holds the session, the adapter reports `HOST_SESSION_OWNERSHIP_CONFLICT`.
It observes the original owner's metadata without repeating resume or creating
another conversation; normal delivery resumes when that same owner loads the
pinned session. Inbox custody and business tools remain available meanwhile.
Use the returned `next_action` to correct a mismatched host. Never remove a
writer lock, copy an identity or kill the user's session to make PUSH look ready.
Direct CLI launch alone does not establish incompatibility: use the selected
host version and supported shared-daemon/remote/standalone mode.

An ownership conflict does not identify the other writer or establish that the
current conversation is standalone. The connection-recovery update reports
`VERIFY_SELECTED_CODEX_ROUTE_AND_ORIGINAL_SESSION_OWNER`, with owner identity
and the need to exit explicitly undetermined. First verify the selected existing
route. A healthy shared host needs no exit/relaunch. Only a confirmed standalone
owner without a supported control endpoint needs a one-time handover using that
Codex installation's standard resume flow. After its writer exits, explicitly
load the exact saved thread on the selected shared host; merely exiting does not
reset the SDK's resume suppression. No project Python launcher is required.
Do not remove locks, kill the session or change sandbox/model settings to repair
an unverified route.

RPC/handshake diagnostics distinguish ownership, access/authentication,
unsupported API, binding and temporary transport failures, retaining safe codes
and phases without exposing arbitrary host errors. Claude scope failures use the
same classified backoff. Changes of receiving binding, generation or destination
must revalidate the selected projection; notification writes do not prove wake.
Update affected original runtimes and independent bridges when present. The
owned updater requires the new capability; external hosts keep their existing
supervisor and state. A completed update is distinct from restored delivery.

## Native 0.3.31 policy

Compact delivery replaces full-body reminders with
one minimal notification followed by `peerwork_inbox` using its batch reference.
See [compact delivery and controls](agent-delivery.md#native-0331-compact-notification-delivery)
for bounded reads, fresh/active views and the distinction between automatic local
notification acknowledgement and explicit application consumption.

The original frontend, resident runtime and bridge, when present, need compatible
`compact-notifications-v1` support. Preserve original identity, state, receiver,
pending IDs and host-session pins. Updating only the frontend does not upgrade a
running scheduler or bridge. No new Workspace Owner permission is introduced.
Do not restart a deliberately stopped stack as a side effect of inspection.

Use the selected client's `peerwork_delivery` controls, or
`peerwork agent --profile PROFILE.json delivery status|pause|resume|self-test`.
Manual pause persists across restart and prevents new notification admission;
it does not consume pending work or retract already-written host input. Inspect
pause/enforcement results before upgrading original components. The self-test
belongs to this upgrade/resume workflow, not to a separate service or model
process. It observes the local notification/read path, not end-to-end service
transport or a real business reply. Preserve approval waits and current host
activation; AGY queued input and Claude Channel remain supported observations.

Batch progress is independent of `consume`. A valid bounded inbox result triggers
an internal local observation acknowledgement inside the same tool invocation;
there is no additional model ACK call. Unhandled work remains available through
`view: active`. Compact wake backoff is shared across the bound destination's
batch, preventing each old unconsumed document from generating another full-body
reminder. Unknown host acceptance remains unknown, and exactly-once model input
is not promised.

The remaining sections preserve the original recovery foundation and stack
boundaries. The per-item body-reminder policy below applies to 0.3.23–0.3.30;
0.3.31 uses the compact batch policy above.

## Published 0.3.23–0.3.30 notification policy

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

Live unknown calls retain their original destination/binding and authorized
namespace. Their facts survive restart and rebind. Native 0.3.30 bounds local
retention after reporting, generation fencing or exact consumption; see
[notification state retention](notification-state-retention.md). Retirement never
invents a host result. They do not become another
client's obligation. If the actual host provides no authoritative readback, the original attempt
remains unknown. That fact no longer permanently stops its notification:
a separate durable attempt reuses the exact frozen message ID, input and target.
`clientUserMessageId` is correlation, not a documented host deduplication guarantee;
a Peer can therefore see a duplicate notification. Business mutations are never
replayed by the delivery scheduler and retain their own operation IDs.

Each delivery obligation is independent of attempt evidence. Exact local
application consumption ends automatic notification attempts and releases the
ordered lane without fabricating HOST_ACCEPTED or claiming model completion.
Before local evidence retirement, a late original receipt refines only that
original attempt. It cannot overwrite
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
without resending an accepted input. Queue/capacity pressure remains explicit. Native 0.3.30 compacts legacy local
notification evidence and performs retirement even while new-input admission is
full; preserve the original state when upgrading both Runtime and bridge.

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

Compatibility is the requirement, not identical version strings. The published legacy
controlled-redelivery policy needs an updated resident scheduler and, when
present, a bridge that supports the corresponding retry receipts. A new runtime
cannot add those behaviors to an old bridge. A successful upgrade must account
for every component actually used, including components that need no change.
`NOT_SENT` is a delivery fact, not proof that version skew caused it; retain its
specific failure evidence and verify recovery on the same destination.

For an authorized upgrade, install the current Linux executable and run its
selected-client update entry:

```sh
peerwork connect --local ORIGINAL_REGISTRY --participant HANDLE --update status
peerwork connect --local ORIGINAL_REGISTRY --participant HANDLE --update apply
```

An existing project selection can supply the registry and handle. For an owned
runtime, `status` inventories the recorded installation and its effective host
configurations.
This includes bridges added or rebound after installation and configured hosts
whose sources are currently blocked; superseded base selections are omitted.
A running owned runtime supplies this inventory through authenticated admin
status. Stopped installations and older runtimes that lack the inventory field
use the original protected host state with the same configuration merge rules.
The admin `hosts` field describes dispatcher observations; `host_configurations`
contains the full configured selection. Update completion uses the current
effective inventory, including after an interrupted update.

`apply` uses the executing CLI as its target, checks required runtime features, and
leaves a compatible running runtime unchanged regardless of version equality.
It updates owned MCP/Skill entries through the existing installer. This release's
runtime requirement is `host-observation-upload-deadline-v1`.

The update records its original configuration before authenticated stop and
restart. Repeat the same command with the same executable after interruption or
failed start; it resumes the original operation and launch fences. Keep that
artifact available until the operation completes. Identity, journal, pending
IDs, host destinations, approval waits and durable delivery pause remain in
place. An already stopped owned runtime stays stopped. It is not reported as
running the new version until it is started through its original lifecycle.
The command does not replace a running binary on disk or download a release.

Externally managed runtimes and original bridges remain under their existing
launcher. The returned `continuation` lists the exact recorded host/project/server
selections and requests their supported reload, followed by `peerwork_context`
and `peerwork_delivery` status in the same host. It does not invent a host reload
API, new session or process authority. A loaded MCP/Channel/bridge version that
cannot be observed stays UNKNOWN. `OWNED_UPDATE_COMPLETE` means owned work has
finished; a non-null continuation still needs external action. No receiver,
membership, grant or destination change is part of this update.

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

## Current receiving and saved setup

`peerwork_context` includes `delivery_status`, a read-only view of the selected
receiving scopes. A compatible runtime advertises
`current-delivery-observation-v1`; older runtimes leave current observations
UNKNOWN. The view separates current receiver custody, pause/stopped state,
body-key freshness, Channel observations and saved setup objectives. Setup scope
matches do not complete a requested host or role objective. Reading context does
not resume delivery, change a setup, rebind the host or request new authority.

Channel observations are matched to the selected actor, Origin, mailbox,
membership and local client binding; stale or different observations stay
UNKNOWN. Channel notification writes still do not attest host acceptance or
model response. A pending role approval can coexist with working receiving.
Use the returned current blocker/next action and preserve the original setup
reference when continuation is needed.

Runtimes advertising `host-observation-upload-deadline-v1` schedule refreshes
against the actual last uploaded host and key observation times. Unchanged
local probes are coalesced before the existing freshness deadlines. A slow
pulse or clock retry retains the original observation age, and fresh pulses do
not delay independent acknowledgment work. This does not change service expiry
policy or promise host/model response latency. Adopt the changed original
resident runtime to obtain this scheduling correction; changing only a loaded
MCP executable is insufficient.

An authenticated `STREAM_TIME_WINDOW_INVALID` is retryable: the runtime refreshes
signed service time and reconnects with backoff capped at eight seconds. It keeps
the original receiver and delivery checkpoints, and reports `RECONNECTING` until
a frame verifies. Updating also allows a previously persisted time-only rejection
to retry after verified session setup. Other frame verification failures remain
quarantined. A generic `STREAM_VERIFICATION_FAILED` is insufficient to diagnose
clock skew: inspect the selected receiver's `verification_failure.code`,
`phase`, and `scope_authenticated` fields without collecting message bodies.
