# Host bridge recovery

Native0.3.41 adds [interactive AGY background receiving](agy.md) on the existing
native inbox. Refresh the owned MCP entry, arm `peerwork_listen`, read its compact
batch on completion, and rearm. This path needs neither an App endpoint nor a
managed stream-json child. Preserve an existing working App/managed binding.
Quiet waits do not poll the model. Temporary stream/IPC failures use the same
original source with backoff; permission, binding or persistent verification
failures remain explicit. Existing stop/pause and original pending work survive.

## Installed startup recovery

Native 0.3.35 adds `automatic-runtime-startup-v1`. An installed receiving
integration restores its original owned runtime when the normal MCP/harness
starts, without a Context, Connect, inbox or resume call. The same task observes
a later runtime exit while MCP remains active. Native0.3.43 first authenticates
a healthy endpoint against the original client binding, without requiring old
config, PID or launcher records. Starting, stopping or transferring the owned
runtime still validates its original ownership, configuration, selected artifact
and writer fence. Recovery preserves the identity, namespace and conversation.

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
deduplicated transition hint in ordinary tool results. `RUNTIME_RUNNING` is a
runtime observation; use current delivery health for receiver and host facts.
Repeated tool calls do not add health requests or self-tests. Stderr also reports
bounded transitions. These surfaces cannot notify a model when its harness is
not running, and MCP instructions are not a guarantee of model attention.

Notification pause remains durable and retains pending work. Explicit
`peerwork_delivery` resume may restore the original installed runtime and resume
notifications. Host-required activation, including Claude Channels opt-in, still
belongs to the original host. Endpoint changes do not authorize another session.
External supervisors and embedded clients keep their existing lifecycle;
no OS service or new client dependency is installed automatically.

## Receiving activation replacement

Native0.3.43 keeps one durable original Peer client while allowing ordinary tool
frontends to attach. A new opted-in receiving activation can replace the current
activation for its selected original source. The latest committed activation
wins; opening an RPC connection, reading status or using a newer executable does
not select a receiver. Other Peers, Spaces and separately bound conversations
retain their own receiving state.

The current activation reconnects with its existing identity. A superseded
activation stops receiving and cannot reclaim ownership through automatic retry.
Notification admission fences stale output while preserving original batches,
backoff and already admitted or UNKNOWN host attempts. Replacement does not
clear pause/stop or create a fresh self-test success. Ordinary tools and pending
operation recovery continue through the original client.

Use the host's existing opt-in or selected Connect/rebind flow; no activation
IDs need to be assembled by the Agent. Changing a destination still requires
the exact supported host selection. An older frontend that lacks activation
fencing must release its original projection through the normal host refresh
or drain before replacement. Keep physical host locks and refresh the original
runtime/frontend together; never delete a lock or redirect an uncertain input.
This does not give the SDK control over arbitrary sessions or attest a model
response.

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
current conversation is standalone. Native0.3.40 reports
`VERIFY_SELECTED_CODEX_ROUTE_AND_ORIGINAL_SESSION_OWNER`, with owner identity
and the need to exit explicitly undetermined. First verify the selected existing
route. A healthy shared host can keep its current session. For a confirmed
standalone owner, check whether the
[local queue](#use-the-local-queue-for-an-existing-codex-thread) can serve the
original thread. If the operator chooses the control-endpoint path and a
handover is required, use the installation's standard resume flow after the
original writer exits. Load the exact saved thread on the selected shared host.
The SDK keeps its resume suppression across exit. Keep locks, the original
session and sandbox/model settings intact during diagnosis.

After a destination has been persisted, a restarted dispatcher or bridge checks
the original Codex thread without requesting its writer. If the thread is not
loaded, delivery reports `HOST_SESSION_NOT_LOADED` and keeps the inbox available.
After an upgrade, this code still describes the selected App Server route.
Confirm the actual owner and delivery mode before restarting any component.

A protected Codex host configuration can opt in to route discovery by listing
one to four additional Unix control endpoints in `codex_routes` and pinning
`expected_session_id`. Start or resume the thread using that Codex installation's
normal interface. Peerwork discovers the exact original thread and session
among the configured endpoints when attaching or recovering. The original
destination digest and inbox stay fixed. An ambiguous route blocks attachment.
Select only endpoints controlled by the original host user. A session without
a supported control endpoint keeps inbox access and can use the local queue
when its prerequisites are met.

For a running Codex Bridge, the local host integration can update the allowlist
with `peerwork bridge codex-routes CONFIG.json unix://SOCKET`. The command
replaces the additional endpoints in the original Bridge's protected state.
It accepts up to four endpoints. Use the command without endpoints to clear the
list. It leaves the startup configuration, original destination, credentials
and inbox intact.

If the original Bridge selected a custom proxy socket and pinned the Codex
installation and OS user, recovery also checks that installation's standard
daemon socket. The exact original thread and session must be loaded there.
Peerwork verifies the local socket's peer UID and never starts a Codex daemon
or resumes the thread while finding its owner.

An initialized Bridge with a pinned, same-user Codex installation can use that
installation's local queue when the original App Server no longer loads the
exact thread, reports another writer, or its explicitly pinned socket is gone.
The original thread UUID must also be the original session ID. Peerwork keeps
the Bridge, destination and admission records. An earlier accepted, queued or
uncertain notification stays fenced across both paths. A confirmed no-input
attempt remains retryable. A fresh queue receipt does not establish that the
thread is active or has read the inbox.

When the Bridge confirms that a notice cannot safely be repeated, a newer
verified inbox head can produce a separate notice after the existing backoff.
The new reference covers new items. Unread original work remains in the
inbox, and the original batch reference is readable while retained. A late
read of that reference does not acknowledge its successor. When the original
reference was a verification probe, an explicit read of the new bound notice
can verify the same destination. A paused receiver stays paused.

### Use the local queue for an existing Codex thread

An operator can select the local queue for the original thread on the same OS
account that owns Codex. Check that the original Codex home is on an
owner-controlled, protected path before selecting a Bridge. Use an existing
authorized queue Bridge when available.
Otherwise start a queue Bridge with its own protected state and the original
selected receiver's grants. Keep the App Server Bridge and its existing
configuration, ledger and pending receipts intact. An initialized Bridge pins
its host configuration and rejects an in-place mode edit with
`BRIDGE_BINDING_CHANGED_REQUIRES_REVIEW`.

Set `local_queue_only: true` in the queue Bridge's protected `host`
configuration. Use the exact original thread UUID for both `thread_id` and
`expected_session_id`, and retain the original Codex destination endpoint and
pinned executable, home and UID. The Bridge uses `codex queue` without remote or
resume flags. Select this mode explicitly because the queue can accept input
while the conversation is offline.

Starting with 0.3.49, the original runtime can stay running while the operator
rebinds the existing receiver to the authenticated queue Bridge. Use
`peerwork runtime admin ORIGINAL_ADMIN.json status` to identify the selected
engine and host group. Put the matching `adapter` from the queue Bridge's
`BRIDGE_READY` output in the original runtime's private rebind request. For a
multi-principal Bridge, use the adapter for the exact selected principal.
Keep the same request and operation ID when resuming a pending rebind.

```json
{
  "method": "host_rebind",
  "rebind": {
    "format": "peerwork.host-rebind.v1",
    "operation_id": "UNIQUE_ID_FOR_THIS_REBIND",
    "engine": "ORIGINAL_ENGINE_NAME",
    "host": "ORIGINAL_HOST_GROUP_NAME",
    "adapter": "REPLACE_WITH_SELECTED_BRIDGE_ADAPTER_OBJECT"
  }
}
```

```sh
peerwork runtime call ORIGINAL_ADMIN.json PRIVATE_REBIND_REQUEST.json
```

Use the original configuration and its state. Reserve `initial_subscriptions`
for a first host binding.

Queue submission carries only an opaque notification reference. The bridge
persists the admission before starting Codex and suppresses later submissions
of the same batch, including when the first result is unknown. Check that the
original thread reads a fresh test batch before relying on automatic wake.
A queued receipt confirms submission only.

For `BRIDGE_UNAVAILABLE`, the runtime can relaunch the original same-user Codex
bridge while automatic receiving is enabled. Run the original protected
`peerwork bridge run` command once on this version to record its successful
startup. Recovery uses that exact executable and configuration, is serialized
with bridge startup, and retains the endpoint, thread and pending receipts.
A normal bridge stop disables relaunch until the next explicit start.
Cross-user bridges and bridges configured with an environment-supplied auth
token use their existing host-side supervisor. The error conveys no
information about the current thread owner.

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
| HOST_SESSION_NOT_LOADED | The selected App Server has not loaded the exact saved thread. Confirm the selected route and current owner. For a running standalone thread, check the [local queue](#use-the-local-queue-for-an-existing-codex-thread) prerequisites. If using the App Server route, load the original thread through that host. |
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

For an authorized upgrade, install the verified target Linux executable and
run its selected-client update entry. If the Agent's sandbox denies access or
shows remapped ownership, have the installation's OS user run the preflight on
the original host. Repair permissions only if that check confirms a defect.

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
launcher. `EXTERNAL_ACTION_REQUIRED` delegates the runtime change to that
launcher or supervisor. When the Codex adapter inherits its installation
settings, preserve the active host's `CODEX_HOME`. The returned
`continuation` lists the exact recorded host/project/server
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

## Upgrade a directly launched shared runtime

An operator of an already running shared runtime can explicitly authorize
maintenance replacement from the installed account:

```sh
peerwork connect --local ORIGINAL_REGISTRY --participant HANDLE --update apply \
  --runtime-config ORIGINAL_CONFIG --admin ORIGINAL_ADMIN \
  --rollback-executable ORIGINAL_BINARY
```

Use the original protected configuration and administrator endpoint. The
rollback binary must be a verified installation of the currently running
version. Run this command only for a directly launched runtime whose
operator controls the lifecycle of every affected client. A supervisor-owned
runtime uses the supervisor's update procedure.

Maintenance stop leaves startup intent intact. The updater checks the launch
configuration digest before stopping the original runtime. It verifies the
original engine inventory, waits for the existing writer to release its
state, and starts the selected binary against the same configuration.
Repeat the exact selection after interruption. A definite failure to start
uses the pinned rollback binary. An uncertain startup is reobserved without
starting a competing process. Inspect the running version and reload the
original MCP through its host before verifying automatic delivery.

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
