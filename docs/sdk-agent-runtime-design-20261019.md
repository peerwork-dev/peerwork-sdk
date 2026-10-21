# Peerwork SDK: composable operations and durable Agent communication

Date: 2026-10-19. Status: canonical design proposal; illustrative names, no new implementation or acceptance claim.
This resets the product direction while preserving qualified implementation and evidence. Companion Peerwork product-repository records are `docs/sdk-multiplatform-plan-20261012.md`, `docs/sdk-client-plan-20261012.md`, `analysis/sdk-native-20261012/T194-DESIGN.md` and `analysis/sdk-native-20261012/SDK-COMMUNICATION-RUNTIME-PROPOSAL.md`.
Those records remain evidence/history; this SDK-repository document governs the proposed experience and incremental work below. Companion paths are provenance, not installed-package prerequisites.

The [2026-10-21 operation and offline-testing decisions](unified-operation-recovery-design.md)
refine this direction with immutable operation attempts, version coexistence,
optional ticket conversion and a shared native protocol simulation interface.
They are internal design decisions, not a claim of released capabilities.

## 1. Product purpose and observable value

The SDK removes repeated mechanical work from Agents collaborating through Peerwork.
An Agent should express an authorized intent, obtain exact verified references, and recover or hand off unfinished work using the installed package.
Finding internal source, assembling signatures, choosing state-file paths, reconstructing approval packets, checking arbitrary latest records, or writing polling loops means the corresponding workflow is unfinished.
Wrapping an HTTP route or increasing the number of exported methods does not establish delivery.

The CUDA analogy concerns composable operators: participants combine communication and protocol primitives into locally chosen collaboration patterns.
Peerwork supplies neither a mandatory manager nor a universal task/discussion/business workflow.
Protocols remain independently authored, discoverable and adoptable; publication, verification and adoption stay distinct.
The SDK makes safe composition cheaper than direct API scripting while retaining expressiveness for new protocols.

Track value on representative journeys using retained traces: caller-authored glue, manual signing/state/recovery/polling steps, tool calls needed to locate authoritative inputs, and avoidable inference during waiting.
Compare the same task and authority before/after a change; report time and tooling effort with environment context, not arbitrary success thresholds.
Separate necessary business reasoning and protocol choice from accidental platform work.
Method coverage, route percentages and a successful final record are insufficient product metrics.

## 2. Current evidence and remaining boundary

| Status | Supported statement |
| --- | --- |
| Public artifact | `v0.1.1-experimental.38863120132`, dated 2026-10-16, predates the 2026-10-17 member repair; it does not deliver that repair. |
| Local accepted repair | Native worktree source `1e92357`, runtime `b0bf8ef`, Cargo version `0.1.1`: installed Linux GNU Python/Node/CLI PRIVATE member submit, reconcile, saved retry and pending-operation evidence, within T194/T199/T200 scope. |
| Existing reusable inputs | Rust action/replay/security engine, protected stores and locks; historical client exact-result recovery; product-side notification mechanisms subject to contract mapping. |
| Proposed/incomplete | Unified contexts, complete native browser approval producer, communication runtime, richer diagnostics and cross-platform/distribution parity for this experience. |

Owner-only helpers and historical specialized clients do not establish ordinary member API equivalence.
Generic signed native transport does not establish complete browser approval.
PROD deployment does not qualify SDK usability, public availability or workflow compliance.
Current native `read_latest` resets an inactive generation and fetches/replays from the beginning; paging and rollback floors do not establish incremental sync between polls (`crates/runtime/src/secure_read_profile.rs:229`, `crates/runtime/src/secure_journal_read.rs:174`, `crates/runtime/src/secure_read_access.rs:334`; independent source review, no new runtime test). True incremental/no-change cost is a roadmap item, not a shipped runtime claim.
Existing stable caller operation IDs are qualified for PRIVATE/guarded paths, not universal PUBLIC/platform idempotency.
Reuse previous evidence within its frozen source/artifact/environment scope; keep first failures, PRIVATE depth-2049 compatibility limits and unqualified platform/runtime cases visible in the linked plans.

## 3. Boundaries and a small public model

| Layer | Owns | Does not decide |
| --- | --- | --- |
| Caller / Agent | Intended principal, service, business intent, protocol/source choice, budget, execution and disclosure consent | Signature encoding, receipt verification, recovery transport or polling mechanics |
| Platform runtime | Identity references, protected state, fixed security workflows, exact transport/recovery, verified sync and notification delivery | Business priority, protocol adoption, universal roles or task completion |
| Protocol | Exact source, schemas, permissions, predicates, transitions and reference requirements | Implicit platform authority or automatic execution of received text |
| Service | Authoritative admission/authorization, accepted history and supported transport contracts | Caller intent inferred from possession of a valid key |

Expose one immutable `Context` composed from `Principal`, `Service` and optional `Workspace`; two durable handles are `Operation` and `Consumer`.
A profile is a convenient reference to a context, not an authority or isolation boundary.
The default journey is install → bind → enter/inspect → act → wait/resume. Workspace inspection returns verified state, effective grants, entry protocol and recoverable operations before writes.
Keep a few coherent entrypoints: `open`, `inspect`, `operate`, `operations`, and `events`.
Operations and event handles supply status/recovery and sync/watch/receive/ack behavior; avoid a separate client class or method family for every protocol.
Fixed platform workflow intents may have typed constructors, backed by the same operation lifecycle.

Illustrative equivalent calls, not current signatures:

```python
ctx = peerwork.open(profile="agent-a", expected_actor=actor, expected_service=service)
offer = ctx.inspect(workspace=space, protocol=source_ref, action="reply")
op = ctx.operate(intent={"kind": "protocol.action", "workspace": space,
    "source": source_ref, "instance": instance_ref, "action": "reply",
    "values": values, "refs": exact_refs}, operation_id=stable_id)
result = op.status()       # persisted evidence; use op.recover() after uncertainty
```

Node uses the same intent/result vocabulary with idiomatic async calls; CLI maps JSON intents to `peerwork operate --profile agent-a --expect-actor … --expect-service … --operation-id … --json`.
`peerwork operations inspect|recover …` and `peerwork events sync|watch|receive|ack …` are thin adapters, not alternate lifecycle implementations.
Historical import, raw packet inspection, explicit transport staging and replay tuning belong to an expert namespace with compatibility preserved. Offline help/schema/version require no identity or network; ordinary input is typed values/JSON, never double-encoded signed envelopes.
Installable help and examples describe intent schemas and recovery without requiring checkout, fixture imports or private APIs.
Results use a versioned common schema: `context`, `operation_id`, `intent_digest`, `status`, `evidence`, `refs`, `continuation`, `error`.
References include service/workspace, exact source and instance, object/revision, command and commit/checkpoint identities where applicable; absent evidence stays absent.
Errors carry stable `code`, `layer`, `operation_id`, safe context, effect certainty and structured permitted next actions; language exceptions and CLI exit categories retain this envelope.
CLI stdout is machine data, stderr is diagnostic text; waits and cancellation have bounded, consistent semantics across bindings.

## 4. Context, continuity and safe selection

`open` is noncreating and reversible: resolve and validate existing references locally; do not enroll, generate keys, publish, adopt protocols or change remote state.
Missing identity/history is a typed failure; initialize, import, enroll and context migration are explicit intents.
Use existing signing identity and recipient/device history references, never duplicated PEM files or per-run roots.
One principal can address several services/workspaces; multiple principals can coexist on one host.
Signing-key restoration alone does not restore PRIVATE decryption history; expose the missing history or authorized rekey path.

Service identity includes stable local service ID, audience and receipt trust/continuity policy separately from transport endpoints.
Equal audience/workspace IDs do not merge environments; endpoint changes require explicit verified continuity, never automatic repinning or fallback.
Resolve explicit config/profile, then scoped environment, then OS-user default once; no mutable process-global selected actor.
An Agent launch contract provides expected actor and service. Preflight compares them, selected history, source bindings and workspace before enrollment or business POST.
Display safe selection provenance and public identifiers; a valid but unintended authorized actor is still a selection failure.

Logical storage namespaces are `principal`, `service`, `workspace`, `operation family + ID`, and `consumer + source/filter version`.
Contexts reference identity/history stores; workspace namespaces retain grants, keys, replay floors, caches and operation records; consumers retain their own leases/acks.
Use adapters over existing bound roots first. Maintain atomic writes, file protection, cross-process locks and binding checks.
Workers intentionally sharing a principal share its canonical operation store; separate principals retain separate private stores.
Profiles prevent accidental mixing, not hostile same-UID access; stronger OS/process isolation remains a deployment choice.
Migrate storage explicitly, with recoverable metadata, validated bindings, rollback/read compatibility and preserved operation IDs/bytes; refuse to open a second competing writer.
Pending operations remain inspectable/recoverable in their original service/principal context throughout rollout; never silently relocate, delete or re-sign them.

## 5. Discovery and generic expressiveness

`inspect` returns available protocol manifests, exact source bytes/references/digests, entry instructions, schemas, action/reference requirements and observed capabilities.
Installed/adopted source and catalog candidates are distinct; mutable names are discovery aids, never substitutes for exact execution pins.
Anonymous discovery works without creating an identity. Authenticated readiness uses the selected actor and a reported verified checkpoint.
Expose supported/unsupported/unknown and stale evidence explicitly; local readiness is advisory and the service remains authoritative.
Fetch/extract/validate mechanical inputs and exact history; the caller still selects the protocol, business action and values.
Do not auto-adopt an unknown source or infer semantic intent from a plausible action name.

The same `operate` path accepts dynamic manifest-supported protocol actions and schema-described supported platform intents. A new platform workflow without a complete native producer reports `UNSUPPORTED_PRODUCER`; arbitrary URLs or raw signed commands are not workflow support.
Both reuse selected identity, signed audience, durable intent, encryption, exact refs, transport and result verification.
An extension manifest must declare required runtime/verifier features and effect mapping; unsupported semantics fail visibly rather than being ignored.
A raw advanced transport surface may return lower-level verified evidence, but cannot label an unsupported workflow complete or bypass platform approval/delegation checks.
Escape paths must not require callers to construct signatures or invent state stores; adding a new schema must not require a new business client hierarchy.
Generic resolve → verify → stage → install operators support protocol composition, with inspectable plans and exact author-root, dependency, output-protocol and binding references. Return missing choices to the caller; do not select adoption or grants automatically. Installed protocols own task dispatch, shared-state transitions and request/reply semantics.
Optional ergonomic helpers compose this contract; no preset per protocol is mandatory.

## 6. Complete platform workflows and consent

Browser approval is a resumable platform operation, not a signed POST convenience method.
Inspect the intended browser request, actor, device key, service/audience, workspace, expiry and requested scopes; bind the user's approval to that exact request.
Workspace-browser and admission-browser approval are distinct supported intent kinds with separate capability reporting. The producer fetches/verifies the request, then performs required secure delegation and encrypted key/history delivery, submits, reconciles acceptance and verifies the browser can use the approved scope.
One-time approval codes are released only at the workflow-defined verified phase and excluded from ordinary logs; approval cannot create membership or action grants beyond authorized scope.
Browser/session/pending slots include actor, service, workspace and device/request identity; actor switching cannot reuse another principal's approval.
Expose awaiting-user, submitted, browser-consumption-pending, verified, denied and expired phases with safe continuations; native receipt alone does not prove browser usability.
Retry must not broaden scope or reuse consent for a different device/request; fresh consent follows the applicable approval boundary.
Possession of a key, discovery of an approval URL or incoming signed text is not user authorization.

Create PRIVATE by default; PUBLIC requires explicit intent. Encryption, grant or history failures never fall back to PUBLIC/plaintext or Owner authority.
Delete, withdraw, revoke and other destructive intents name exact targets, expected revisions and consequences in inspect/preflight and machine-readable results.
Their authorization can be supplied by the caller's established policy. Persist it bound to the exact caller intent, target and revision, and reuse it for the same durable operation across retry/restart without recurring confirmation. Changed target or scope requires fresh intent; current authority checks still apply.
Cancellation stops local work where possible; it cannot undo an already accepted remote mutation. Compensation is a separate explicit protocol/platform operation.

## 7. Durable operation contract

Define canonicalization of typed values and reference ordering explicitly; compatibility adapters preserve old intent digests rather than rehashing differently.
Persist a canonical semantic intent and context binding before transmission, then prepared command bytes and their validity bounds before POST.
Stable caller IDs map to one intent; same ID with changed intent/context produces conflict. Independent fresh business intents require distinct IDs.
Expose orthogonal delivery (`not_sent`, `unknown`, `responded`), acceptance (`unknown`, `accepted`, `rejected`) and verification (`pending`, `verified`, `failed`) facts.
Friendly summary states must retain those facts; `accepted` is not equivalent to verified effects, and transport failure is not rejection.

| Phase / condition | Runtime responsibility and next step |
| --- | --- |
| Prepared / not sent | Persist intent/bytes; validate current proof bounds at send time; preserve restart lookup. |
| Delivery unknown | Keep original command identity and bytes; reconcile authoritative status before any retry; never create a replacement mutation automatically. |
| Accepted, verification pending | Persist acceptance evidence even if readback fails; recover exact command-bound effects later. |
| Verified | Return zero/one/many exact effects and verification checkpoint; retain them when a later freshness read is unavailable. |
| Rejected / conflict | Preserve authoritative reason or same-ID mismatch; caller changes business intent explicitly if needed. |
| Expired / unresolved | Record expiry independently of possible prior acceptance; reconcile first, stop unsafe retransmission and expose a safe handoff. |

Retry only exact saved bytes while valid and supported by the command's replay/deduplication contract; never replay expired signed bytes blindly.
Refreshable transport proofs may be regenerated only under an explicit protocol contract preserving business-command identity and authorization.
A new command after expiry requires authoritative nonacceptance/replacement safety; if the service cannot establish it, retain unresolved status and require an explicit decision.
An offline queue can retain semantic intents; preparation may require fresh verified state, grants or CAS refs after reconnection. Changed refs, CAS or signed bytes create a recorded attempt under an explicit safe protocol contract, never silently replace an unresolved attempt.
No “latest object” lookup substitutes for exact result association; zero-effect commands can still be verified successes.
Expose list/inspect/recover for pending operations even when a process dies before printing its operation ID; keep selection/history conflicts distinct from network errors.
Propagate cancellation/deadline through lock waits and I/O; obtain locks before minting expiring proofs and return typed busy with bounded retry guidance.
Diagnose wall-clock skew, RTT, proof expiry and local contention separately without widening cryptographic bounds or trusting arbitrary HTTP Date headers.

## 8. Communication without polling inference

`events.sync` verifies/decrypts incremental sources; `watch` streams updates; a durable `Consumer` provides receive/lease/ack and restart handoff.
The library or packaged CLI owns adaptive polling, pagination, reconnect/backoff, deduplication and checkpoint persistence with no Agent invocation on no-change polls.
Journal, admission and delivery queues have explicit source adapters and independent cursor/authorization coverage; unsupported sources are reported.
Event IDs bind source namespace and authoritative sequence/hash/item version plus deterministic event index.
Offer explicit every-event versus latest-state/coalescing delivery; current snapshots cannot silently substitute for intermediate event history.

Keep verified replay progress, durable inbox enqueue progress and each consumer's acknowledgement separate.
Atomically commit verified progress and notification enqueue, or use a durable replayable write-ahead segment; crash between them must not lose a notification.
Workers with the same consumer ID compete for leases; distinct consumer IDs receive independent deliveries. Cross-principal shared services must preserve isolation and disclose their expanded key-access boundary.
Receive uses a bounded lease; unacked events can redeliver. Ack records consumer acceptance under its declared contract, not protocol task completion.
Task results/closure are explicit protocol actions. Consumer idempotency handles at-least-once delivery; no end-to-end exactly-once execution promise.
Use stable consumer identities and versioned filters; `now`, `resume` and historical replay start modes are explicit.

Multiplex authorized subscriptions and reuse verification/decryption per context; bound queues, memory, concurrency and reconnect bursts.
Backpressure retains recoverable source position, exposes lag and stops unsafe cursor advance; retention gaps require explicit resync/gap reporting.
Reauthorization/expiry/revocation stop unauthorized fetch/decrypt/delivery and report affected queues; already disclosed plaintext cannot be remotely erased.
PRIVATE activity hints remain authorized and opaque; semantic projection happens locally after verification/decryption.
Status includes source coverage, last verified/enqueued/acked positions, backlog, lease state, backoff and last safe error.
Wait completion, deadline/cancel exit or durable handoff must be explicit; printing an event to an unattended terminal is not a completed Agent handoff.

Start in-process or with a packaged foreground CLI loop. An optional local service can share I/O and wake configured consumers without becoming mandatory infrastructure.
Agent adapters obey configured subscriptions, allowed actions and compute budgets; signed incoming content never becomes executable instructions automatically.
Measure idle requests, paging, apply/decrypt cost, backlog recovery, wake rate and resource use at representative subscription counts.
Add authenticated multiplexed push hints/batching when measured limits justify them; lost hints recover through authoritative sync.
Shared local polling alone does not prove fleet scalability, and a central broker or universal scheduler is not a prerequisite.

## 9. Diagnostics, packaging and delivery slices

Capability diagnostics distinguish installed binding/build, runtime/verifier features, service/protocol support and current principal/grant/key readiness at a checkpoint.
Distinguish unsupported producer, unavailable history, pending admission, denied scope, wrong context, stale refs, state busy, transport uncertainty and verification failure.
Emit safe actionable continuations and build/schema identifiers; never require secrets, plaintext PRIVATE bodies or raw tokens in evidence.
Product progress is complete useful journeys; Rust port/build-matrix progress is supporting engineering. Preserve Python-without-Node and standalone CLI promises, but qualify honest cohorts without making an architecture replacement or all-platform rebuild a prerequisite for the first useful loop.
Python, Node and CLI share the Rust lifecycle/core and conformance vectors; idiomatic calling style may differ, semantics must not.
Install/import is inert and needs only the declared runtime for that artifact; no checkout, compiler, hidden subprocess runtime or postinstall download workaround.
Publish exact versions, hashes/provenance, supported targets and per-target installed-workflow evidence; public download availability remains a separate gate from local builds.

| Work package | Bounded finish and acceptance |
| --- | --- |
| A. Contract and existing repair delivery | Map existing member engine into common result/error/operation vocabulary; retain lost-response evidence; qualify/install/publish a clearly scoped candidate through existing release gates. No complete-runtime claim. |
| B. Context adapters and recovery continuity | Existing identity/history references, wrong-actor/service preflight and shared stores work for two principals and one principal/two spaces; interrupted old operations recover across adapter rollout without new effects. |
| C. Complete platform intents | Browser approval from native package through actual browser use; scoped rejection/expiry/restart and explicit destructive intents; member authority never substituted by Owner. |
| D. Generic discovery and composition | Package-only discovery retrieves exact source/schema/refs; caller composes an unfamiliar supported protocol action with the same lifecycle, without handcrafted envelopes. |
| E. Durable communication | Supported-source cross-poll verified delta continuation, measured bounded no-change cost, inbox/leases/ack and packaged polling pass crash, reconnect, duplicate, backpressure/revocation and complete wait/handoff cases. Every-event mode retains multiple intermediate updates; pruning/overwrite reports a gap without advancing/acking missing delivery as complete. No-change polls invoke no Agent. |
| F. Measured scale and platform parity | Profile representative load, optimize demonstrated bottlenecks, and qualify promised Python/Node/CLI targets and optional wake adapters; report uncovered cases explicitly. |

The first complete vertical slice combines the minimum A–E work for one supported host, one PRIVATE protocol and one event source: installed package → bind existing member → verify entry/source → complete browser approval → member-authored action → lose reply/restart/recover exact effect → receive/ack or durably hand off a subsequent event. It must require no checkout, handcrafted envelope, copied PEM, per-run state root or caller polling script. This is a scoped usable loop, not a prerequisite to claim all platform/protocol coverage.
Its acceptance includes wrong-actor preflight before effects, denied scope preserved, same-operation recovery without duplicate effects, actual browser consumption, and a cancelable wait with persisted continuation. The promised incremental/every-event source must prove cross-poll verified delta continuation with measured bounded no-change cost, retain multiple intermediate updates and expose pruning/overwrite gaps without advancing/acking missing delivery as complete. An earlier snapshot-backed slice may claim latest-state/coalescing only, never incremental, every-event or fleet-scale completion. Lower-level installed checks cover all three bindings; natural-Agent evidence separately qualifies the tested binding/cohort.

Each package reuses qualified components and adds focused boundary checks; it does not require a giant rewrite or completion of unrelated speculative features.
Contract/state compatibility is agreed first; B can adapt current roots while A closes distribution. C/D use B and the existing operation engine; E reuses established verification and storage.
Release each honestly scoped slice; keep old clients/readers and pending operations supported through explicit version negotiation and reversible adapters.

## 10. Acceptance, tradeoffs and unresolved choices

Pair repeatable lower-level tests with a frozen natural-Agent installed-package journey; they answer different questions.
The following installed behavioral matrix is required for the promised cohort; each cell means the full journey from its actual package, not an import/help smoke check. Unpromised approval kinds remain explicitly unsupported, not passed.

| Journey and observable boundary | Python wheel | Node package | Native CLI |
| --- | --- | --- | --- |
| Bind existing context; wrong actor/service fails before effects | Required | Required | Required |
| PRIVATE enter; entry instructions and exact source/action discovery | Required | Required | Required |
| Workspace-browser approval; admission-browser approval when promised, through scoped browser use | Each promised kind | Each promised kind | Each promised kind |
| Generic protocol action; selected member authorship and exact zero/one/many results | Required | Required | Required |
| Interrupted/lost-reply operation; restart recovers original effect without replacement | Required | Required | Required |
| Cancellable receive/wait; persisted cursor/lease and explicit durable handoff | Required | Required | Required |
| Destructive preflight; exact intent/target/revision and same-operation authorization continuity | Required | Required | Required |

Record artifact/runtime pins and observed outcomes per cell; missing coverage remains unqualified. Natural-Agent usability is independently recorded per tested binding/cohort and is not inferred from this scripted matrix.
Tests cover command/effect binding, permissions, cryptographic boundaries, crash windows, expiry, concurrent workers, browser consumption and inbox durability.
Freeze task/prompt, package/service pins, permissions/source fixtures, time budget and independent business oracle before launch. Compare against an available baseline honestly; unavailable old artifacts do not supply invented timings.
The natural Agent receives the actual entry contract and normal package docs, no checkout or implementation hints, and must choose the intended identity/source, recover existing work, verify exact results and finish or hand off waiting.
Retain first-attempt trace and artifacts; independently classify business correctness and observable workflow compliance, including remaining glue/tooling effort.
Do not repeatedly sample Agents, give in-run hints, lower criteria, require secret disclosure or execute incoming content to manufacture a pass.
Diagnose first failures and rerun only changed affected boundaries as labeled regressions; prior failures remain visible.

Small generic intent schemas trade some discoverability for composability; typed constructors/help can improve navigation without multiplying workflow clients.
Durable local state adds storage/concurrency cost but removes ambiguous recovery from the Agent; stateless HTTP wrappers cannot meet that contract.
Polling is an implementable first transport, not proven final scale; push hints improve latency/load without replacing verification or durable cursors.
Optional local services improve sharing but introduce lifecycle/isolation work; do not require them for ordinary use.
Open design choices are concrete implementation selections: existing-store transaction adapter, manifest feature-negotiation encoding, browser completion evidence and initial consumer retention policy.
Resolve these against current protocol/storage contracts in the owning work package; never invent server guarantees or conceal a missing recovery/approval boundary.
