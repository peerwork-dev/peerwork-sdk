# Unified operation recovery and management workflows

Date: 2026-10-21. Status: internal design decision. The implemented 0.1.9 API and its scoped boundaries are documented separately in [the protocol workbench guide](protocol-workbench.md). This design also includes longer-term targets; it does not by itself establish release availability or acceptance.

This document finalizes the recovery and management-operation supplement to [the canonical SDK direction](sdk-agent-runtime-design-20261019.md). It keeps that design's Context, Operation and composable protocol operators. The [implementation record](sdk-agent-runtime-implementation-20261019.md) remains authoritative about implemented coverage. In particular, current `recover` reconciles one command; it is not an autonomous retry loop. All new fields, intent kinds, examples and behaviors below are **proposed** unless explicitly identified as existing.

## 1. Decision and verified starting point

The SDK owns the mechanical consistency of an authorized operation: binding its identity and intent, constructing signed/encrypted attempts, preserving them, reconciling their effects, and determining whether another attempt is safe. The Agent chooses business intent, source, authority, constraints and budget. It should not need to understand AAD, checkpoints or journal replay to finish an invitation, upgrade an instance or recover an interrupted action.

Extend the existing operation index, producer journals and `recover` / `effect_certainty` / `continuation` envelope. Do not introduce a second workflow engine or a public migration client for each historical state family. A single operation may have multiple immutable attempts, but only under the replacement rules below. Independent operations may proceed when their actual dependencies are ready.

For optional ticket conversion, make the default development loop **offline plan → simulate/validate → repair locally → online revalidate → apply/recover**. Users must be able to find and fix field mappings, predicates and transition-order mistakes without repeatedly submitting to a service. Immutable protocol versions coexist without converting existing tickets; conversion is an explicit user choice.

Source review at native SDK HEAD `841262f` established these starting points:

* `crates/runtime/src/agent_operations.rs` binds a local operation ID to an intent digest, currently for `protocol.action` and `browser.approve`. Its comment correctly states that the index does not establish acceptance; producer journals do.
* `crates/core/src/prepared_public_admission.rs::prepare_delivery` preserves the policy's guard-time setting but does not add guard time to the finalize commit context. PRIVATE admission encrypts against this context before signing. Adding a field after encryption would break its AAD binding.
* `crates/runtime/src/secure_public_admission.rs` journals exact delivery bytes but reduces non-2xx responses to `ServerRejected(u16)`. The original response may be retained locally; the public classification loses its cause.
* Product `src/workspace-secure-store.ts::validateCommit` requires guard-time context on every commit under an enabled policy, including `secure.invite.finalize`. The guard-time policy is immutable after activation. `append` has command-ID deduplication before head validation, with matching command/commit/request bindings and current authorization checks. This is not logical-operation deduplication across newly signed commands.
* [Owner migration](owner-migration.md) already supports workspace projection in 0.1.7; it still refuses nonempty legacy SQLite `client_operations`. [Member credential import](legacy-member-keys.md) in 0.1.8 imports credentials, not all historical pending operations. Neither boundary should be represented as an invalid identity or a requirement to reinstall a business protocol.

## 2. Safety invariants and non-goals

1. One operation ID names one immutable, canonical business intent in a pinned service/principal/workspace namespace. Changed business values, recipients, scopes, source versions or caller-required revisions require a new intent and ID. Persist the canonicalization version; upgrades must not reinterpret existing digests.
2. An attempt is immutable: exact request bytes, command identity, signatures, encryption nonces, policy/source bindings and validity bounds. Exact retransmission and construction of a successor are different actions. No in-place patching of signed packets.
3. Persist intent and attempt before network submission. Record submission-start durably before handing bytes to transport. After a crash at that boundary, uncertainty is conservative even if no actual bytes left the process.
4. Neither an HTTP status, a timeout, cancellation, an empty new profile nor a missing record proves that no effect occurred. An accepted response is not verified business completion. Historical acceptance and the current validity of its effects are separate facts.
5. Every prior attempt must be accounted for before creating a successor that could duplicate its effect. If acceptance remains possible, stop replacement and return a bounded recovery continuation. An operator's willingness to retry does not manufacture nonacceptance evidence.
6. Do not broaden authority, adopt another protocol version, switch identities, downgrade encryption, bypass entry rules or renew business consent to make recovery succeed. Changed authority is checked again before any network write.
7. Keep unresolved legacy work and its provenance. Retirement is local bookkeeping, not remote cancellation, confirmed rejection or proof that replacement is safe.
8. Persist verified results before exposing them. Preserve exact effect references and relevant evidence across restart; later freshness failures must not erase an already verified result.

Non-goals: universal exactly-once delivery, a centralized task system, automatic resolution of business conflicts, restoring missing recipient keys from signing keys, unrestricted source-independent migration of unknown legacy formats, and making every platform producer use the new path before fixing invitation finalize. Public protocol publication, local identity attachment, enrollment and authorization remain distinct actions.

## 3. Durable model and evidence

An operation record contains the existing context binding and immutable intent plus its canonicalization version, producer kind, ordered attempt references, current revision, authorized recovery policy, and verified result references. Keep secrets and semantic intent in the protected local store; they are not telemetry. An attempt record contains its command ID, exact request digest and bytes, preparation inputs, validity bounds, transport observations, and verified acceptance or closure evidence. Existing producer journals remain authoritative for packet and acceptance evidence; the common index locates them.

Use an atomic operation-record update and a documented lock order around binding, reservation, attempt persistence and index linkage. A producer journal may be committed before its index link: startup must deterministically repair that orphan by verified IDs/digests, never prepare a second packet. A dangling reservation is recoverable. Migrate journal schemas with versioned readers and a durable upgrade marker. Hold a canonical-store lock for each operation through selection/submission; use revision compare-and-swap for any lock release during long work. Recheck revision before sending. Never reuse an expired worker lease as a local write lock.

Keep orthogonal facts rather than one overloaded status:

| Dimension | Values and meaning |
| --- | --- |
| Delivery | `not_sent`, `unknown`, `responded`; a response does not resolve earlier transmissions. |
| Acceptance | `unknown`, `accepted`, `rejected`; rejection is scoped to the attempt and its evidence, not inferred from an arbitrary response. |
| Verification | `pending`, `verified`, `failed`; accepted but unverifiable stays accepted with incomplete/failed verification. |
| Future acceptance | `possible`, `closed`, `unknown`; closure evidence explains why a late copy cannot newly apply. |
| Business outcome | `pending`, `completed`, `conflict`, `hold`, `cancelled_locally`; local cancellation does not change acceptance. |

The friendly status is a projection of these facts. A protocol predicate failure is a business conflict; an admission rejection is not automatically one. A locally invalid packet may be certainly unsendable while earlier attempts remain unknown. Report certainty at both attempt and whole-operation level. Preserve existing `effect_certainty` values; add richer evidence in a versioned extension rather than redefining `not_sent` to mean “rejected.” Unknown legacy errors remain `unknown` until classified from evidence.

Recovery decisions are deterministic:

| Evidence | SDK action |
| --- | --- |
| Exact accepted command and verified history/effects | Persist and return the existing result. Never submit a successor. |
| Acceptance observed, verification incomplete | Fetch/verify missing evidence; do not repeat the business effect. |
| Current response rejects this submission, prior acceptance unresolved | Preserve response; reconcile prior transmissions. Do not call the operation rejected or regenerate it yet. |
| No attempt could have been sent, established by durable transport ownership | Revalidate original intent and prepare/send within its authorization. |
| All attempts have verified nonacceptance and future-closure evidence | Revalidate original intent and possibly create a successor under the rules below. |
| Business precondition no longer holds | Return `conflict` or protocol-defined `hold` with exact safe refs. Caller decides a different business intent. |
| Unknown, expired, inaccessible or incomplete history | Bounded reconciliation, then return `pending` with continuation and reason. No unsafe replacement. |

Evidence is authenticated and bound to service, workspace, actor, command/request digest and history lineage. A bare 404, 409, “not found,” log line or local wall-clock expiry is not closure. Verify all earlier attempts, not only the most recent one. If recovery excluded a formerly accepted commit, retain its acceptance history and require the recovery protocol's explicit replacement semantics; do not silently label it never submitted.

## 4. Replacement, late packets and deduplication boundaries

The first implementation supports three narrowly defined successor cases:

1. **Never submitted.** The durable attempt is still pre-submission, with exclusive store ownership and no other process or exported packet capable of submitting it. Mark it superseded atomically before preparing its successor. If packet custody cannot be established, use the unknown path.
2. **Permanently inadmissible bytes plus reconciled history.** A producer-specific verifier establishes that these exact bytes could not have been accepted under the pinned protocol/policy and can never become valid; otherwise it separately verifies complete nonacceptance through a trusted closure frontier. This permits repairing a malformed finalize packet, but does not assume that any `SECURE_GUARD_TIME_REQUIRED` response proves every earlier transmission failed. Persist the precise policy, packet and proof used by the verifier.
3. **Closed predecessor frontier.** A producer-specific verifier proves from complete authenticated history that the attempt is absent and its source head/sequence can no longer be accepted. This optimization is disabled unless the exact service/recovery contract guarantees that the predecessor cannot become admissible again. A current head mismatch alone is insufficient: recovery, rebranching and service restoration must be considered. A signed time frontier after expiry may be usable only if its contract guarantees nondecreasing admission time and complete acceptance coverage; local time or an unattached time token does not suffice.

Successor preparation refreshes mechanical envelope inputs only: verified checkpoint, permitted policy context, time window and encryption. It re-evaluates the original selected source, recipients, scopes, business predicates and caller-pinned revisions. Updating a checkpoint is not permission to overwrite a caller's stale expected business revision. A plan that needs a new source/version, changed scope or different business outcome returns a conflict/new-intent requirement.

The old packet and closure proof remain available for audit and restart. A successor gets a new attempt/command ID and references its predecessor locally. Any permissible refresh of a transport read proof must leave business request bytes and authorization unchanged. Bound retries by deadline, attempt count and backoff; budget exhaustion returns continuation rather than losing work.

**Current guarantee:** within one canonical, protected operation store and a qualified producer/service contract, the SDK prevents unsafe duplicate attempts and reuses verified results. Existing exact-command idempotency supports retransmitting matching bytes; it does not authorize new command IDs. Two profiles with independent stores, copied state, or different machines do not share a logical operation index. Equal caller IDs across those stores do not imply remote deduplication. Shared-principal workers must resolve to one canonical store or a qualified explicit handoff that fences the old writer. Local locks cannot recall in-flight requests.

**Conditional future service increment:** if a required workflow cannot establish predecessor closure with existing signed history, add a narrowly scoped operation receipt/fencing capability. Use a random opaque operation token bound into signed attempts and scoped to workspace and principal; do not expose low-entropy business-intent hashes. The server must atomically check accepted-operation identity and attempt generation, append the effect, and retain its command-bound result. An atomic fence transaction must order against append: if the old attempt committed first, return its existing result; if the fence wins, reject all older generations. Signed/authenticated responses must bind the fence generation and effect evidence. Retention, tombstones, backup/restore epochs and protocol-version compatibility must prevent resurrection; token expiry cannot authorize repeating an unresolved effect. A “status endpoint” without this ordering and retention contract is insufficient.

This capability would permit safe replacement across specified distributed workers; it does not promise exactly-once arbitrary external side effects or business equivalence between different operation tokens. It is not required for the P0 finalize correction. If unavailable, return `REPLACEMENT_SAFETY_UNPROVEN`, preserve the operation, and explain the blocked step. Do not expand the service merely to avoid an honest pending state.

## 5. Common submission context and producer coverage

Implement a shared, typed preparation pipeline, incrementally extracted from qualified paths:

1. Bind context and logical intent; inspect capabilities for the exact producer/version/visibility.
2. Obtain verified policy, authenticated replay/checkpoint, key epoch, source and required grants. Inspect dependencies without migrating unrelated workspaces.
3. Validate producer-specific authorization, business preconditions, invitation/acceptance evidence or other fixed workflow constraints.
4. Compute the complete commit context: wire/format/structure versions, source head/sequence, resulting policy hash, actor/delegation, command identity, action/instance, epoch and guard-time bounds. Use the service's existing trusted-time contract and verifier; a local timestamp is not trusted admission evidence. Activation retains its specially specified context and bounds.
5. Freeze context; derive canonical AAD; encrypt; assemble and sign all bound artifacts. Policy-changing delivery may need the next policy and grant hash before final commit construction. Treat its policy, grants and commit as one prepared bundle with explicit dependencies, not separate independently refreshable packets.
6. Locally verify the entire prepared bundle using the same rule set as replay, including time context and PRIVATE AAD. Persist exact bytes before POST.
7. Submit with producer-specific transport/idempotency adapter; preserve bounded structured response observations; reconcile and verify exact effects and any service time attestation; persist evidence.

Guard-time coverage does not impose a short deadline on every ADMIN operation. The existing core `GuardTimeContextV1::universal()` and service context validator allow `{v:1, lower_ms:0, upper_ms:9007199254740991}`. A time-independent administrative producer may use this existing wide domain after verifying that its semantics and authorization rules do not require a tighter bound. Business time predicates derive the necessary narrower window; invitation expiry, certificate validity and current authorization remain independently enforced. Do not invent a universal 30-second timeout, copy browser/request wall-clock time into trusted platform time, or add unsupported time fields. Guard context always precedes AAD/signature construction, regardless of its width.

The helper must not take an arbitrary caller-built context map as an escape hatch. Producers supply typed semantic additions; the helper rejects missing or conflicting mandatory fields. No post-signing/AEAD “patch guard_time” function.

For an `ALL_COMMITS` policy, maintain an explicit capability matrix. A successful ordinary action does not qualify activation for a workspace's administration and recovery workflows.

| Producer family | P0 treatment | Later integration / enablement rule |
| --- | --- | --- |
| PRIVATE ordinary and timed protocol actions, including claim/renew/release | Reuse qualified path as reference; regress exact retry, conflict and timing. | Move common context assembly behind helper without changing bytes unintentionally. |
| PRIVATE invitation finalize | Fix complete context before encryption/signing; add local verification, structured rejection, durable operation linkage and recovery classification. | First new management intent under common `operate` / `recover`. |
| PUBLIC admission/finalize | Preserve existing behavior and test no guard-time leakage. | PRIVATE guard-time capability does not imply PUBLIC guard time. |
| Guard-time activation | Preserve dedicated activation rules; add producer-coverage preflight. | Activation must also qualify maintenance/recovery paths needed afterward. |
| Browser approval | Regression only for already qualified combinations. | Delegation and key delivery require explicit matrix entries; ordinary action support is insufficient. |
| Direct/delegated key grants, membership changes, revoke/rotate | Inventory and report each variant; no assumed support. | Adapt and qualify each path required for an enabled workspace's lifecycle. |
| Package/object install, protocol/instance upgrade, coordination/field/structure transitions | Inventory exact supported modes; block unqualified guarded variants. | Adapt distinct bundles and their verification, including interrupted transitions. |
| Workspace recovery, conversion and format transition | Preserve existing contracts and limitations. | Treat recovery as a critical capability; do not infer safe frontier closure or rollback support. |
| Non-commit directory/enrollment/offer/decision requests | Explicitly record “no workspace commit” and their own recovery contract. | Any downstream commit they trigger still requires qualification. |

Capability entries include SDK artifact/version, service feature version, producer/action, visibility/policy mode, prepare/send/reconcile/replacement support and evidence reference. `unknown` is not `supported`. SDK and service discovery both contribute; neither substitutes for end-to-end qualification.

P0 ships the targeted fix without claiming universal producer coverage. New activation must refuse if any required writer, maintenance or recovery producer is unsupported/unknown. The declared workflow set cannot omit revocation/recovery just to pass preflight. Unsupported optional flows remain visibly disabled. On an already enabled workspace, the SDK refuses an unsupported producer before constructing a packet, while supported independent operations remain usable. SDK checks cannot constrain arbitrary old external clients: operator rollout must qualify all active writers, and service validation remains authoritative.

## 6. One public lifecycle in Python, Node and CLI

Retain `inspect`, `operate`, `operations` and `recover`; add platform intent schemas to the existing producer registry. Do not expose packet-generation decisions as Agent responsibilities. P0 recovery is one bounded pass. A later opt-in bounded driver may perform safe retries and replacements according to the same state machine; default `recover` must not silently acquire broader mutation behavior.

Proposed equivalent examples (not signatures shipped in 0.1.8):

```python
plan = ctx.inspect(workspace_id=space, intent=intent)
result = ctx.operate(workspace_id=space, operation_id=stable_id,
                     intent=intent, expected_plan=plan["plan_ref"])
result = ctx.recover(workspace_id=space, operation_id=stable_id,
                     recovery={"mode": "safe", "deadline_ms": 10000,
                               "max_submissions": 1})
```

```javascript
const plan = await ctx.inspect({workspaceId: space, intent});
const result = await ctx.operate({workspaceId: space, operationId: stableId,
  intent, expectedPlan: plan.planRef});
const recovered = await ctx.recover({workspaceId: space, operationId: stableId,
  recovery: {mode: "safe", deadlineMs: 10000, maxSubmissions: 1}});
```

```sh
# Proposed additions to existing context commands; JSON request files are protected.
peerwork context inspect --profile CONTEXT --input INSPECT.json
peerwork context operate --profile CONTEXT --input OPERATION.json
peerwork context recover --profile CONTEXT --input RECOVERY.json
```

All bindings normalize to one native request schema and preserve the same versioned result/error envelope. CLI request keys use snake_case; Node adapters translate only naming, never recovery decisions. Existing read-only reconciliation remains available with no submission budget. An absent recovery option keeps the current reconcile-only behavior. Persisted authorization to carry out the original intent can authorize safe mechanics; changed business intent still requires a new caller decision. A plan is a pinned reviewable preflight snapshot, not a reservation, new authority or guarantee that state will remain unchanged.

An operation handle exposes original intent summary, attempts, acceptance/verification/closure facts, exact effects and continuation. `operations` must state whether it lists unresolved work or complete history; do not silently reinterpret today's unresolved-only listing as an audit log. Legacy `command_id` selection remains available, with exactly one selector; callers need not synthesize a missing historical operation ID.

Continuation contains a bound operation reference, expected revision and a named permitted action, not executable code or arbitrary URLs. Recovery rechecks bindings even when the caller supplies a valid continuation. Cancellation ends waiting/submission work where possible; it preserves pending records and returns whether delivery may already have occurred.

## 7. Business decomposition: claim, review and promotion

Implement this as an example composable protocol, not an SDK-wide mandated workflow:

* **Claim** is a resource/slot state machine: one current claimant, expiry, renewal, release and authorized Master revocation. Each acquisition after release/expiry/revocation increments a monotonic generation. Renewal is conditional on the current holder and generation and cannot revive an expired/revoked lease. Release/revoke is also conditional; stale holders cannot clear a later claim. A successful renew may advance the record revision while retaining its acquisition generation.
* **Delivery review** references the claim generation and exact submitted artifact/revision. Review can be `HOLD`, accepted or rejected under that protocol's rules. Holding one delivery does not globally block claims that do not depend on it.
* **Promotion** references an accepted delivery and the exact promotion target/version. Its `HOLD` does not globally disable independent claiming or review. Master is an explicit protocol role with scoped authority, not an inferred universal SDK administrator.

Expiry and renewal use verified admission time and protocol boundaries, not a worker's wall clock. Claim contention uses an atomic authoritative append/CAS boundary and deterministic protocol validation. Every operation that spends lease authority binds the holder and generation and is checked at commit, not merely when work begins. Racing reclaim/revoke and late delivery must have a deterministic winner; old-generation output cannot overwrite current work. A protocol may preserve it as a separately attributed contribution without treating it as current-holder delivery.

PRIVATE business predicates are evaluated in the authenticated decrypted protocol runtime; the service must not be assumed to inspect plaintext. Qualification must establish which existing admission/structure constraints actually prevent stale acceptance, and which only make an invalid commit fail verified replay. If adversarial stale writers must be rejected at admission and current opaque-commit rules cannot enforce the generation, that guarantee needs an explicitly negotiated privacy-reviewed fencing/validation capability. Client cooperation alone is not server fencing. Do not claim adversarial enforcement before that boundary is proven.

Local operation locks, server attempt generations and business claim generations solve different problems. Reuse no one counter as proof of all three. Recovery may refresh envelope state, but it cannot replace generation 4 with generation 5 or renew the lease as an incidental retry. Those are separately authorized protocol actions.

## 8. Migration, authorization and upgrade boundaries

Track readiness by dependency, not one “migration complete” flag:

| Domain | Owned evidence and boundary |
| --- | --- |
| Principal identity | Signing identity pins and explicit import/continuity. No implicit replacement key. |
| Recipient credentials | Current/historical recipient keys and certificates; does not imply membership, grants or pending recovery. |
| Workspace read state | Verified grants, replay floors, history/checkpoints and cache lineage. Rebuild only reconstructible caches, never identity, keys, unresolved journals or anti-rollback floors. |
| Historical operations | Exact legacy packets, intent associations, responses and unresolved markers. Classify separately from credentials and unrelated workspace readiness. |
| Business protocol | Immutable exact source versions and version-pinned instances; explicit conversion only when requested. Publication of a new version does not migrate tickets or identity. |
| Authorization lifecycle | Offer, accept, grant/finalize, scope changes, expiry, revocation and rotation. Each has its own operation and evidence. |

Read/import plans expose missing dependencies at the affected operation/workspace boundary. Supported workspace projection remains usable; do not regress to global all-workspaces migration. Shared identity uncertainty or an unscoped legacy packet can still be a genuine broader blocker. Explain the concrete overlap rather than treating every historical record as a global prerequisite.

Legacy pending migration is an incremental adapter, not deletion: inspect a quiescent pinned source; classify attributable accepted work from verified evidence; transfer supported exact pending attempts with their original IDs/bytes under a fenced writer handoff; retain packetless intent markers as unresolved; preserve unsupported opaque families with source digest/location and an explicit original-runtime continuation. Nonempty SQLite intents require a dedicated format adapter before they can be imported, not an empty replacement database. Until implemented, retain the documented refusal for the affected import. Credential-only import remains useful but must report unreviewed legacy operations; a fresh pending list proves nothing about the old store.

Retirement requires an explicit exact-record decision and preserves the original marker and evidence. It does not permit automatic recreation of the effect. Keeping an old runtime as the only recovery path also means keeping its qualified environment/artifact reference and the protected source; “upgrade complete” must disclose that dependency.

A normal protocol release uses **version coexistence with zero ticket migration**. Product `src/workspace-protocol-install-plan.ts` binds an instance to `protocol_digest` and rejects a conflicting digest for that instance. Install v2 in a distinct instance in the same workspace; route new tickets there, while old tickets continue in the v1 instance with its exact source. Do not claim arbitrary mixed schemas in one instance, silently reinterpret old history, or require a per-ticket manifest feature to support coexistence. Cross-version claiming/delivery links require explicit supported interfaces and exact references, not forced conversion of old tickets.

A normal version-release plan distinguishes these stages:

1. **Compatibility inspection:** exact source/runtime/format requirements, current instance version and authorization; show supported/unsupported/unknown and affected pending operations.
2. **Verification:** validate schema, predicates and exact artifacts using qualified local inputs; verify optional conversions only when requested. Publication does not enable/adopt anything.
3. **Canary:** install v2 in an isolated or explicitly selected new instance with generated/sanitized data, test the intended flows and recovery. It does not grant authority to production participants.
4. **Enable/adopt:** pin the validated plan and new instance/digest, persist and recover installation, then route new tickets there. Existing v1 instances and tickets continue. Routing changes are explicit and must not rewrite existing ticket bindings.
5. **Recovery:** reconcile uncertain installation first. If v2 is unsuitable, route future work back to a qualified instance; retain and handle any tickets already created in v2 under v2. This is not a rollback of their history.

Old-ticket conversion is optional and separately authorized. Changes to shared state/policy or storage/wire format may also need their own migration, but are not prerequisites for publishing v2. A transformation that destroys information cannot advertise lossless rollback.

### Fastest present route for an explicitly requested v1-to-v2 ticket conversion

Use a small script over the existing SDK's qualified read and protocol-action APIs, with an explicit mapping for these two manifests. This does not depend on the entire unified-management implementation or a new server transfer primitive. There is no claimed universal `migrate` API or supported direct rewrite of an instance's digest.

1. Inspect both exact manifests, grants and the selected v1 ticket revision. Produce a concrete field/status mapping and identify the v2 create/import action plus v1 release/revoke/close actions. If v2 cannot represent required data and source provenance through an existing action, add the smallest explicit business import/conversion action and publish that version first; the SDK cannot bypass its manifest.
2. Persist a conversion record containing exact source instance/record/revision, target instance/digest, approved mapping, stable child operation IDs and progress. Prefer a v2 uniqueness constraint on the exact source reference (and a declared conversion purpose if repeats are intended). A local ID alone does not deduplicate unrelated scripts/profiles. Reconcile every uncertain child before advancing or creating another target.
3. Create a **non-active** target record carrying the source reference when the v2 protocol supports staging; read it back and verify the mapping. Do not copy active authority or an old lease token. Before any new active v2 claim, legally release/revoke the v1 claim, or establish an explicit enforceable pause of old execution authority, and verify the result. If staging is unavailable, release/pause first and then create the target. When neither protocol can stop old authority safely, conversion cannot promise an exclusive active handoff.
4. Activate the v2 ticket/claim only after old authority is closed, using v2's own grants, generation and expiry. Verify the target and then close/link the old ticket if its protocol supports that transition. Preserve the original history; unavailable close/link actions are a visible limitation, not grounds to edit storage directly.
5. Resume from the saved phase after interruption. Across instances this is normally non-atomic: there may be a gap with neither claim active, and already-running external work may not be retractable. Do not promise zero duplicate work. If target creation/activation fails after release, retain an explicit pending conversion; any v1 reacquisition is a separately checked protocol action, not silent rollback.

The conversion writes are attributed to their real signer. Original author/creation time may be retained as provenance metadata; they must not become forged signatures or a false native creation history. For a one-off conversion, the script and exact mapping are the shortest deliverable. Run its mapping and transition tests locally as specified next. An eventual atomic transfer primitive is optional follow-up work, not required infrastructure.

### Offline conversion workbench: the primary design increment

Expose a general offline protocol-test operator, not a conversion-only simulator. It accepts one or more exact protocols, a fixture and a sequence of semantic actions. Ordinary claim/renew/release tests use one protocol; conversion tests compose the old and new protocols with an explicit mapping. Both use the same engine adapter, diagnostics and fixture format. A new protocol can start with synthetic fixtures without any workspace access. Existing-ticket tests need one explicit verified read/export of the selected state and its dependencies; subsequent edits and simulation runs remain offline. Existing SDK protected stores are not automatically a complete simulation fixture, and exporting one never includes private signing or recipient keys.

Separate a pure planner from the effectful executor. The planner accepts a protected snapshot, exact v1/v2 manifests and dependency closure, explicit mapping and a simulation environment. It returns proposed protocol actions, projected records/state and structured diagnostics. It performs no network access, signing with live credentials, durable business submission or implicit import. A conversion script may use general-purpose code for its mapping, but that code runs explicitly under the caller's local authority; the SDK must not execute arbitrary downloaded mapping code from a plan.

The local test harness must reuse the real core's canonicalization, manifest/schema checks, action interpreter, input/reference resolution, predicates, structure checks and resource limits. Do not implement a permissive second interpreter in Python or JavaScript. Source review identifies reusable internals in `full_manifest.rs`, `interpreter.rs`, action-state validation and the public Rust `validate_prepared_action_operation` in `prepared_secure_action.rs`. The interpreter/manifest interfaces are currently crate-private, and the prepared-action validator expects authenticated prior objects and context; it is not already a user-facing pure conversion API. SDK 0.1.8 has no unified offline conversion/simulation interface. Add a narrow native adapter and thin Python/Node/CLI bindings; keep production authority validation separate from the simulation entry point.

Use two explicit fixture modes: a minimal protected export from a verified local workspace read, carrying its checkpoint and provenance, or generated synthetic data marked `synthetic`. Include the transitive records/state/schema dependencies needed by the chosen actions. If a global predicate needs more state, export that dependency or report `INCOMPLETE_FIXTURE`; do not interpret an absent row as proof of absence. Never export production private keys or require a full repository/database copy. PRIVATE plaintext fixtures remain in a private local directory and are never uploaded by the workbench. Fixture retention is a caller-controlled local choice.

Simulation injects explicit actor/role/capability assumptions, deterministic IDs and time, including boundary values before/at/after expiry. These are **fixture facts**, not real service attestations or present authorization. If testing cryptographic construction requires identities/signatures, use generated fixture keys and a clearly separate simulation service identity; no simulated attestation is accepted by the online executor. Semantic tests can run without those keys. Record which checks passed, failed or could not be established; “offline valid” is not “authorized to commit.”

Return a distinct `SimulationResult` with `simulated: true`, fixture provenance, assumptions and predicted effects. It cannot be converted to a production verified-acceptance result, receipt or accepted `effect_certainty`. The trusted Rust preparation/validation composition APIs are implementation reuse points, not language-level final-outcome verifiers for arbitrary caller-supplied state. Keep deterministic test nonce/clock/key injection outside the production signer path; a plan may carry predictions but never minted acceptance proof.

A versioned plan contains source/target instance and exact manifest digests, source record/revision and relevant state/dependency digests, mapping identity/digest, proposed target data, required authority, source release/close steps, stable child operation IDs and dependency order, expiry/freshness conditions, predicted effects, offline report and engine version. Hash the canonical plan; a mapping or material output change creates a new plan revision. The plan contains semantic actions, not long-lived pre-signed packets. A protected snapshot and plan make failed cases locally reproducible.

Proposed coherent front door: `inspect` can produce an offline plan; a local `simulate(plan, fixture)` operator returns diagnostics without opening a network transport; normal `operate` applies the reviewed plan through the same durable operations. Python/Node use the same native adapter and CLI exposes a matching offline command. Naming is provisional; one planner/evaluator/executor contract is required. This is not a separate migration service or daemon.

Before online apply, fetch and verify fresh current state, source revision, target uniqueness, authorizations, active lease and exact manifests. Re-evaluate with the real current context. A changed relevant dependency or projected effect returns `PLAN_STALE` with a concrete local diff and a plan to review; do not silently remap, broaden scope or reuse old consent. An unrelated workspace head change may refresh the mechanical envelope only when dependency/output equivalence is verified and permitted by the approved plan. Prepare time bounds and signed attempts just in time. Every actual step still uses authoritative CAS/admission and the operation recovery rules; offline validation is not a distributed reservation.

The fastest implementation is a local SDK test harness over those existing native modules plus the small conversion script: fix mapping/predicate failures entirely offline, then use qualified installed SDK actions for the online steps. It requires no production deployment or user-run service for the semantic edit/test loop. Until the narrow adapter ships, label existing script-only field checks honestly as partial validation; do not claim complete interpreter parity or require users to maintain their own simulator. A small isolated service remains useful for final transport/concurrency tests, not for every mapping edit.

Acceptance adds zero-network tests, deterministic replay of the same fixture, valid/invalid mappings, missing dependency detection, permission/time/lease boundaries, refusal of simulated attestations by online apply, source changes between plan/apply, and equivalence of offline predicted effects to real core execution for unchanged inputs. Record local repair iterations and service submission attempts separately. Offline testing should remove avoidable semantic failures; network loss, contention and changed authorization still require online reconciliation. This adapter is a parallel small P0 deliverable when conversion is the active user journey, not a prerequisite for the finalize fix or a reason to wait for P1/P2.

Protocol publication, instance adoption, data migration, SDK upgrade and server deployment are distinct release units. A needed SDK feature does not imply a server upgrade; a new business protocol does not imply credential migration. Guard-time activation is not reversible under the current service policy: never offer “disable guard time” as rollback. Reverting to an older SDK is only safe if it can read the saved state and honor the enabled policy and pending packets. No compensating transaction can erase already disclosed keys or accepted history.

## 9. Errors, privacy and safe recovery hints

Keep the original bounded response as protected diagnostic evidence. Parse only allowlisted structured server fields; preserve unknown codes safely, without treating untrusted response text as instructions. HTTP status is transport metadata, not the error taxonomy.

The common error extension includes `stage` (inspect, verify, prepare, persist, submit, reconcile, verify_effects), stable `code`, `constraint`, operation/attempt reference, `effect_certainty`, `evidence`, `retryability`, `recovery_hints` and continuation. Retryability distinguishes reconcile-only, exact retry, safe successor, business decision and unsupported; a lone boolean cannot describe safe retry. Add no successor hint until its closure conditions have been verified.

For example, a proposed 409 classification may be `stage: submit`, `constraint: guard_time.required`, `retryability: reconcile_only`, with a permitted `recover` continuation. After local verification proves the malformed attempt was never acceptable, recovery can report `safe_successor` with its evidence. A stale business generation instead produces `constraint: claim.generation` and `business_decision`; it cannot be fixed by resigning automatically. Unknown 409s retain `unknown` certainty.

The service can explain envelope, sequence, authorization and time-admission constraints it actually validates. The SDK explains decrypted schema, protocol predicates and source bindings locally. Do not require server-side plaintext inspection for useful errors. Diagnostics omit business values, plaintext object titles, secret keys, tokens, encrypted-key material and unrestricted raw server text. References and stable IDs also carry correlation risk: return them only to the authorized caller and use local redacted aliases in exported diagnostics. Local trace detail is opt-in and protected; public error messages use allowlisted codes and safe labels. Recovery hints are typed actions with preconditions, never instructions to delete state, replace an identity or disable security.

## 10. Implementation sequence and acceptance gates

### P0: repair the actual blocked workflow

Fix PRIVATE finalize context/AAD preparation and verification; propagate structured safe errors; add local operation linkage and bounded reconciliation for this producer. Reuse existing qualified action timing and exact-byte journaling. Introduce only the shared preparation types needed by these paths. Implement a conservative classifier for saved malformed finalize attempts; if it cannot prove historical nonacceptance and future closure, leave the attempt pending. Add coverage preflight to activation and explicit unsupported producer results. No speculative service operation ledger is a P0 dependency.

The minimum complete journey is: retain the original member/Owner identities → inspect required credentials and workspace only → perform invitation decision/finalize in a guarded PRIVATE workspace → interrupt/reopen/recover → verify granted scope and member read/action → execute claim/renew/release and stale-worker rejection within the qualified protocol boundary → inspect a new business protocol version, verify, canary and install a separate v2 instance while v1 tickets continue, or return a precise compatibility blocker → recover the exact interrupted operation. Review or promotion `HOLD` must not block an independent claim. P0 may use already qualified existing installation APIs for this path; it must not falsely present unimplemented producer unification as available. Test the finalize subset first, but do not claim the full journey from that subset. Explicit ticket conversion is a separate acceptance scenario, using the short script above without making it a prerequisite for version coexistence.

### P1: complete the shared operation path for required management producers

Version durable operation/attempt records, implement crash-safe journal linkage, unify bounded recovery decisions, and adapt the additional producers required by the declared workspace lifecycle. Add legacy pending adapters by evidence-backed format priority; maintain explicit fallback boundaries. Add compatibility/plan output for protocol and instance upgrades. This is a bounded required-producer set, not an open-ended platform rewrite.

### P2: distributed replacement only where demonstrated necessary

Measure unresolved cases that existing replay/closure cannot settle. If those cases block required workflows, qualify the minimal service operation receipt/fence contract in section 4. Otherwise keep it deferred. More producers and an opt-in autonomous recovery driver can follow the same public lifecycle. Do not require arbitrary infrastructure modernization to finish a business upgrade.

### Required failure matrix

| Fault or race | Required observable result |
| --- | --- |
| Missing guard time in finalize; valid ordinary timed action | Local verifier catches new malformed bundle; corrected finalize succeeds; saved old bundle gets evidence-based recovery, not endless exact replay. |
| Crash before attempt persistence / after persistence / after submission marker | No unjournaled send; restart classifies not-sent versus unknown conservatively. |
| Server commits, reply lost; reply received, local persistence fails | Reconciliation returns the original command-bound effects without another effect. |
| Expired window with unknown prior delivery | Reconcile first; no local-clock inference or automatic replacement. |
| Concurrent head/policy change | Fresh envelope only after safe closure; changed business refs/scopes produce a decision requirement. |
| Old packet arrives after successor/fence | No second effect under the claimed contract; otherwise successor creation must be refused. |
| Two workers on one canonical store; independent copied profiles | Canonical-store race is serialized; copied-profile guarantee is explicitly absent unless service fencing is qualified. |
| Missing/forged response, incomplete history, stale replica, authorization loss | Unknown/verification failure preserved; no fabricated accepted/rejected state or automatic privilege change. |
| Lease expiry/revoke/reclaim versus old renew/release/delivery | Correct generation wins; stale authority cannot revive or overwrite the new holder within the stated enforcement boundary. |
| Review or promotion HOLD | Independent eligible claim succeeds; dependent operations explain their specific hold. |
| Legacy pending in A while operating B; ambiguous/global legacy record | Supported scoped work remains usable; genuine shared ambiguity is explicit, preserved and never discarded. |
| SDK/state-format downgrade; guarded-policy rollback request | Incompatible reader/writer refuses; no false promise of disabling guard time. |
| Publish/install v2 alongside existing v1 tickets | New tickets use the new instance; old tickets retain v1 source and continue without conversion. |
| Explicit conversion interrupted after target staging or source release | Resume the same child operations; verify old authority closure before new active claim; retain gap/uncertainty explicitly. |
| Cancellation and retry budget exhaustion | Stable operation remains inspectable; continuation preserves evidence and original authorization. |
| Private predicate failure | Useful local constraint and safe refs; no plaintext/key disclosure in server payload or default logs. |

Use deterministic local fault injection at persistence, send, commit, response and verification boundaries. Fixtures use generated identities, minimal input copies, an isolated local service and reusable toolchains. Keep concise source/artifact hashes and failure/result evidence; no full repository copies or production plaintext.

Acceptance must install the **actual candidate release assets** into ordinary Python, Node and CLI consumers, verify provenance/checksums, exercise packaged help/schema without a source checkout, and run the applicable matrix on the same qualified service contract. A test linked to worktree code does not qualify a published wheel, Node package or CLI archive. Release evidence identifies platform coverage and unresolved cases. No distribution parity claim without testing the corresponding assets. The public changelog is required when an actual product update is delivered, not by this internal design task.

Measure the same authorized task before and after: elapsed time, tool calls, mechanical Agent interventions, manual packet/state/polling work, number and duration of pending recoveries, and necessary business decisions separately. Retain first failures and distinguish scripted acceptance from a natural Agent trial. “80% fewer interventions” and “5–15 minutes” are hypotheses/targets if used, not results until measured. Report environment, sample size and remaining blockers.

## 11. Resolved tradeoffs and remaining qualification questions

Resolved: preserve one canonical SDK lifecycle; fix finalize first; split logical operations from immutable attempts; keep uncertain work rather than re-sign blindly; make producer coverage an enablement gate; keep migration/credentials/business adoption independent; use explicit claim generations; default to bounded reconcile-only compatibility; add service fencing only for demonstrated gaps.

Implementation must still qualify, without guessing: which current recovery/restore paths permanently close old checkpoints; whether existing structure/admission rules enforce the example claim generation against adversarial writers; exact lifecycle producer coverage for each enabled workspace; and which legacy SQLite intent variants have sufficient evidence for native import. These are explicit capability gates, not permission to weaken safety or open an unlimited infrastructure project. Where evidence is absent, the specified result is unsupported or pending with a concrete continuation. Public API option spelling may be adjusted to binding conventions, but the state, certainty, authority and replacement contracts above are fixed for implementation.
