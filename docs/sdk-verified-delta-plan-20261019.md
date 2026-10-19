# Verified cross-poll delta: implementation boundary and next slice

Status: proposed, not implemented or qualified. T285 source review only; no new
runtime, service, package, or performance tests were run for this assessment.
This is a focused continuation of [the Agent runtime design](sdk-agent-runtime-design-20261019.md).

## Current behavior and concrete blockers

The current event adapter can recognize an unchanged protected checkpoint with a
small signed GET. It does not create a new proof, advance a cursor, or establish
freshness against a service withholding history. A changed or ambiguous reply
uses full authenticated history replay. This remains an honest useful reduction
in unchanged-poll work; it is not cross-poll incremental verification.

The following are architectural constraints, not missing convenience methods:

- `secure_read_profile.rs::read_latest_json_with_cancel` resets the inactive
  generation, verifies its complete replay against the protected old floor, then
  promotes its pointer. Its two slots are complete snapshots, not prefix/suffix
  segments.
- `secure_journal_read.rs::fetch_next_with_budget` stops after `next:null`.
  `validate_page` requires every page to repeat one checkpoint and policy list;
  `AuthenticatedJournalPages` additionally binds exact saved bytes and their
  chain. Appending another snapshot would violate this proof's meaning.
- `secure_verified_read.rs::collect_unverified_artifacts` takes policies from the
  first page only. Its downstream verifier receives all commits from genesis.
  Synthesizing replacement HTTP pages to join snapshots would falsely describe
  transport custody and is not an acceptable shortcut.
- `secure_replay.rs::replay_basic_content_depth` restores archived history,
  scans the complete signed chain, and preflights recovery before processing
  commits. Its local state includes seen-object identities, revision maps,
  prior objects, role history, previous policy, structure progress, migration
  state and verified guard-time proofs. `ReplayedSecureJournal` is a verified
  output projection; it does not preserve this continuation state.
- A later recovery can exclude an earlier range. Migration, archive restoration,
  structure transitions, policy changes and key epochs also need their existing
  semantics. Blindly appending effects or receipts can disagree with full replay.

## Bounded implementation sequence

1. Extract a private core replay state and its transition from the current
   verifier, initially without changing behavior. Make the existing full replay
   drive that same transition, retaining existing chain/recovery preflight.
   This avoids maintaining a second, weaker validator. A sealed continuation
   has no public constructor from caller JSON or a rendered object snapshot.
2. Define a deliberately narrow initial supported continuation: an ACTIVE
   PRIVATE prefix and ordinary action suffix with unchanged selected policy,
   keyring lineage and supported structure mode. Authenticate suffix headers and
   the final checkpoint before interpreting actions. Unknown transitions,
   recovery, migration, archive changes, structure changes or policy/key changes
   explicitly request full replay; they never receive weaker validation.
   Whether any ordinary action has historical semantics must be reviewed before
   admitting it to this class. Do not assume action names alone prove safety.
3. Introduce a distinct authenticated segment representation for exact fetched
   suffix pages. Bind base sequence/head/policy, configured origin, authority,
   actor/device, owner pins, discovery continuity and final checkpoint. Require
   the first suffix sequence to be base+1 and every link to be contiguous. Keep
   original HTTP bytes and snapshot boundaries; do not rewrite old pages.
4. Persist the continuation and its matching exact-artifact prefix only after
   verification. Use a versioned protected generation with manifest/digest and
   context/source binding, then atomically promote its pointer. Protected local
   storage supplies local integrity under the existing threat model; a plain
   hash alone does not authenticate an untrusted serialized replay state.
   Core deserialization and runtime restoration must be audited separately.
5. Let event ingestion consume the verified suffix and its exact action receipts.
   Preserve every intermediate receipt, including zero/many effects. Keep the
   reader checkpoint, durable enqueue checkpoint and per-consumer ack separate.
   Only after this path passes differential and restart tests should events
   advertise verified delta for that explicitly supported source cohort.

An optional earlier transport optimization may reuse an authenticated old prefix
plus newly fetched suffix while still fully replaying locally. It must be named
and measured as suffix transport reuse, not completion of the delta verifier.
It is not a prerequisite for the core extraction and must not add a parallel
synthetic-page proof path.

## Continuity, failure and delivery contract

The continuation must retain enough chain/policy history to establish ancestry,
not just compare sequence numbers. Epoch keys remain in the existing protected
keyring; no key copying into the new state format. Pin policy hashes and effective
sequences, owner authority, recipient/keyring lineage and attestation context.
Guard-time attestations remain bound to exact commit, source/result checkpoints,
service key and policy; retries cannot widen time bounds or replace proofs.

Hold the established profile/source lock while selecting and promoting a
candidate. Readers must see either the old verified generation or the complete
new one. Cancellation or crash before promotion leaves a resumable candidate
or an ignored orphan, never a new trusted floor. Crash after promotion but before
enqueue must recover the same retained verified suffix into the inbox without
losing intermediate events. Do not reclaim prefix/segments while a durable
reader/enqueue reference still needs them; exact consumer delivery deduplicates
by the existing source-namespaced event identity.

A nonancestor checkpoint, missing required retained range, incompatible restored
continuation or contradictory exact artifact fails closed. Distinguish corrupt
local continuation (full replay may repair it if authorized history is available)
from an actual source/history gap. A proven gap is sticky and never advances or
acks the missing range as complete. Transport timeout, revocation and verification
failure are not themselves evidence of pruning. Local consumer ack stays offline;
it is not protocol completion and cannot erase a source gap.

Retrospective recovery needs an explicit event contract before broader support:
previously delivered signed receipt evidence must not silently disappear, and
its historical observation must not be advertised as a permanently current
business effect. Keep this transition on the full-replay path until correction
or invalidation delivery semantics are reviewed. Full replay fallback alone is
not a claim that this broader inbox contract is already implemented.

## Required evidence before enabling the capability

- Differential real signed vectors: every supported prefix/suffix partition must
  yield the same objects, exact receipts, policy/checkpoint and failure classes
  as full replay. Cover multiple intermediate updates and zero/many effects.
- Negative continuity cases: wrong actor/device/origin/owner, base fork, missing
  or repeated sequence, changed policy/key lineage, altered exact page bytes,
  malformed/future/expired/missing guard-time proofs and unsupported transition.
  No rejected candidate may move the trusted or enqueue floor.
- Restart matrix around segment write, manifest write, pointer promotion and
  inbox enqueue; cancellation at the same boundaries; two writers under the
  existing lock. Assert no lost or duplicate logical delivery and no implicit ack.
- Explicit retained-history loss and local corruption tests, separately labeled.
  An artificial local cursor fault does not qualify external retention behavior.
- Measure unchanged, supported changed-suffix and fallback polls separately:
  fetched bytes, signature/decryption/transition work, retained storage, lock
  duration and active/wait time. Changed-suffix verification must actually avoid
  reprocessing the historical prefix. Bound total resources without relaxing
  existing crypto limits; no arbitrary success percentage substitutes for this.
- Repeat installed Python/Node/CLI sync/receive/restart journeys for each tested
  cohort, then frozen natural-Agent workflow acceptance. A core vector pass is
  not installed usability or fleet-scale evidence.

Release incrementally behind an explicit source capability with the old full
reader available. Existing protected profiles, pending operations and inbox
cursors must continue to open without forced migration or identity creation.
Do not enable a default automatic state-format upgrade until rollback and
cross-version opening behavior are tested.
