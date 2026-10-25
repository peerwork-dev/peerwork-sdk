# Owner checkpoint conversion

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

For the separate one-off campaign where every legacy workspace can first go
offline, use [legacy workspace migration](legacy-space-migration-candidate.md).
It adds Owner-authorized frozen-archive retrieval, an encrypted reusable local
capsule, explicit read-only historical snapshots and operator admission into a
running new target. It does not require restoring old business execution.

## Review the selected Owner cache locally

Pause the Owner watcher and all other operations using the selected profile.
The inspection reads and verifies the existing ACTIVE cache without HTTP. It
copies only the selected cache and epoch-key state into a private temporary
directory beside the report, removes those temporary copies afterwards, and
never copies the signing identity. It preserves the original cache.

```js
const review = await sdk.inspectOwnerCache({
  stateDir: '/private/owner',
  workspaceId,
  reportPath: '/private/owner/conversion-field-review.json',
  expectedActor,
});
```

Python exposes `inspect_owner_cache(state_dir=..., workspace_id=...,
report_path=..., expected_actor=...)`. The CLI accepts the corresponding
snake-case JSON through `peerwork conversion inspect-cache REQUEST_JSON_FILE`.

The protected report contains local protocol schema declarations and instance
state field paths/types, not current state or record values. The returned result
contains only counts, the verified source frontier, and report path/hash. The
Owner authorizes the conversion disclosure policy. The approved default keeps
narrative body fields encrypted and makes other business structure readable;
repeated per-field approval is unnecessary. Mixed fields are diagnosed explicitly. Missing cache,
invalid verification, changed source files, or a report outside the selected
Owner directory fail explicitly. This tool is a review operation, not a complete
current-state exporter or a mapping approval.

## Prepare directly from the verified Owner cache

`planOwnerCheckpointFromCache(...)`, `plan_owner_checkpoint_from_cache(...)`, or
`peerwork conversion plan-cache REQUEST_JSON_FILE` generates the body/structure
mapping in the protected Owner directory. Select the existing Owner, workspace,
verified source snapshot SHA256, display name and plan path. It never submits a
transaction. Schema mappings are scoped to each instance, so identical schema
names in different protocols cannot cross-contaminate each other.

Then use `prepareOwnerCheckpointFromCache(...)`,
`prepare_owner_checkpoint_from_cache(...)`, or
`peerwork conversion prepare-cache REQUEST_JSON_FILE` with the selected Owner
state directory, exact plan/output paths, target origin and audience. The tool
verifies the existing ACTIVE cache, selects latest instance revisions, maps rows
into a zeroizing in-memory source buffer, and persists signed structure plus
encrypted bodies only.
It creates no persistent plaintext source snapshot and never copies identity
files. Verified original supplying commits and historical role claims accompany
the conversion. Record claims include the original record actor and creation
time separately from the supplying commit's actor and conversion acceptance
time. All source state remains on the Owner host.

```js
const plan = await sdk.planOwnerCheckpointFromCache({
  stateDir, workspaceId, expectedActor, snapshotSha256,
  name: 'Converted workspace', planPath: `${stateDir}/conversion-map.json`,
});
const prepared = await sdk.prepareOwnerCheckpointFromCache({
  stateDir, workspaceId, expectedActor,
  planPath: plan.plan_path, outputPath: `${stateDir}/checkpoint.jsonl`,
  origin: 'https://api.peerwork.dev', audience: 'https://api.peerwork.dev',
});
// Use prepared.context_binding.authority when binding the converted Context.
// An existing identity's authority must not be guessed from a new-ID default.
```

Preparation returns `context_binding` with the execution profile, selected
actor, authority, audience and workspace IDs. It does not bind a client to an
unactivated target or silently change the existing Owner profile.

Each manifest retains its own compilation budget; a mapping may contain many
independently bounded manifests. The whole plan has a separate2MiB input bound.
Multiple narrative fields can be encrypted as a JSON object through
`body_fields`; the decrypted content text is that JSON object. A single
`body_field` retains plain-text content. Business predicates that still depend
on removed body fields are rejected explicitly, without weakening the rules.
Inputs used exclusively to construct removed narrative outputs are removed
from the structural action contract as well. If another rule still uses that
input, preparation fails with `CHECKPOINT_BUSINESS_RULE_REQUIRES_BODY`; it never
requires the caller to disclose plaintext content in a structural command.

## Prepare a bounded signed artifact offline

For synthetic fixtures or an already authorized local export, supply a
protected current-state JSONL file and a
`peerwork.owner-conversion-map.v1` plan. The plan binds the existing Owner,
workspace, policy and journal frontier, selected target manifests and bootstrap
grants. Explicit field paths select readable structure and encrypted body text;
unselected fields are not exported. Business rules can only inspect structure.

```js
const prepared = await sdk.prepareOwnerCheckpoint({
  identityPath: '/private/owner/identity.state', expectedActor,
  origin: 'https://api.peerwork.dev', audience,
  sourcePath: '/private/owner/current.jsonl',
  planPath: '/private/owner/conversion-map.json',
  outputPath: '/private/owner/checkpoint.jsonl',
});
```

Python exposes `prepare_owner_checkpoint(...)`; CLI:
`peerwork conversion prepare REQUEST_JSON_FILE`. Both use snake-case request
fields. Existing identity selection is mandatory. Preparation makes no network
requests, enrollment or profile-wide receipt/key reconciliation.

Preparation streams source rows and automatically chooses bounded pages with at
most eight records, splitting further by byte size. Reopening the same output
verifies and reuses its exact signed bytes. Body keys remain in protected local
storage. Missing keys for an existing artifact are reported separately and never
silently replaced. Structure-only conversion does not create body-key state.

Selected source timestamps retain their original precision and offset as source
claims; authoritative transaction acceptance time remains distinct. Converted
records identify the Owner as the conversion attestor and retain the old record,
revision, author and commit association. They do not claim that the old author
signed the new structure. Source history remains unchanged in the archive.

## Operator import and activation

These commands run beside the protected archive and service receipt key. There
is no online checkpoint-submission route.

1. Initialize an isolated PostgreSQL target with `init --importing`.
2. Archive a consistent SQLite snapshot with `archive SNAPSHOT SHA256`.
3. Run `convert-owner-checkpoint CHECKPOINT_JSONL` once. The importer owns bounded
   page transactions and persists its progress. Invoke the same artifact after
   interruption to resume from the committed byte offset.
4. Inspect `checkpoint-status WORKSPACE_ID` if the result is uncertain.
5. Explicitly activate with `activate-owner-checkpoints SHA256`. Full activation
   requires every source workspace to be converted.

The signed `WORKSPACE_FRONTIER` binding approves the selected workspace, not
changes in unrelated workspaces. `convert-owner-checkpoint FILE --snapshot SHA256`
may select a later verified archive only if the selected Owner, authority,
policy and workspace frontier are identical. Re-uploading the same signed file
performs a one-time chain check outside row locks; ordinary resumes do not scan
an accepted prefix.

An isolated canary may explicitly select one or more workspaces using
`activate-owner-checkpoints SHA256 --canary WORKSPACE_ID ...`. Its persisted
scope is immutable. Default server startup rejects canary targets; serving one
requires `WORKSPACE_ISOLATED_CANARY=1` or explicit embedded-app `allowCanary`.
A canary is not a full production migration.

## Remaining release boundaries

- The selected ACTIVE-cache adapter is implemented. Relation conversion, broader
  legacy source coverage and membership/grant continuity remain unfinished.
  A selected real PRIVATE import/read, original author/time verification,
  large-program adoption/recovery and host-local restore have passed in an
  isolated candidate; this does not qualify every legacy workspace or browser
  journey. Historical role checkpoints are bounded to
 32 actors/256 roles per instance packet; larger histories require paging.
- Workflow transition validation uses only selected records/heads. Dependency
  graph workflows and reminder scheduling are not enabled by this candidate.
- An admitted artifact with a terminal semantic error currently requires a fresh
  isolated target for a corrected plan. Exact-file interruption recovery is
  supported; in-place corrected-plan retirement is not yet supported.
- Member/browser body-key delivery, browser/PUBLIC journeys, paged full audits,
  production-derived rehearsal and deployment are separate unfinished work.
- No SDK release or public Changelog publication has occurred for this candidate.
