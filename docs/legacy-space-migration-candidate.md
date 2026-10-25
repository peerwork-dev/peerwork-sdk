# One-off legacy workspace migration

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

All legacy spaces can remain archived and unavailable while the new runtime
serves new spaces. Their original signed history and ciphertext remain intact.
An Owner can subsequently authorize conversion of one archived workspace without
restarting the legacy service or taking the new service offline.

## Result and boundaries

The campaign's supported default is an explicit `READ_ONLY_SNAPSHOT`. It retains
instance IDs, record IDs/revisions, current heads, relations and historical
attribution, while re-encrypting narrative bodies for the new body format.
Business structure becomes readable under workspace access controls. The Owner
signs the new representation; it is not a new signature by each historical
author. Original protocols remain in the protected source archive/capsule.

The new snapshot has a distinct protocol name/version and inert actions. It
does not restore old workflow dependencies, reminders or execution behavior.
Restoring those behaviors is separate work. The workspace Owner can later adopt
new supported protocols; that does not make the historical snapshot executable.

Legacy memberships, business grants, old member key delivery and PUBLIC
publication are not automatically re-enabled. The restored space starts PRIVATE
with its Owner. Additional access and publication require explicit new actions.
The campaign currently refuses sources with unclassified entity withdrawals;
it does not silently recreate a withdrawn current head.

## Owner request and protected source

Use an existing native identity. Pause concurrent operations on its selected
profile before capture or preparation. Keep the directory private (0700), files
0600, and back up the identity and generated body-key cache through the existing
protected process. Never send signing seeds or epoch/body keys to the operator.

Create `request-selection.json` on the Owner host:

```json
{
  "identity_path": "/private/owner/identity.state",
  "expected_actor": "OWNER_ACTOR_ID",
  "recipient_path": "/private/owner/migration-recipient.state",
  "request_path": "/private/owner/source-request.json",
  "workspace_id": "WORKSPACE_ID",
  "snapshot_sha256": "FROZEN_ARCHIVE_SHA256",
  "audience": "SERVICE_AUDIENCE",
  "service_key": "PINNED_EXPORT_RECEIPT_PUBLIC_KEY"
}
```

```sh
peerwork legacy-migrate request-source request-selection.json
```

The request binds the Owner, workspace, snapshot, audience, service signing key
and a dedicated encryption recipient. Repeating the same request reuses its
exact bytes; conflicting selections are refused. Send only `source-request.json`
to the operator. The operator uses the protected PostgreSQL archive:

```sh
node dist-workspace/src/workspace-postgres-admin.js \
  export-legacy-source /private/source-request.json /private/source.encrypted
```

The operator validates the Owner signature and frozen archive. On a running
target it also checks the current Owner root. It returns encrypted scoped rows,
an authenticated page chain and the pinned service's signed receipt. Rows from
other workspaces are excluded. No legacy HTTP endpoint is involved. The signing
key is pinned explicitly by the Owner, rather than trusted merely because it
appears inside the returned file.

Copy the ciphertext to the Owner and create `capture-selection.json`:

```json
{
  "identity_path": "/private/owner/identity.state",
  "expected_actor": "OWNER_ACTOR_ID",
  "recipient_path": "/private/owner/migration-recipient.state",
  "request_path": "/private/owner/source-request.json",
  "source_path": "/private/owner/source.encrypted",
  "capsule_path": "/private/owner/source.capsule",
  "state_dir": "/private/owner"
}
```

```sh
peerwork legacy-migrate capture-source capture-selection.json
```

For encrypted journals, `state_dir` selects existing local epoch keys and the
saved verification floor. Alternatively, supply `keyring_path` to a protected
existing keyring when recovering without a profile. Supplying both is refused.
A plain legacy PUBLIC source needs neither. Missing decryption keys cannot be
recovered by server authorization alone.

Capture verifies request binding, encryption, all page hashes, the service
receipt, original secure policies/commits and exact source frontier. It checks
the saved floor when a profile is selected. This first secure capture processes
retained history once and can be slow; it is explicit migration work. It does
not mutate the old cache, install lifecycle or identity. Decrypted source rows
are processed in memory and the resulting local capsule is authenticated and
encrypted under the selected identity. A partial or modified export is refused.

If the complete source is already available in an authenticated Owner cache,
`legacy-migrate capture-cache` accepts `state_dir`, `workspace_id`,
`expected_actor`, `snapshot_sha256`, and `capsule_path`. Network refresh is off
unless explicitly selected. A capsule matches one exact source; final cutover
writes require a new matching frozen source, not a claim that an old capsule is
permanently current.

## Offline mapping and preparation

```json
{
  "state_dir": "/private/owner",
  "workspace_id": "WORKSPACE_ID",
  "expected_actor": "OWNER_ACTOR_ID",
  "snapshot_sha256": "FROZEN_ARCHIVE_SHA256",
  "capsule_path": "/private/owner/source.capsule",
  "name": "Historical project snapshot",
  "plan_path": "/private/owner/snapshot-plan.json",
  "read_only_snapshot": true
}
```

```sh
peerwork conversion plan-cache plan-selection.json
```

Inspect the protected plan's body/structure mappings locally. It classifies all
instances; ambiguous mixed fields are errors. Plain PUBLIC and sources whose
legacy derived index is still `Seeding` require this explicit read-only mode.
The latter uses complete authenticated logical objects, never the unfinished
old index, and never claims that old business execution has been restored.

Prepare with a second selection:

```json
{
  "state_dir": "/private/owner",
  "workspace_id": "WORKSPACE_ID",
  "expected_actor": "OWNER_ACTOR_ID",
  "capsule_path": "/private/owner/source.capsule",
  "plan_path": "/private/owner/snapshot-plan.json",
  "output_path": "/private/owner/checkpoint.jsonl",
  "origin": "https://TARGET_CONTROL_ORIGIN",
  "audience": "SERVICE_AUDIENCE"
}
```

```sh
peerwork conversion prepare-cache prepare-selection.json
```

Planning and preparation use the sealed source without network or old journal
replay. Preparation validates the target first, encrypts body fields and signs
bounded checkpoint pages. All selected instances, retained records, current
heads and relations must be accounted for. Keep the generated local body-key
cache: the signed checkpoint alone cannot decrypt restored bodies. Choose the
actual target origin; local body-key storage is origin-scoped. An acceptance
tunnel and a production origin are different local key namespaces.

## Operator rehearsal, import and recovery

Send only the signed checkpoint containing authorized readable structure and
encrypted bodies to the operator. First validate the complete artifact against
the frozen archive in an isolated target with the same implementation. A valid
signature does not guarantee that every later page has valid mappings.

After rehearsal passes, a new target already activated with the complete
archive disposition can admit this one space:

```sh
node dist-workspace/src/workspace-postgres-admin.js \
  convert-owner-checkpoint /private/checkpoint.jsonl --live-archived
```

Admission requires global READY/ALL, the registered frozen snapshot, current
Owner authority, and the same Owner's ARCHIVED target. An unrelated ACTIVE space
cannot be replaced. The global store stays READY. This space remains CONVERTING
and unavailable to ordinary reads until its final transaction installs ACTIVE
and the new execution profile together. New workspaces and their writes remain
independent. Reserved locators and existing workspace quota are retained.

For an interrupted operation, inspect before retrying:

```sh
node dist-workspace/src/workspace-postgres-admin.js checkpoint-status WORKSPACE_ID
```

Resume with the exact signed file. Committed pages resume by byte offset;
completed replays import zero pages and cannot overwrite subsequent writes.
Replacing the mapping during a partially admitted live import is not supported.
A semantic error discovered after admission needs operator diagnosis and a
fresh isolated rehearsal, not repeated blind retries or manual progress edits.

Finally, the original Owner reads through the new SDK with the new target
origin and local body keys. Compare the exact expected current-head set,
retained-record/relation counts and all expected body opening results. Current
head count differs from retained historical record count. No client must replay
the old journal to read the migrated current state.
