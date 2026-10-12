# TypeScript WorkspaceClient v1 migration checkpoint, 2026-10-12

The tracked `dd8a9d2` `workspace-client.ts` (SHA-1
`b34e997a37467cb23ad7a2348c7a24c3a3365ce2`) stores its command journal in
SQLite application ID `0x50574331`, schema v1. The native runtime now has an
explicit `KernelClient::migrate_ts_store` operation after current-origin HTTPS
discovery has been parsed and pinned. The caller supplies the old database,
a private backup path, and an allowlist of public key IDs for all historical
local signers. No private key is read from or exported by migration. A missing
signer fails before native rows are changed, with an abbreviated key ID in
the error. The old database is opened read-only, backed up through SQLite's
online backup API, read back and compared row for row with the source, and
left untouched. Existing backup content must match the current source to
resume; if the old client has written since the backup, migration refuses.

Migration accepts only the exact tracked tables/DDL, application ID and
version, `quick_check=ok`, one pinned discovery row, valid timestamp/status
pairs, bounded row count and bytes, and private source/backup paths and
sidecars. Each row's exact saved JWS, digest and canonical command or catalog
chunk wrapper are checked. The TypeScript store did not persist raw POST
bytes: the native request body is reconstructed from its exact JWS and chunk
using the tracked submit format, then authenticated against the signed
command with the shared core. Pending rows stay pending. Accepted rows enter
the native accepted table only after the stored receipt/result verifies
against that row's signer, the pinned receipt key, exact command and result.
Native import is one `BEGIN IMMEDIATE` transaction: all existing IDs, byte
bindings, timestamps and accepted responses are preflighted under the same
write reservation before any row is inserted. A conflict rolls the whole
target import back. An unchanged source can be imported again after restart;
existing native rows with other IDs, changed timestamps, body bytes, or
accepted response bytes are refused. Accepted saved responses must equal
their lossless kernel-canonical encoding, matching TypeScript's saved format.
Actor-specific pending listing verifies saved rows and filters by signer, so
a legacy database containing more than one actor can be preserved without
relabeling records.

The old database persisted discovery semantics but neither `baseUrl`/origin
nor private signing keys. Current TLS origin and signer allowlist therefore
come from the explicit new-client configuration; migration cannot prove the
old client's original origin from the database. Callers must stop old-client
writes while taking the backup and importing; the before/backup/after
comparison detects changed snapshots but cannot establish future quiescence.
The source saved a canonical parsed response, not raw HTTP status/headers or
original response octets, so the imported accepted body preserves those
saved canonical bytes only. An import crash before commit leaves the native
transaction rolled back; retry with the same unchanged source and backup is
the recovery path. The old client remains usable from its unmodified source.

The experimental public entrypoints are `KernelClient.migrate_ts_store(source,
backup, trusted_signer_key_ids)` in Python, `client.migrateTsStore(source,
backup, trustedSignerKeyIds)` in Node, and `peerwork kernel migrate ORIGIN
JOURNAL IDENTITY SOURCE BACKUP --trusted-signer=KEY_ID` in the CLI (repeat the
last option for each historical actor). They use the same native importer and
return only pending and accepted row counts. Required source and backup paths
must be absolute and private. A cancellation before import refuses; once the
local SQLite transaction has begun, its atomic commit/rollback determines the
outcome. Callers must retain the backup. Importing verifies historical public
signatures but does not authorize the current identity to submit a different
actor's saved command; exact retry requires that actor's matching protected
local signing identity. For a local legacy-key migration, the explicit
`import_identity_seed_file(target, protected_seed_file)` API in Python,
`importIdentitySeedFile` in Node, and `peerwork identity import-seed-file` in
the CLI accept a path to a 32-byte Ed25519 seed file. The seed is never a
command-line value or result field. The native layer requires a private,
owner-controlled regular source and parent, rejects links, never overwrites
an existing native identity, and keeps the source unchanged for the caller to
manage. No public wrapper sends the old DB, backup, or seed to the service.

Three focused synthetic Linux tests passed under Rust 1.89 with the locked
offline workspace. They cover exact JWS/body reconstruction for ordinary and
catalog upload paths, pending and signed accepted import, two actors,
omitted-signer refusal before native writes, source preservation,
backup/readback, restart idempotence, changed-source refusal, conflicting
destination rollback, noncanonical saved-response refusal, weak matching
table names/columns refusal, forged accepted receipt and pending-with-response
refusal. The new public entrypoints pass a four-crate Rust 1.89 locked-offline
type check and Python/Node syntax checks; installed-interface migration and
actual TypeScript-client-created source coverage are still pending. This is
not yet a real Peerwork service migration run or Windows backup/readback
execution.
