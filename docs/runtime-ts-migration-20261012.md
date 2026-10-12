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
local signing identity. The tracked TypeScript agent initializer writes a
protected Ed25519 PKCS#8 PEM file (`agent-ed25519.pem`). For that source,
`import_legacy_identity_pem(target, source)` in Python,
`importLegacyIdentityPem` in Node, and `peerwork identity import-legacy-pem`
in the CLI import the file directly. The parser accepts one Ed25519 private
PKCS#8 PEM object with no trailing data; wrong algorithms and malformed files
are rejected. A separate low-level `import_identity_seed_file` /
`importIdentitySeedFile` / `identity import-seed-file` path accepts a protected
raw 32-byte seed when the caller has one. Both require a private,
owner-controlled regular source and parent, reject links, never overwrite an
existing native identity, and keep the source unchanged for the caller to
manage. Neither PEM nor seed is a command-line value or result field. No
public wrapper sends the old DB, backup, or key file to the service.

Three focused synthetic Linux tests passed under Rust 1.89 with the locked
offline workspace. They cover exact JWS/body reconstruction for ordinary and
catalog upload paths, pending and signed accepted import, two actors,
omitted-signer refusal before native writes, source preservation,
backup/readback, restart idempotence, changed-source refusal, conflicting
destination rollback, noncanonical saved-response refusal, weak matching
table names/columns refusal, forged accepted receipt and pending-with-response
refusal. The public entrypoints pass a four-crate Rust 1.89 locked-offline
type check and Python/Node syntax checks. The direct PEM importer had one
focused Rust positive/negative pass after its test PEM generator was corrected
to wrap base64 at 64 characters; its first focused run rejected that malformed
test envelope. The maintained `ed25519-dalek` PEM parser uses locked
`pem-rfc7468` 0.7.0 from crates.io.

At exact SDK commit `a93aabf13f427662b8191b12112010d3531d3e78`,
the opt-in [installed migration regression](../tests/installed-migration-smoke.py)
passed against the pinned actual Peerwork kernel HTTP app. The tracked
TypeScript `WorkspaceClient` created a fresh v1 SQLite store with two actor
identities, two accepted commands, and two unsubmitted pending commands.
Node's Ed25519 PKCS#8 PEM export used the same serialization and protected
`agent-ed25519.pem` filename as the tracked legacy initializer; the fixture
did not invoke that initializer function. Python imported actor A's PEM,
Node imported actor B's, and both public IDs matched the legacy client's.
A wrong algorithm PEM was refused without creating native identity state.
Python migrated the closed old store through a checked private online backup;
both actors' accepted and pending statuses were recovered. Submitting actor
B's saved command with actor A's identity failed without any service command
or workspace count change. Node and CLI repeated the same import idempotently,
then Python and Node submitted their respective pending exact commands. The
real service ended with four commands and four workspaces, and the old DB hash
remained unchanged. This proves the installed business path for the synthetic
two-actor cohort; Agent workflow compliance remains unverified.

The measured Linux x64 development artifact SHA-256 values were Python wheel
`78a22d8c0be7cfdccd0e04d24585bab6a1cfde733310d05261dfedc822dc7d52`,
Node addon `355cface4605e607ff80e31d6c0152f56d7adccaa26fa40d31c1372c920aa6f8`,
and CLI `d71627ff8f18d55db2c9c2badce184bec48f5668ec64dbd3f601954d66fbd3dc`.
From installed Python import, the observed stages were TS store close 994 ms,
native backup/readback/import 1,483 ms, both actors recovered 1,920 ms,
wrong-actor refusal 2,035 ms, Node/CLI reimport 2,445 ms, and both exact
retries verified 3,386 ms. An initial installed invocation stopped before
service startup because the source-pin environment variable contained a
wrong full commit hash; the corrected exact pin passed its first service run.
The earlier raw-seed fixture at `606f3a0` passed but is only low-level seed
import evidence, not direct legacy PEM compatibility. The installed test
writes sanitized counts, hashes, and stage times under `.build-artifacts`.
Actual Windows backup/readback and macOS/Windows client execution remain open.
