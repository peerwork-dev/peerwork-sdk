# Kernel receipt and recovery checkpoint, 2026-10-12

Native journal schema v3 adds `accepted_responses`, an exact-byte saved HTTP
response table keyed by the immutable prepared command ID. Native v1/v2 stores
migrate atomically; TypeScript database migration is still separate and has
not run. A response enters this table only after the core authenticates the
stored signed command and exact request body, matches its proof to the SQLite
row, and verifies the returned signed receipt against the configured origin's
pinned discovery key, audience, command, intent digest, result digest, and
result fields. HTTP status alone never marks acceptance. The public status and
pending listing re-verify saved responses on read, so a corrupt accepted row
causes an error instead of silently hiding a pending operation. Raw JWS, body,
and receipt bytes stay internal; public results use redacted getters.

The actual localhost HTTP regression prepares a signed command, loses its
first POST response, restarts and observes PENDING, receives a malformed
receipt and remains PENDING, then retries the exact saved request and records
ACCEPTED. A second restart re-verifies the saved response. Corrupting the
accepted response afterward makes pending listing fail closed. A separate
orphaned accepted-response record is refused at store open by foreign-key
integrity validation. Its first synthetic fixture failed during insertion
because the bundled SQLite connection already enforced foreign keys; the
corrected fixture explicitly disabled that enforcement to model an external
writer. No production check changed for that fixture correction. The full 24-test
runtime suite passed under the task-local Rust 1.89.0 toolchain with locked
offline dependencies and authorized localhost socket access.

This is a synthetic server test for the kernel command path. It does not prove
actual Peerwork service behavior, verified workspace reads, the separate
secure-agent action/journal replay path, backup/readback migration from old
TypeScript state, executed Windows protected storage, or Python/Node/CLI parity.
