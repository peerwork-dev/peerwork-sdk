# Secure pending journal boundary, 2026-10-12

The TypeScript `SecureAgentClient` has a separate secure packet/action-intent
path from its `WorkspaceClient` command-receipt SQLite path. The native
`secure_intents` module now stages an internal, pending-only durable store for
that path. It uses the same protected filesystem lock and atomic replacement
as secure local state, but a distinct file and schema. Each row pins the
configured origin and local actor at store level, and its own intent ID,
secure route, action, workspace, owner key, requested intent digest, SHA-256
of exact request bytes, and exact base64url-encoded packet. An exact repeated
prepare is idempotent; the same ID with changed bytes or context fails.
Untrusted exact HTTP response bytes can be appended in a bounded observation
list, including after an uncertain POST, without changing the row's pending
classification. Public summaries contain only ID, workspace, action, and
observation count; no raw packet or response is a language DTO.

Opening a saved store rejects a changed origin or actor, unsupported schema,
duplicate JSON keys, malformed base64, changed packet digest, excessive size,
or invalid row metadata. One Linux Rust 1.89 locked-offline regression passed:
exact packet and an unverified 2xx-looking response survived process-style
close/reopen; repeated prepare and duplicate response were idempotent, changed
packet same ID conflicted, and changed origin/actor refused. This is storage
evidence only. No secure packet is currently submitted from the public SDK;
the HTTP status and stored response cannot authorize `ACCEPTED`.

The bounded `prepared_secure_request` verifier now checks a PRIVATE,
unstructured, direct-author `{commit}` append packet against the exact HTTP
route, signed v1/v3 domain and signer, full supported payload key set,
ciphertext admission bounds, actor/workspace/policy/head context, and SHA-256
of the exact request bytes. Runtime source now rechecks that proof against
the immutable row, protected local identity, configured origin, owner key,
action, commit intent digest and saved request SHA before any POST/retry. The
source also keeps a received HTTP response as an untrusted observation and
leaves the row PENDING. This combined runtime source is an unverified local
checkpoint until its focused socket test and locked-offline check pass.

This is only pre-submit integrity. The caller-supplied workspace policy pins
must come from authenticated persisted history; a proof from arbitrary pins
does not grant scope. Bootstrap, public/structured/v2, delegation, policy
updates, grants and other secure routes need separate prepared proofs. The
tracked local decoder accepts empty ciphertext components when the total is
valid, while `workspace-secure-store.ts::validateCommit` rejects empty chunks
at HTTP admission. This verifier follows the latter and also requires at
least 16 aggregate ciphertext bytes.

Before any terminal result, a separate core `VerifiedSecureOutcome` must
authenticate the complete signed policy/commit chain, sealed content and
recovery/migration restoration, protocol source/structure, ACTION evaluator,
and exact response/head/effect binding. Runtime then compares that proof to
the unchanged row and persists the terminal state atomically. These proofs,
real Peerwork secure HTTP acceptance and cross-platform execution remain open.

The first combined runtime test attempt stopped before compiling this source:
concurrent package compiler WIP changed `namespace_manifest` to three
arguments while a caller still supplied two (E0061). The package owner is
correcting that source. This interruption is distinct from the earlier
successful core proof 4/4 and pending-store 1/1 focused tests; the combined
runtime/socket checkpoint is not yet accepted.
