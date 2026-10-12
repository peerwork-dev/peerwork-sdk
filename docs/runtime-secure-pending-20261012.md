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
leaves the row PENDING. The exact committed source pin is
`a45ea0de4c9a01c2b232b0c16a9498cce90996fd` (proof correction
`2c46d7ded895fb6a8c0d5553f600c1d290b30585`). A detached worktree at
that pin passed Rust 1.89 `cargo check -p peerwork-runtime --offline --locked`
and the focused `cargo test -p peerwork-runtime secure_intents::tests
--offline --locked` suite, 3/3. The socket regression receives the complete
signed first POST, drops its reply, then proves the same exact bytes are sent
after journal close/reopen. It records the subsequent 200-looking reply as
opaque untrusted bytes and still lists the row as PENDING. This is a
synthetic local HTTP server, not actual Peerwork secure effect acceptance.

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
complete Peerwork secure outcome acceptance and cross-platform execution
remain open.

An opt-in actual service check now covers this narrow append route at SDK
source `c49d95df345d685c62a3d761509374cc1e59ae3e` against pinned
Peerwork TypeScript service checkout
`f828b6c50a0a58d1e718af90f653b214adcc3328`. The existing reference
bridge verifies that checkout's tracked build-input closure and compiled
artifacts before starting a fresh `WorkspaceKernel` and actual HTTP app.
`SecureAgentClient` generated a synthetic Ed25519 PKCS#8 identity, registered
it and created a PRIVATE v3 unstructured workspace through the real service.
Tracked TS writer helpers prepared one signed encrypted `discussion.post`
request without sending it. Native Rust imported the synthetic protected
PEM, persisted exact request bytes, verified its saved row, and submitted it
through a proxy that waited for the real app to apply the first POST before
dropping the reply. The test then closed/reopened the native journal and
retried the exact packet. Service `secure_commits`/head counts were 1/1 after
TS setup, unchanged 1/1 after native prepare, 2/2 after the applied lost
reply, and unchanged 2/2 after exact retry. The native row stayed PENDING
with one opaque response observation. The exact Rust 1.89 locked-offline
focused command `cargo test -p peerwork-runtime
actual_service_secure_append_retry_stays_pending --offline --locked` passed
1/1 in 1.33 seconds at the detached SDK source pin. The previous fixture
pin `a96c08416d3ba8875e54d6cd8098a193d0834b7c` also passed 1/1 but
did not assert the pre-submit 1/1 baseline; the correction adds that evidence.
This is scripted synthetic business-path evidence of actual server same-ID
dedup, not a native secure outcome proof or Agent workflow-compliance test.
Native production callers still need authenticated persisted policy context
and native signed request authoring; this fixture used tracked TS writer
helpers only to establish the signed-input interoperability boundary.

The first combined runtime test attempt stopped before compiling this source:
concurrent package compiler WIP changed `namespace_manifest` to three
arguments while a caller still supplied two (E0061). The package owner is
correcting that source. This interruption is distinct from the later passing
detached-checkout result; the original failed build is preserved as a shared
source integration interruption. The corrected core proof's four focused
tests also passed, including a newly re-signed one-byte ciphertext refusal,
normal split ciphertext acceptance, and empty-component HTTP admission
refusal.
