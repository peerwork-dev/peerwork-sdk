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

An internal native authoring slice is now committed at SDK source
`074554c24c6e3375086f6df713f942052df7af52` (author module/test
`94a46aac1c1fcf9af0f50820f8f5b305bf918688`, direct `zeroize` lock
`20118488adc4ebc88d808d965da1e5cd604deb40`). The author module source
SHA-256 is `3212287f317dfb7a51891be17e3317e4d4bed01fef3733eec63fbd66fd151e86`;
the independent cross-open script SHA-256 is
`fca58601c7c52c6fedad8889c68a67f53f3af40d8b7cb530a52dc564504d0bcd`.
From a clean detached checkout at that exact SDK pin, Node 24.20.0 ran
`tests/secure-author-cross-open.mjs` with Rust 1.89 and task-local Cargo
cache/target, `--offline --locked`; it exited 0 in 6.7 seconds. Its focused
Rust test passed 1/1, and the pinned tracked TypeScript crypto verified the
native v3 PRIVATE signature, decrypted its AES-GCM content to the original
synthetic operation, and rejected altered context. The disposable vector was
deleted by the script. Earlier TS-to-Rust AES cross-open is recorded in the
core conformance report; this check is the native-to-TS direction.

This author is `pub(crate)` inside core and accepts caller-supplied context
and operation. It uses fresh OS nonce bytes with an explicit entropy error,
zeroizes selected plaintext/key/signing temporaries, and self-verifies the
signed HTTP packet before returning exact bytes for durable persistence.
Core peer source review found no scoped nonce/AAD/chunk/signature mismatch.
Dependency-managed key schedule and canonicalizer allocations have no full
memory-erasure proof. No authenticated policy/checkpoint/operation evaluator
proof exists yet, so this is cryptographic interop only, not an exposed
secure action capability or final-effect proof. Runtime production retry
must reuse the one persisted signed packet and never re-encrypt or re-sign it.

The first combined runtime test attempt stopped before compiling this source:
concurrent package compiler WIP changed `namespace_manifest` to three
arguments while a caller still supplied two (E0061). The package owner is
correcting that source. This interruption is distinct from the later passing
detached-checkout result; the original failed build is preserved as a shared
source integration interruption. The corrected core proof's four focused
tests also passed, including a newly re-signed one-byte ciphertext refusal,
normal split ciphertext acceptance, and empty-component HTTP admission
refusal.

Native recipient and private key lifecycle checkpoint: exact SDK source
`7463133ad35381c11e6acd8c02e2b3817dcb9c24` includes the new core
`SecretKeyring` and `SecretRecipient` primitives and private runtime
`SecureLifecycle`/`RecipientState` stores. The keyring source SHA-256 is
`42d6c6a177f54002df2c1480eb10708811b00d47734b6a3d93263df25c7c83b4`,
recipient source `2ba11fcd46241d4ebdf7a6414ec11495ba843c4fca65c49a864faae81619aeab`,
and recipient cross-open script
`95493be0432366cf417c01afc41b94d6a40b6d92d55feac6946f43852bc9e6e2`.
Synthetic TS-to-native and native-to-TS keyring HPKE open checks passed at
the earlier `5deb980` checkout; the recipient script passed at detached exact
`7463133` using Node 24.20.0 and Rust 1.89 locked-offline Cargo. It had
tracked TypeScript verify the native Ed25519 self-certificate, import the
native P-256 private serialization, open a native-recipient HPKE box, and
refuse an altered certificate. Generated private bytes were task-local and
removed by the script. This proves bounded crypto/serialization
interoperability, not a signed directory grant or action authority.

The first recipient-state handle returned by create/open released its
protected file lock while the recipient object was still live. Commit
`5deb980aea54aae73ded51484010a86c542a856a` retains the store guard
inside that handle; the focused regression observes `Busy` for a second
open until the first handle drops, then reopens the same certificate and
private scalar. At `7463133`, the recipient verifier also enforces the
tracked 366-day maximum signed certificate lifetime; a newly signed
367-day certificate is refused. Core peer review found the corrected bound
matches `workspace-secure-client.ts::verifySecureCertificate` and did not
identify another scoped certificate mismatch.

The private lifecycle represents an unestablished workspace as absent
active and pending rings. Every present PRIVATE ring denotes at least one
usable epoch key. This maps to tracked `newSecureKeyring` (one initial key)
and `openKeyGrant` (PRIVATE nonempty and containing the current epoch);
the valid empty PUBLIC keyring and low-level parser remain separate and
accepted there. Commit `7463133` rejects corrupt persisted empty present
PRIVATE histories on reopen. This is a native PRIVATE state invariant, not
a claim that the general TypeScript keyring parser rejects empty rings.
Pending key material persists exactly over reopen; production promotion
still waits for complete authenticated policy and journal proof.

The same commit corrected a secret-read lifetime issue: the protected
store now reads only the metadata-snapshotted length into a zeroizing
buffer, probes one zeroizing byte for growth, and rejects changed length;
identity create/import existence probes and open use the secret-bearing
read path. A deterministic appended-byte regression and over-cap
regression passed. This bounds allocation despite a noncooperating
same-user append between metadata and read. It does not prove complete
memory erasure in dependency internals or rule out concurrent same-length
mutation by a same-user writer.

Focused Rust 1.89 locked-offline results at `7463133`: core recipient 2/2,
runtime protected-state 9/9, lifecycle 2/2, identity 3/3. A detached
exact-checkout full runtime command compiled and passed 33 tests, including
those affected tests and recipient-state lock regression; six unrelated
localhost socket tests failed to bind with sandbox `EPERM`, and one
opt-in actual-service test was ignored. Those environment failures do not
convert this command into a full-suite pass. No Agent entry workflow or
space-protocol acceptance was exercised by these scripted crypto tests;
workflow compliance remains unverified separately from their business
correctness.

The six sandbox-blocked localhost cases were then run from the same
detached `7463133` checkout through the approved socket execution route,
without repeating the 33 already passing cases. Locked-offline filters
`transport::tests` passed 4/4 (three of the six plus one non-socket test),
`kernel_client::tests` passed 2/2 with its opt-in real-service case still
ignored, and
`secure_intents::tests::lost_http_reply_then_restart_retries_identical_verified_packet`
passed 1/1. The initial full-suite sandbox `EPERM` remains a recorded
environment failure; these focused runs complete its missing test coverage
at this source pin, not a replacement full-suite run.
