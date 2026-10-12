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

Native protected-state-to-authoring checkpoint is SDK source
`3aab83510f27ca2bce0b6f757c466cdaa538eaa2` (`ebe87e5` bridge and fixture, followed by the core low-level
module registration). The author source SHA-256 is
`828377d6eb42f421857744e34d05241886c9eb55332762f900af0b36ed4e218f`,
runtime private bridge
`6d809c72762144a62cd446cba6094736b35da5508ae6e2de535a3335abfedc38`,
and tracked-service bridge
`f3835783bd94a782f7ead32830be550b3960955a6b2be2fb10e855fd7666f9e8`.
The low-level Rust author API is now cross-crate visible, with explicit
caller-supplied context and no policy/action authority. The runtime bridge
requires a matching protected identity, origin, actor, workspace, owner pin
and **active** epoch key; it derives the exact route, signs and seals one
new request, persists proof-derived ID/action/digest and exact packet before
any transport, and refuses an already-saved ID before re-encryption.
Pending epoch keys cannot authorize it. The bridge is private to runtime;
no Python, Node, or CLI secure action entrypoint was enabled.

At detached exact `3aab83510f27ca2bce0b6f757c466cdaa538eaa2`, Rust 1.89 locked-offline focused local test
passed 1/1: pending-only key refused, test-only active key staged one exact
packet, duplicate prepare did not re-author, and close/reopen preserved the
same bytes. The opt-in actual-service focused test passed 1/1 in 1.33s with
Node 24.20.0 against pinned TypeScript service
`f828b6c50a0a58d1e718af90f653b214adcc3328`.
The exact test filter was
`secure_native_prepare::tests::actual_service_accepts_native_authored_packet_then_exact_retry`
with `cargo test -p peerwork-runtime --lib --offline --locked ... -- --nocapture`,
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`
set through the approved loopback-socket execution route. The reference
bridge checked the configured checkout and built service provenance before
launch; the environment variable was present, so the test entered the
actual server branch rather than its unset-variable early return. TypeScript created a
fresh PRIVATE v3 workspace, policy, identity, action context, operation, and
epoch key in protected temporary fixture files. The Rust private test
imported that key through a **cfg(test) grant stand-in**, authored a new
ciphertext/signature distinct from the unused TypeScript prepared packet,
and saved it without an HTTP POST; service commit/head counts stayed 1/1.
The first native-authored POST was applied by the real kernel before the
proxy discarded its reply (counts 2/2). A reopened journal retried the
identical saved packet and received an observation; service counts remained
2/2 and the native row remained PENDING. Synthetic fixture files and
private keys were removed with the temporary directory. This proves
native packet admission and same-ID retry through actual HTTP, not a
complete native client action: signed policy/grant authority, native
production key activation, full replay/effect proof, and final-result
promotion remain open. Agent entry-instruction/space-protocol compliance
was not exercised and remains unverified independently.

Signed direct key-grant material checkpoint is SDK source
`27fe519d2013befdafddb65309471abed0e0b065` (module `46f1524`, core
registration `27fe519`). The grant verifier source SHA-256 is
`3702de8aaea82cd2960978f5ec7e09900aa0af84509418da7863b17cfaa54129`,
and the dynamic direct TypeScript oracle script is
`41a99969646ce3dff93ef8fef0aa748c7456d9c7d266b9f1edea71af8cea70b8`.
At a detached exact checkout, Node 24.20.0 ran
`tests/secure-grant-cross-open.mjs` with Rust 1.89 offline locked Cargo,
task-local dependency cache/target, and no service or operator state. The
script used vendored pinned TypeScript `createPolicy`, `verifyPolicyChain`,
`createKeyGrant`, and `openKeyGrant` to create and open a fresh synthetic
PRIVATE owner grant. It supplied a mode-0600 temporary vector to the Rust
`direct_ts_owner_grant_vector` filter with `PEERWORK_GRANT_VECTOR` set; the
native positive and altered signature, wrong recipient, epoch, and policy
negatives passed. The vector and synthetic recipient private scalar were
removed on exit. The test's unset-vector early return is not counted as
evidence; the script set the variable and checked the Rust subprocess exit.

The bounded verifier checks caller-pinned owner against the signed policy
header chain and exact checkpoint, selects the grant's signed policy hash,
requires the latest policy to keep its owner and epoch, checks the recipient
self-certificate and current membership, authenticates the direct owner
grant signature, then opens HPKE with the signed grant payload minus `box`
as exact context and parses a workspace/current-epoch keyring. The returned
private-constructor `VerifiedGrantMaterial` proves those cryptographic
facts only. Caller-supplied origin/owner inputs and header-chain checks do
not establish complete replay or freshness; it is not consumed to promote
runtime keys. Invitation acceptance, delegated delivery, owner bootstrap,
rotation/recovery and full signed journal replay remain required routes and
currently fail closed or lack an activation consumer. Agent workflow
compliance was not tested by this crypto oracle.

Signed invitation and device-delegation grant checkpoint is SDK source
`866f104cd734f142bf716842b815dcbebeec07e9`. The verifier source
SHA-256 is `ecfac4d457b8dc5077351de2c64f172ecfebf00c593feca791ff78ccf94b5a1d`;
the dynamic oracle script is
`83291f7aeeb7f31566920328045c8dc8f3202dd9475b06ca2af7f36e516ee5e2`.
The existing direct grant vector was extended with a TypeScript-created
accepted invitation for a current policy member and a signed device
delegation. TypeScript `openKeyGrant` opened both, while the Rust verifier
authenticated signed offer/decision or delegation, exact recipient and
workspace, selected/latest policy and owner, related artifact hashes,
grantor membership, times, origin/audience pins for delegation, and the
HPKE/keyring context. Rust rejected omitted or altered related proof,
altered grant signature, epoch/policy and wrong recipient. A delegated
origin/audience mismatch is refused against caller-supplied runtime pins;
those pins still require configured-origin provenance outside this helper.

The focused dynamic test ran against a detached clean checkout at exact
`866f104` using Node 24.20.0 and Rust 1.89 `cargo test -p peerwork-core
direct_ts_owner_grant_vector --offline --locked` for each of three
mode-0600 temporary vectors. The script set `PEERWORK_GRANT_VECTOR`, checked
each subprocess exit, and deleted the vectors. It reused the task-local
conformance `node_modules` installation only after the detached and main
`conformance/package-lock.json` files matched byte-for-byte (SHA-256
`51ee718ed3b84f58542dc1329e688faccaed3dbfcd6acc4cd408167fb2eca9c0`);
the temporary symlink was removed after the passing run. The first detached
attempt stopped before any verifier execution because `node_modules` was
absent; it is not counted as a test pass.

This remains cryptographic grant-material verification only. The signed
policy/checkpoint inputs and trusted owner pin are caller-supplied, current
origin provenance and complete journal replay are not established here,
and no runtime key was activated. Owner bootstrap, production
policy/grant-to-keyring activation, rotation/recovery and full effect proof
remain required. Agent workflow compliance was not exercised by these
synthetic crypto vectors and remains unverified separately.

Peer review found two valid-input/time errors in the first invitation and
delegation verifier at `866f104`. It required an accepted invitation's offer
policy hash to equal the later grant's selected policy hash, while the
tracked TypeScript flow permits an earlier signed invitation followed by a
new policy adding the recipient. It also checked delegation expiry at grant
issuance but not at the later open time. Corrected source is
`a2de9cda3118fdf32e336a5fc1a2f27e0a518f29` (verifier SHA-256
`1a39de398a04d34fa97b8e3cf06c685e36e884204b5adec1aa48948ebcbc5e15`,
oracle script SHA-256
`466620f88b2ca3214569946ffb0365a163411951c7ed771361e5e5de66edab0d`).
The corrected TypeScript positive issues the invitation under policy v1,
adds the invited member under policy v2, creates the grant under v2, and
opens it. The Rust header-chain fixture has two synthetic signed v1 commit
headers to make policy v2 effective; those headers are not evidence of a
replayed action. The delegated case opens while valid and refuses an open
exactly at signed expiry in both TypeScript and Rust. The detached exact
`a2de9cd` Node24/Rust1.89 locked-offline dynamic oracle passed all three
cases and related negative assertions; the temporary lockfile-matched
dependency symlink and mode-0600 vectors were removed. The original
`866f104` bounded pass remains recorded as its narrower first attempt and
is superseded for invitation/delegation parity by this corrected pin.

Recipient-certificate peer review found a narrower v1 compatibility issue:
the local recipient verifier rejected a correctly signed certificate with
an extra benign payload field, while pinned TypeScript
`verifySecureCertificate` accepts it. Corrected source is
`06692007c2d1084bd4ac353a144728833942e4b3` (`secure_recipient.rs`
SHA-256 `d09043e1c207f7af08e0dd92984e97f17b34b1771a7f9de233a0dfca0fdf431b`,
oracle script SHA-256
`f0cc158263f3db33d796f0cb43c700d44ef098b0b0caafff251c2c43ef934d31`).
The detached exact-pin dynamic oracle passed four TypeScript-to-Rust vectors,
including a v1 policy/grant with an extra signed certificate field and the
prior rotated-invitation and delegated-expiry cases. The JWK itself remains
exactly four fields. Structured v2/v3 policy certificates retain their
separate exact-field shape rule in `secure_chain.rs`, matching the pinned
structured-policy validator; that rule was not changed. The lockfile-matched
temporary dependency link and private vectors were removed after the run.

Protected pending grant-evidence checkpoint is SDK source
`e906e973c8f2e4d6f3a60832e2d771128de18f46`, corrected at
`d18eae324b7106762645ab0c49065787f1342786` (module SHA-256
`371fbec2826c7d4b1649c8b1a883ea159ba5b2df4a43838bd63ab04bf1ddb41c`).
This private runtime module saves one exact signed policy/commit/checkpoint,
grant, recipient certificate and optional invitation/delegation bundle in
one atomically replaced protected state file, after core grant proof.
Configured origin, audience, workspace, owner and local signer pins are
immutable. Reopen re-verifies with the protected recipient and caller's
**current** observation time; no saved timestamp stands in for the current
time. Exact repeat is idempotent and changed bytes refuse replacement. No
plaintext keyring is serialized: HPKE material is opened by a fresh proof.
The returned material does not activate `SecureLifecycle` or authorize an
action. The caller must obtain policy/commit bytes through the configured
origin's TLS transport; this local store cannot prove that provenance.
Its current native evidence cap is 64 MiB and each chain is capped at 1024;
valid larger histories need paged/streamed storage before broad support.

At a detached exact `d18eae3` checkout, Rust 1.89 locked-offline
`cargo test -p peerwork-runtime --lib secure_grant_pending::tests` passed
1/1. The synthetic self-grant test uses protected identity and recipient
files, saves exact evidence, reopens the same pending epoch, refuses a
whitespace-different replacement, wrong origin/recipient and tampered saved
signature. A separate delegated grant in that test reopens while valid and
fails exactly at its signed expiry. An over-1024-policy input refuses before
core signature/HPKE verification and leaves the store empty. These are
synthetic Rust storage tests; no real service or language wrapper was
exercised. The first focused test failed on an incorrect assertion that a
direct grant expires when its certificate later expires. Pinned
`openKeyGrant` checks that certificate at grant issuance; the corrected
test preserves a later direct reopen. This local self-grant is not proof
that the tracked TypeScript owner bootstrap flow is natively reproduced.
Production policy/grant provenance, complete replay/checkpoint activation,
owner bootstrap, rotation/recovery and final effect verification remain open.

Owner-bootstrap pre-submit checkpoint: `04798ce` added a signed genesis
`{policy,commit}` proof for the exact `/api/workspace/v1/secure/workspaces`
route; `03cbc7a` added native PRIVATE packet authoring with a fresh OS nonce.
Core registration landed at `17b001b`. Peer review found that the v3
bootstrap handler rejects the *presence* of `migration`, `recovery`, and
`conversion_excluded_members` even though generic signed shape permits
them. `39e39d4` corrected the proof (source SHA-256
`87f3f4d71fef3838f1484a890fb601ed076afe702bed987f22d6d690d1d9c0eb`):
a validly signed v3 baseline passes, while newly signed variants with each
forbidden property set to null refuse. Rust 1.89 locked-offline focused core
test passed 1/1. This is pre-submit integrity, not decrypted operation or
service acceptance.

Runtime checkpoint `197f1f9d0083757f468fdb87f913eb62f1eac7aa` (lifecycle,
author bridge, journal SHA-256 respectively
`858132af9b7115dc705a48f19647391602ce345d048a92d38cd3b123c9a4b43b`,
`d2466670f3c99a6a3a9950888a6400c62b7d933e11740e8ddc80dd71965e28ff`,
`42ea6b057ccc7561fab9f3a2c36cdb2bae302d3f40cb850a94cc382d0218fff8`)
stages epoch 1 in protected pending state, signs once, then atomically saves
the exact root-route packet before any HTTP. A repeated intent ID refuses
before re-encryption; reopen and retry reprove saved signature, origin,
workspace, local owner/key, pending key presence, action, digest and exact
request SHA. Every HTTP response remains PENDING. If preparation fails after
key staging, repeating it reuses the staged key. The detached exact-pin
`cargo test -p peerwork-runtime --lib
secure_native_prepare::tests::owner_bootstrap_stages_key_and_exact_packet_across_restart
--offline --locked -- --exact` passed 1/1 on Rust 1.89 with task-local Cargo
cache and target. The first check used the default Cargo cache and stopped
before compilation because `pem-rfc7468` was absent; the documented
task-local cache command then passed. This regression covers durable local
preparation and refusal, not actual Peerwork bootstrap admission. It uses
an empty synthetic BOOTSTRAP object set, whereas tracked owner creation
installs the collaboration preset objects and scopes. Those native objects,
actual service lost-reply retry, complete replay/activation, PUBLIC mode,
structured mode and language surfaces remain required. Agent workflow
compliance was not exercised by this synthetic Rust test and is unverified
separately from local business correctness.

Custody correction `89a7e0a`: reviewer found that saved signed bootstrap
bytes and independently protected pending keyring could be mismatched on
restart. Before `submit_saved_bootstrap` can POST, the runtime now derives
the signed content context, authenticates the exact saved AES-GCM body with
the reopened epoch-1 pending key, and checks the BOOTSTRAP operation shape.
A second independently generated pending ring with otherwise identical
origin/owner/workspace pins refuses before transport, leaving saved bytes
unchanged. The focused Rust 1.89 locked-offline restart test passed 1/1.
This supersedes the narrower `197f1f9` custody claim. The decrypted byte
buffer is `Zeroizing` and a successfully parsed operation is wiped; parser
allocations on a malformed plaintext error path are not proven erased.
No complete memory-erasure claim is made.

Native default owner-create source checkpoint is `7aa8272` plus core
registration `7603df0`. It embeds the exact tracked
`f828b6c50a0a58d1e718af90f653b214adcc3328` Apache-2.0
`src/workspace-presets.ts` (SHA-256
`2e85ed64b4ff63737cfe5fc2fd47f270dc8bb488533a5a287a0270d5702223bd`)
as six validated collaboration manifests. The generated fixture SHA-256 is
`0aa41e318cfb7b205a31d281d45d09c9d220af2b33e97df31975ba522af32786`;
the native builder SHA-256 is
`1c4931c179e9b0e6017da1219dec2c0a13e9f932643223473779fd2ab6172e7a`.
Rust independently canonicalizes and hashes each embedded manifest, then
constructs the workspace, protocol, instance and Owner scope objects in the
tracked six-entry order. The exact detached-pin core test passed 1/1. This
runtime path does not spawn Node. These six defaults are not the complete
dynamic/custom protocol authoring API.

Native owner-create transport checkpoint is exact SDK commit
`f78b694fd5c41251d6fa90ea828c5c292fa4e5a7` (runtime producer SHA-256
`238d4078d3b1cad94f4a8a1a9b23678cdeffa791e823b00740ad5b9f5d52cd70`,
transport `cd3dbeeeca5a657224cc0f6dc85016d6090c1d14771cce1118e9796c99835bfd`,
reference bridge `61350432c95de2b1eb7181a710961022a594f29069d552b6e90acb6d107cdec7`).
The opt-in Rust test was run from a clean detached checkout at that exact
commit with Rust 1.89 locked-offline, Node 24.20.0, the pinned built
TypeScript service checkout `f828b6c`, with
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`.
The test filter was
`cargo test -p peerwork-runtime --lib
secure_native_prepare::tests::actual_service_native_owner_bootstrap_lost_reply_exact_retry
--offline --locked -- --exact` using the task-local Cargo cache/target and
Rust 1.89 compiler.
The bridge itself verifies its pinned source and compiled-closure hashes.
TypeScript only generates/registers the synthetic Ed25519 Owner identity;
Rust imports its protected PEM, creates a P-256 recipient, authors the six
default objects/scopes, v3 PRIVATE policy and encrypted signed BOOTSTRAP,
stages the epoch-1 key, and saves exact request bytes before HTTP. Fresh
service secure counts were commits 0/head absent before and after native
preparation; the first POST committed but its reply was dropped; service
counts then were commits 1/head sequence 1, with DB head hash equal to the
native signed commit digest. Reopen re-used the exact bytes and the real
service returned workspace ID, sequence 1 and the same head; counts stayed
1/1. The native row stayed PENDING with one observed response, and the key
stayed pending. The exact detached opt-in test passed 1/1. Focused local
owner preparation and root-route allowlist tests also passed; the ordinary
test with `PEERWORK_REFERENCE_ROOT` unset exits early and is **not** actual
service evidence.

The first two opt-in attempts stopped at `Transport(InvalidOrigin)`: the
root bootstrap route was missing from the transport's exact allowlist. The
runtime allowlist was corrected, with a focused negative test rejecting
nearby paths, then the exact-pin service test passed. This is actual service
admission and same-ID dedup evidence for one native default PRIVATE owner
create, not a signed journal read, complete operation replay, active-key
promotion, PUBLIC/structured create, or a public language create surface.
Agent workflow compliance was not exercised by this scripted client test;
business-path behavior and workflow compliance remain separate judgments.

## Exact secure journal read and restartable pagination

SDK source `83f35f55cc25a7c9d003ee614fcd589644619424` adds a private,
protected secure-journal read store. It signs a fresh single-use Ed25519 GET
proof over the exact sorted path, configured discovery audience, local actor
and default actor authority. It stores exact bounded HTTP page bytes with
configured origin, discovery context, actor/key and workspace pins. Each
reopen rechecks those pins, the exact saved pages, checkpoint equality,
policy-prefix equality, increasing commit sequence and cursor continuity.
The store exposes only **unverified transport progress** internally; signed
policy/commit replay, key activation, action effects and final outcomes still
require the complete core proof. The native 32 MiB page, 64 MiB store and
2048-page caps are interim storage limits, not full protocol parity.

Exact source SHA-256: `secure_journal_read.rs`
`4f20d19b81c655b97ea4372dc2cf7e9151d02e4d65fab3357ed692d7eef20359`,
`secure_native_prepare.rs`
`52c66e6121e400e2599a155029d19bff87bd9037b6ce9d5050694053876958f7`,
`transport.rs`
`8e98ab939f07dc2a2d06c9f4dcebc566b2667da715c0d5655374bf5a4600924f`,
and reference bridge `dac55c9174cd2990c9d60bf238b7f2923b3660553b90e22dfafab60f61c92ab0`.
From a clean detached checkout at that SDK pin, Rust 1.89 with task-local
Cargo cache/target and `--offline --locked` passed focused
`cargo test -p peerwork-runtime secure_journal_read::tests` 1/1. The
opt-in real-service filter
`cargo test -p peerwork-runtime actual_service_native_owner_bootstrap_lost_reply_exact_retry --offline --locked -- --nocapture`
passed 1/1 in 10.39 seconds with
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`;
the bridge pins the tracked `f828b6c` service build inputs. The test used
fresh synthetic state and the already recorded native owner-create/lost-reply
flow. After its exact retry, a **test-only** pending-key activation and 50
additional native-signed, service-admitted pagination packets raised the
service count/head sequence from 1/1 to 51/51. Those extra packets exercise
HTTP journal pagination only; their ACTION effects were not independently
replayed or accepted as business-correct. The first signed GET saved exactly
50 commits at checkpoint sequence 51 and cursor 50. After protected-store
close/reopen, the second fresh signed GET saved commit 51 against that same
checkpoint. A second reopen retained both exact pages; service counts stayed
51/51 during reads. The protected key/intent remain without final proof.

The first signed GET attempt failed HTTP 401 `SIGNATURE_INVALID` because the
local reference proxy forwarded only Content-Type and dropped the
`X-Peerwork-Read` header. The fixture now forwards only that additional
read-proof header. Independent review also found the initial page-two target
ordered `at_head,at_sequence,after,limit`, which the tracked verifier rejects
as noncanonical; it now uses `after,at_head,at_sequence,limit`. Both failures
are preserved as first-attempt evidence, and the corrected exact-pin two-page
run passed. This scripted test exercises business transport behavior, not
Agent instruction or space-protocol compliance; those remain unverified.

Read-context and cancellation correction at exact SDK source
`26be8ad3b0bfda6042ddfb1cd9a57e596b21d046` (prior cancellation-only
source `aa423b23cd70fff298d527cd1d0e500a3a87d239`) removes a caller's
ability to pair an arbitrary parsed discovery with the read transport. The
private reader now accepts an origin-bound `KernelClient`, whose open fetches
and schema-checks discovery from its configured origin and persists the
continuity pin in SQLite. Its protected read store pins the original exact
discovery wire, origin, actor/key, explicit configured authority and
workspace. Reopen permits only the tracked additive discovery update rule;
a changed receipt key or removed feature fails. Stored schema v2 refuses
the earlier private v1 interim format until a deliberate migration exists.

The pinned service requires first identity registration authority
`SHA256(actor_id)` (`workspace-kernel.ts::executePath` around line 680), then
requires that registered root authority on signed reads. A synthetic
`WorkspaceClient` registration with a nondefault authority was attempted
first and received HTTP 401 `SIGNATURE_INVALID`; there is no supported
nondefault registration/rotation route in this pinned service. The reader
still takes and pins an explicit authority from client configuration, and
the actual service regression verifies a wrong authority gets HTTP 401 with
zero saved pages. It also verifies a different local identity and a different
configured origin both refuse reopening the protected two-page store before
GET. No service database was seeded or altered to manufacture a positive
nondefault-authority case.

The same fresh actual-service fixture holds the first journal GET response
after the service processes it, cancels the native request in flight, and
asserts zero saved pages. Reopen signs a fresh nonce and downloads the same
50+1 pages at fixed checkpoint sequence 51; service counts remain 51/51.
This checks read cancellation and exact transport recovery only. The
first custom-authority fixture failed 401 as above; a preceding local source
mistake (`WorkspaceClient` not imported in the bootstrap fixture) caused a
bridge-before-ready failure and was corrected before the protocol attempt.
Both are preserved, not counted as successful evidence.

SHA-256 at `26be8ad`: `kernel_client.rs`
`f8485e5955d51cb947df19ed36e49d35f360fec071887e3136141d78b35a018b`,
`secure_journal_read.rs`
`6401d20fbc20e5b07cc0a9721b859ea95a964e7417ff842f1b32ee3f47cf04ad`,
`secure_native_prepare.rs`
`213a571587ce0e36af33a8c369fadc7cca91cb488ca23167849079976502f6c1`,
and reference bridge
`4fa7792cd13099bba500961d55789b4e6da0e4753c37c4cc2651b5d50853c6f3`.
A clean detached checkout with Rust 1.89, task-local Cargo cache/target,
`--offline --locked`, the same explicit `PEERWORK_REFERENCE_ROOT` and
`PEERWORK_NODE_BIN` values above, passed focused
`cargo test -p peerwork-runtime secure_journal_read::tests` 2/2 and the
opt-in actual-service filter above 1/1 in 10.91 seconds. The bridge's
fresh state and pinned tracked build-input checks still apply. The ordinary
environment-unset test is vacuous for service evidence. Agent workflow
compliance remains unverified separately from these scripted business tests.

Paged custody and monotonic read discovery at exact SDK source
`5e0b56dd10c901f867617cb2b8fd48e0f4d03328` supersede the interim
inline-page v2 read store. Version 3 keeps bounded index metadata in the
protected state file and each exact HTTP page in a separately protected,
digest-and-length-pinned file. Open verifies every referenced page and cursor;
the future core verifier can consume one exact page at a time through a private
callback. A v2 index migrates only after validating its full old page sequence;
the v3 index is replaced last, so an interrupted migration can rewrite orphaned
page files from the still-authoritative v2 index. A changed page is rejected on
reopen. The reader now persists an accepted additive discovery update before
returning; a fresh client context with earlier D0 discovery cannot roll back
the protected reader after D1 added a feature. The focused D0→D1→D0 regression
asserts saved bytes and rollback refusal. The old 64 MiB and 2048-page
aggregate limits, and a first follow-up's 512 MiB whole-history cap, were
removed; the latter was caught before this evidence run.

This is bounded custody, not unlimited valid-history support. Each HTTP
response is currently capped at 32 MiB and the metadata index at 64 MiB;
the index is rewritten per appended page. A valid page exceeding the response
cap or a very large index still fails, and metadata append cost grows with
history. Adaptive fixed-snapshot page sizing/streamed response and segmented
index metadata remain implementation work. The future signed replay/activation
proof is also absent, so every saved page remains unverified transport evidence.

From a clean detached checkout at that exact SDK pin, Rust 1.89, task-local
Cargo cache/target, and `--offline --locked`, the focused
`cargo test -p peerwork-runtime secure_journal_read::tests` passed 4/4.
The opt-in
`cargo test -p peerwork-runtime actual_service_native_owner_bootstrap_lost_reply_exact_retry --offline --locked -- --nocapture`
passed 1/1 in 8.15 seconds with
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`
through the authorized localhost route. The fixture's established fresh
native-create/reply-loss and 51-commit, 50+1-page reopen assertions execute
against the paged schema; this is not >64 MiB or >2048-page stress evidence.
The first new unit fixture run failed because this environment's `tempdir()`
created mode 0755 while protected storage requires 0700; the fixture now sets
0700, then the four focused tests passed. No product protection was loosened.
SHA-256 at the exact detached pin: `secure_journal_read.rs`
`b853e73eff126bf5d0af39888b0091963d1c8b67bbc47134071c010993d256af`,
`secure_native_prepare.rs`
`213a571587ce0e36af33a8c369fadc7cca91cb488ca23167849079976502f6c1`,
`Cargo.lock` `48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.
This scripted test establishes transport behavior only; Agent workflow
compliance remains separately unverified.

Constant-size chain head and adaptive read checkpoint at exact SDK source
`165a07219ebb127df33214f38de6030c4528eebb` supersedes the v3 growing
index above. Version 4 stores only page count and a domain-separated SHA-256
chain head in the protected root; each exact response remains in a protected
per-page file. Append writes the new page before atomically advancing that
small root. An interrupted append leaves an ignored, overwritable orphan;
reopen scans saved pages once, checks cursor/checkpoint continuity and the
full chain before returning. The callback path checks those conditions again
over the bytes it passes to a future core verifier, and a caller must use its
successful completion before any proof decision. Version 2 or 3 indexes are
fully checked then migrated to v4. Focused tests cover v2→v3→v4, an orphan,
page mutation, callback refusal, and the persisted additive discovery pin.
The v4 root no longer grows with page count; append metadata work is bounded
per page, while reopen and explicit progress validation scan the history.

For a response over its configured budget, the private reader signs a fresh
canonical target at successively smaller limits (50→25→…→1). Once the first
page succeeds, later requests retain its exact checkpoint. A single page
over the maximum 32 MiB response budget still fails; full valid-input
compatibility for that case, policy-prefix pagination, and final replay proof
remain open. No >64 MiB or >2048-page stress run is claimed.

From a clean detached checkout at `165a072`, Rust 1.89 with task-local Cargo
cache/target and `--offline --locked` passed
`cargo test -p peerwork-runtime secure_journal_read::tests` 5/5. With
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`,
the authorized localhost opt-in
`cargo test -p peerwork-runtime actual_service_native_owner_bootstrap_lost_reply_exact_retry --offline --locked -- --nocapture`
passed 1/1 in 9.40 seconds. Its fresh actual service fixture still checks
native create/reply loss and 51-commit 50+1-page reopening; an additional
read sets its budget one byte below the known 50-commit response, observes a
smaller first page, then completes all 51 commits at sequence 51 and reopens
with identical progress. It does not prove secure action effects or Agent
workflow compliance. SHA-256 at the detached pin: `secure_journal_read.rs`
`ae94c112b381811b98dd14d5f51ad7d18a26ead2ae21126f7c9d5d70821421ad`,
`secure_native_prepare.rs`
`30ba6efbf1040032674d3e827c63277e167787ddfc3b8d7e9a9d4b8db045a63e`,
`transport.rs` `0ee771eda865ab63e977e9a2c43e4f3e18cac5896dd594f43d7b744fe782f437`,
and `Cargo.lock` `48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.

At follow-up source `c674424d8ad0600e921fb1808ded3c42fa6c1329`, the
selectable journal response/parser/page-file maximum increases from 32 MiB
to 64 MiB; command-response transport retains its separate 32 MiB bound.
This matches the protected page file's existing 64 MiB maximum. The pinned
service's `SECURE_LIMITS` has a 196,608-byte commit ceiling, at most 50
commits per page and a 32 MiB stored-artifact quota per workspace;
`readJournalSnapshot` includes effective policies plus those commits in the
response. Because response JSON framing adds bytes, the prior 32 MiB cap
could reject a near-quota valid response. The 64 MiB choice is a native
resource budget, not a proven protocol maximum; a single valid response over
it still fails with an explicit size error and needs further streaming design.
Exact source: `src/workspace-secure-contract.ts` lines 124–126,
`src/workspace-secure-store.ts` `storedArtifactBytes`/`assertWorkspaceCapacity`,
and `src/workspace-journal-snapshot.ts` `readJournalSnapshot` at reference
`f828b6c50a0a58d1e718af90f653b214adcc3328`. Rust 1.89 locked-offline
focused read tests pass 5/5 at a clean detached `c674424` checkout; the
actual 51-commit run above was at `165a072` and was not repeated for this
size-only edit. Source accounting gives a tighter pinned-service rationale:
the 32 MiB quota includes every stored secure commit and policy artifact for
the workspace, while the journal response selects at most 50 commits and
1,024 policies from those artifacts. The endpoint adds a fixed-size
checkpoint/envelope and at most 1,073 array separators. The store writes
those artifacts with `secureCanonical` (JSON string escaping and safe-integer
text), then the endpoint parses and emits the same JSON objects. This makes
the 64 MiB response budget conservatively larger than a valid response from
this pinned service, by source inference; it is not a promise for later
server versions or other read routes.

Empty-root discovery correction at exact SDK source
`957e9870b745ed437987a78ae9121cb1f5ee73a6`: the prior new-reader path
constructed a D0 document in memory but wrote no protected root until the
first page. Thus a reader with zero pages could reopen with a different
discovery and lacked an independent persisted continuity baseline. Open now
writes the protected v4 root before returning, including configured origin,
identity, authority, workspace and exact D0 discovery. An additive D1 update
advances that same root before use; D0 rollback is then rejected even before
the first GET. Rust 1.89 locked-offline focused read tests remain 5/5; the
clean-detached opt-in actual-service regression at this exact source passed
1/1 in 9.22 seconds with the same explicit reference root and Node24 binary
above. It now asserts the root exists while progress is zero pages, before
the delayed/cancelled GET. This is transport pin custody, not final journal
authority or an Agent workflow-compliance pass.

The first `957e987` actual-service assertion proved initial root persistence,
but did not itself exercise a D0→D1→D0 sequence with zero pages. At follow-up
source `d22da469206aa856581f59419ee7ba3ba78789c2`, the product open path
uses a private `open_pinned` implementation after deriving origin, discovery,
and identity from `KernelClient`/protected identity. Its focused zero-page
regression opens D0, confirms the root is written, opens additive D1, and
refuses a fresh D0 while retaining exact D1 discovery bytes. Rust 1.89
locked-offline focused reader tests passed 5/5. This is the smallest affected
regression for the rollback edge; the earlier actual-service pin proves the
separate HTTP/persistence path and was not repeated for this refactor.

Native PUBLIC owner-create checkpoint at exact SDK source
`cd75684ed58ebd5ceafdcb90128e7c8f6b3b8c4b`: the existing six pinned
collaboration presets now produce `visibility=PUBLIC` workspace objects, a
signed v3 genesis policy with epoch 0, and a signed plaintext BOOTSTRAP
commit. The low-level bootstrap proof checks mode/epoch/policy/owner/route,
the exact request hash and signed commit; it refuses a signed wrong mode or
malformed public operation. The runtime verifies its protected recipient
certificate against the local signer, saves the exact `{policy,commit}` bytes
before any POST, and re-verifies every saved row pin before each PUBLIC send.
There is no fabricated epoch key or keyring for this mode. Both PUBLIC and
PRIVATE packets remain PENDING after HTTP; no secure effect, activation or
Agent workflow-compliance decision follows from a 2xx response.

Tracked behavior source is reference HEAD
`f828b6c50a0a58d1e718af90f653b214adcc3328`,
`src/workspace-secure-agent.ts::create` (blob `4d0237d`),
`src/workspace-secure-client.ts::createCommit` (blob `e7acae2`), and
`src/workspace-secure-store.ts::bootstrap` (blob `0d0f0d1`). The opt-in test
uses fresh temporary state and the pinned real service bridge; TypeScript
fixture setup registers the owner identity, while Rust authors policy,
objects and commit. With explicit
`PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006`
and `PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node`,
the authorized localhost command
`cargo test --offline --locked -p peerwork-runtime secure_native_prepare::tests::actual_service_native_public_owner_bootstrap_lost_reply_exact_retry -- --exact --nocapture`
passed 1/1 from a clean detached checkout at `cd75684` in 1.63 seconds
after an 8.17-second Rust 1.89 build. It asserts service secure-commit
count 0 before and after native prepare, 1/head sequence 1 after the first
applied POST whose reply is dropped, and still 1/head sequence 1 after
reopening the protected journal and retrying the identical request. The
response is retained as an unverified observation; the row remains PENDING.
The exact-pin focused core bootstrap proof test also passed 1/1. The test
returns early without the reference environment, so ordinary runtime suite
results are not counted as actual-service evidence.

SHA-256 at this source: `bootstrap_objects.rs`
`340699813ed213fa8a3a4550acd7b50035b644f26408302ca6bccb8633899efa`,
`prepared_secure_bootstrap.rs`
`cfac7142ab619427628431bd41d1d93215fc02383a5fb8d13ae08c43079e5c2d`,
`prepared_secure_author.rs`
`d3d8c6a2a73a5c7463baf66d3609a11a3287fa7f3c713e4a56ef050946636b2b`,
`secure_intents.rs`
`f7e8bd731bae79ccc6c479e7bb2f3cd4dbecbccce2c085a7f8850d1ae9068f2f`,
`secure_native_prepare.rs`
`d47c6a1e45dccb1ef3d1f96603e6ae6026a288188941e7c1cf89ccfd3763900a`,
and `Cargo.lock`
`48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.
Structured/custom protocol owner-create, complete signed replay and
activation, public language bindings and all-platform execution remain open.

Structured PUBLIC owner-create checkpoint at exact SDK source
`54a412fe9063efde13b63b27641f47974bc25601` builds a v3
`structure_mode=STRUCTURED` genesis policy from the same signed six preset
objects, with an empty BOOTSTRAP DELTA envelope (those objects contain no
records or entity heads). The new core producer reuses the manifest-normalizing
protocol derivation and full structure-policy/object-binding validators. It
compares its output byte-equivalently, after canonicalization, to the vendored
tracked TypeScript `structurePolicyFromObjects` for both six presets and a
six-presets-plus-official-proposal-package custom object set. The signed
PUBLIC bootstrap verifier also rechecks the policy/object binding on saved
retry and rejects a re-signed extra protocol object absent from the policy.
This is a bounded object/policy integrity check, not complete secure replay.

The first direct oracle run failed because disclosure field array order was
derived from canonicalized manifest keys rather than JavaScript's insertion
order. A diagnostic rerun located the first difference at
`/disclosure/0/fields/0`; the producer now walks raw manifest field order.
A second diagnostic run still differed because the test canonicalized the
input object wire before derivation; the fixture now retains exact
`JSON.stringify` input bytes. These are preserved implementation/test
corrections, not extra pass sampling. A separate initial focused run was
interrupted before tests by concurrent core-owned `ReplayFacts.recoveries`
source WIP (E0063), then core supplied a stable compile window.

From a clean detached `54a412f` checkout with Rust 1.89 and task-local Cargo
cache/target, `cargo test --offline --locked -p peerwork-core
genesis_structure_policy::tests --lib` passed 2/2 and the affected signed
bootstrap proof test passed 1/1. With the explicit reference root and Node24
path above, the authorized localhost opt-in
`cargo test --offline --locked -p peerwork-runtime
secure_native_prepare::tests::actual_service_native_structured_public_owner_bootstrap_lost_reply_exact_retry
-- --exact --nocapture` passed 1/1 in 1.98 seconds after a 9.15-second build.
It asserts policy has six derived protocols and commit DELTA mode, zero
service commits before and after prepare, one/head sequence 1 after the first
applied POST with dropped reply, and still one after protected-journal reopen
and exact-byte retry. The native secure intent remains PENDING. The opt-in
test returns early without the reference environment; an ordinary suite pass
is not actual-service evidence. No Agent workflow-compliance claim follows.

The TypeScript structure source is reference HEAD `f828b6c` blob
`ad73e947faf6f9edf230fca6e3862cd4be13c5e3`. SHA-256 at this SDK pin:
`genesis_structure_policy.rs`
`825482073aee9ff0a59e7c6b897550aaf4703dc2e65793451222a44a90fdde1b`,
`prepared_secure_bootstrap.rs`
`bfde07e8219618e12962672150c04835432db751b1a4b177f2382ef077975bb7`,
`secure_native_prepare.rs`
`5288a9afceaa177f2cb8e579befb8898738c7d32a6dcb6ad207a8f7fb123de10`,
`generate-genesis-structure-vectors.mjs`
`52d3f96123168577384708b3902430dcf8b8743b936e86a728a9f5051b5172ae`,
`genesis-structure-vectors.json`
`ba20230de7ac9526406894008a95fadbdf25c50b1900bf8e1e0f3dbb258318b3`,
and unchanged `Cargo.lock`
`48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.
The custom package case proves policy derivation only; native owner-create
has not yet authored and submitted that custom package. `keep_encrypted`,
coordination options, PRIVATE structured creation, complete replay and
activation, language façades and OS matrix remain required work.

Optional native PUBLIC owner-create checkpoint at exact SDK source
`ab5591ad74c057808026ac826b3bf429567837fc` adds the pinned coordination
v1/v2 preset and object-derived `keep_encrypted` choices. The owner-create
source contract is the tracked `SecureAgentClient.create` at reference HEAD
`f828b6c50a0a58d1e718af90f653b214adcc3328`: six default presets,
optional coordination v1/v2, and optional structured field protection.
Custom manifests are not a genesis input in that path; custom package
onboarding still requires native stage/install and verified use. The native
option methods remain private, and signed genesis proof is pre-submit only.

The fixed detached checkout used Rust 1.89, `--offline --locked`, task-local
Cargo cache/target, `PEERWORK_REFERENCE_ROOT` set to the exact reference
worktree above, and `PEERWORK_NODE_BIN` set to Node 24.20.0. The direct
TypeScript/Rust structure-policy oracle passed 3 cases: six defaults,
six plus official proposal package, and one encrypted `discussion.message`
`author` field. The explicit localhost tests
`actual_service_native_coordinated_public_owner_bootstrap_lost_reply_exact_retry`
and `actual_service_native_keep_encrypted_owner_bootstrap_lost_reply_exact_retry`
passed 1/1 each (the former runs both coordination versions). Each fresh
run used `cargo test -p peerwork-runtime --offline --locked <exact-test-name>
-- --nocapture` with the two reference environment variables set above;
the oracle used `cargo test -p peerwork-core --offline --locked
genesis_structure_policy::tests::exact_tracked_typescript_default_and_custom_declarations`.
Each fresh
service begins at zero commits; preparation does not POST; the first POST
applies then loses its reply; protected-journal reopen and exact-byte retry
leave one commit/head sequence 1. The encrypted-field test checks the signed
policy marks `author` as `e2ee` and removes it from disclosure. The native
intent remains PENDING without complete secure replay. The opt-in tests
return early if the reference root is absent; an ordinary suite result does
not prove service execution.

The first committed `2cfbc35` encrypted-field service run failed before POST:
the test selected `operation.objects[0]` (workspace) as a protocol digest.
A single diagnostic confirmed the requested choice was invalid; `ab5591a`
corrects the fixture to `objects[1]` (first protocol). This is a test-input
correction, not a service acceptance defect. The exact corrected pin passed
both service tests. Business correctness here is bounded to service admission
and idempotent retry; Agent workflow-entry compliance was not exercised or
inferred from these tests.

SHA-256 at `ab5591a`: coordination fixture
`9b32cb924a913425e06c82a8e3d3188560fe46af5bdded21f428bcc05f315158`,
its generator `3eb741f3c1790a4f3ad86081b43b80ec565dcd636bf65ce0eec5c760ae5980e4`,
genesis vectors `d1066fc5398a1dd769fc85dc13b1aba1f2dd948f217ac69faaff1bfe812a959e`,
genesis generator `ce3a9654233c678532121abd1c96655b2769aa55dfa4ef358595519c7c99b14a`,
`bootstrap_objects.rs` `c0bf7c662b84b76157490522e454b593137eb5de504566eebfb0ccd766f492e3`,
`genesis_structure_policy.rs` `c89103285c0340829d30593dc2b24042e0819b9b20c528297fc9fb4b37a51414`,
`secure_native_prepare.rs` `1b92e7413e336af67007b72d2baaa0746f5bc20bc4f2bd52c0dbf9d7eb5d0aa6`,
and unchanged `Cargo.lock`
`48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.
PRIVATE structured/coordination creation, custom package stage/install,
complete replay and activation, public three-language surfaces, and actual
OS release matrix remain open.

PRIVATE structured owner-create checkpoint at exact SDK source
`64dc1f72e99c6e532189e91341473d36c0756991` extends the native
six-preset producer with a signed v3 `STRUCTURED` policy and empty genesis
DELTA, plus validated `keep_encrypted` choices. PRIVATE mode stages one
protected epoch-1 key before signing and persists the exact encrypted
request before HTTP. Its caller remains private and its pending key is not
promoted by a service response. From a clean detached `64dc1f7` checkout,
Rust 1.89 `cargo test -p peerwork-runtime --offline --locked
actual_service_native_private_structured_bootstrap_exact_retry -- --nocapture`
passed 1/1 with the explicit reference/Node environment above. The fresh
tracked service had zero commits before and after preparation; the signed
policy marks `discussion.message.author` `e2ee`; the first applied POST lost
its reply; protected keyring and journal reopened and exact-byte retry left
one commit/head sequence 1. The saved intent remains PENDING. Bounded
independent source review found no mode/context/key mismatch, but reopened
pre-submit verification does not independently rederive the signed structure
policy from decrypted BOOTSTRAP objects; complete core replay must close that
semantic binding before public success. Source SHA-256:
`secure_native_prepare.rs`
`98b2a28be73eeb010fbf4f2cda953409b98f14efe546f651fedaba4b079d41ce`,
unchanged lock `48775117e96fe4cba67314559398d3d08c75fc211952e22473ceacc389003f17`.
No Agent workflow entry test ran; workflow compliance is unverified despite
the business-path service result. Coordination combined with PRIVATE mode,
custom package stage/install, complete replay/activation and public bindings
remain open.

Exact custom-package material custody checkpoint `d61efa4e029db98e12a05989698a19e7faab1ac6`
adds a private protected store for the caller's exact package material bytes
and proposed source-checkpoint bytes, pinned to configured origin, workspace,
owner actor and owner key. It writes once, permits only exact-byte repeat,
rejects changed pins/material and damaged framed bytes on reopen, and exposes
the saved bytes only through an internal callback under the state lock. Its
8 MiB material/8 KiB checkpoint caps are local intake bounds; the tracked
compiler's exact package material and part limits still need to verify those
bytes before staging. The store neither compiles/splits parts nor signs,
posts, marks accepted, or proves a checkpoint. An unkeyed checksum detects
accidental/local corruption but supplies no signed authority.

From the clean detached `d61efa4` checkout with Rust 1.89, task-local Cargo
cache/target, and source-built ICU4C from the pinned dependency, `cargo test
-p peerwork-runtime --offline --locked secure_package_pending::tests --lib`
passed 3/3 in 2m01s (first clean ICU build). Tests cover exact restart,
same-input idempotence, changed origin/material refusal, pre-write resource
refusal, and corrupted-file refusal. This is a local-state test; no service,
Agent entry workflow, or installation test ran, so their compliance and
business-effect evidence are unverified at this checkpoint. Source SHA-256:
`secure_package_pending.rs`
`d5cb9834c2bfdb449486d68accad26284936e73862d2a4ec976232de2d2c8336`,
runtime `lib.rs`
`7851281ad69a210585d2284a829583b38408892ebbf4bf598d056d150196ff37`,
and `Cargo.lock`
`9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.

Core's intended production handoff is a private-constructor package-stage
plan that binds the compiled closure, exact source/part IDs and hashes,
signed action intent and expected head to a complete authenticated
checkpoint. Runtime will persist each exact authored stage packet before
POST and reverify it on retry; a separate install plan must bind the completed
staged sequence and resulting protocol/instance/structure state. Neither
proof exists yet, so custom stage/install and final replay remain open.

The local intake caps above cover tracked source-valid package input: pinned
`protocol-package-closure.ts` sets `wireBytes=6*1024*1024`, and pinned
`workspace-protocol-package-source.ts` sets `materialBytes=wireBytes+32*6*8192+64*1024`
= 7,929,856 bytes, below the store's 8,388,608-byte material cap. The
source checkpoint has exactly seven bounded fields (three 43-character IDs,
two 64-character digests, one safe integer and `v`), well below the 8 KiB
checkpoint cap. These are local resource checks; a complete compiler/source
proof still has to reject malformed or noncanonical material.

PRIVATE coordination owner-create checkpoint at exact SDK source
`d2d0a49c97de74e014f61baa2d1606db594d1553` adds the tracked seventh
coordination preset and v1/v2 policy choice to the private structured
producer. It stages a protected epoch-1 key and one exact signed encrypted
BOOTSTRAP before HTTP; no response promotes that key. With the explicit
reference root/Node24 environment above, clean detached `d2d0a49`
`cargo test -p peerwork-runtime --offline --locked
actual_service_native_private_coordinated_bootstrap_exact_retry -- --nocapture`
passed 1/1 (two fresh service runs, one for each version). For each version,
service commits/head were 0 before and after prepare, 1 after the first
applied POST whose reply was lost, and still 1 after protected keyring+journal
reopen and exact retry. The signed policy contains seven protocols, the
versioned coordination declaration and the selected encrypted author field;
the saved intent remains PENDING. This establishes bounded admission/retry,
not verified action effects, activation, or Agent workflow compliance.
Source SHA-256: `secure_native_prepare.rs`
`0e0c10bdaf97bf0b83711369c70c62305a8b0455bd3d9079f90fcc4a8fb562eb`,
`Cargo.lock` `9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.

Private package-source construction is registered at exact SDK
`ed55f72e23bcef6a26d3df45a726da17dead1430`, following the builder
`56ae173` and canonical source-ID helper `11f1257`. It validates a
caller-supplied source checkpoint, normalizes and compiles the retained
package material through the existing compiler, then produces canonical
source proof and exact bounded part objects. It does not authenticate the
checkpoint or authorize a stage POST, install, acceptance, or final effect.
The direct pinned TypeScript official proposal-package vector and the existing
Rust source verifier round-trip passed 1/1 with Rust 1.89 `cargo test -p
peerwork-core --lib prepared_package_source --offline --locked`; the
registration commit changes only `lib.rs` from the source tree used for that
focused test. The fixture generator is
`conformance/generate-protocol-package-source-vectors.mjs` SHA-256
`32bee9bdcc2333420065168db46fc7e35e8b3ad4a226df05919bacb03d1411f8`,
vectors SHA-256 `c85b48ec735e277349d0d1cbddb8b1157673943db211a0ec29e2bb4689d3dc7a`,
builder source SHA-256 `adac880d0f0f61a6a6986b882bba34f851c683d7a1810de5b72736bf6b05de4c`,
internal verifier/helper SHA-256 `5082d59c0a965b80fb56d3a9fec7a30dff759374ef2ef14f2c86309ee25bd66e`,
registration `lib.rs` SHA-256 `653f7a7743c7f7c11b184e9812e8035ae2e4b283c5a9197039f2489bc292b7c0`,
and lock SHA-256 `9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.
The vendored TypeScript oracle source is `conformance/reference/src/workspace-protocol-package-source.ts`
SHA-256 `18ad9a8529302c48148a73b8d1c2126fa74a9be94e3c84bd69dc1360e613d459`.
This is a source/byte-parity test only; no service action, installed language
client, or Agent entry workflow ran, so business admission and workflow
compliance are unverified for this checkpoint.

A separate private ACTION device-delegation scope resolver is source-committed
at `cb21dff`. Its input contract requires the signed commit context and
selected policy payload to come from future complete replay; the resolver
checks exact embedded-versus-supplied delegation, delegation signature,
device certificate, principal membership, issue-time validity, requested
action and instance intersection, then returns only principal and effective
scope facts. It does not authenticate policy selection, authorize a POST,
prove a journal or emit final action effects. Thirteen direct pinned TypeScript
`resolveSecureAuthor` cases cover valid direct/delegated resolution, expired
delegation/certificate, principal or delegated action denial, a tampered
signed scope and wrong device actor. Follow-up `e8c9e43` adds global
principal/device scopes, both expires-at-issue boundaries and duplicate signed
actions. The focused Rust1.89 locked-offline test
`cargo test -p peerwork-core --lib secure_action_delegation --offline --locked`
passed 1/1 at the stable source window, including effective role/capability
intersection. The first compile failed because the new module referenced a
non-direct `p256` dependency; it now uses the existing HPKE P-256 decoder.
A later compile was interrupted by unrelated in-progress `secure_replay.rs`
`E0063` until its owner completed `ReplayFacts`; the stable focused rerun
passed. Source SHA-256 `5a678c2611ed658fdad4f7b08ab3feec2c1fd0479339b4ea9c4e149965e1c558`,
generator SHA-256 `3ff4337acfd918a4f34e570a4e49235f94e0082795dea8777739562f2577213d`,
vector SHA-256 `624d8c354b4aaa6103e66aaf78b8f0e8fbea273bf11b7b4a24533b9a936c8863`,
and lock SHA-256 `9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.
Core's private registration is `ca30b36`; its bounded peer source review found
no concrete mismatch in the initial eight-case resolver slice, then requested
the five boundary vectors above. Its replay consumer remains a separate
checkpoint. No Agent
entry workflow ran, so workflow compliance is unverified here; business
acceptance and final effects are likewise unverified.

Exact ACTION input-reference resolution is source-committed at `c1cb4ba`
with a malformed-reference parity correction at `560e01d`
as another private replay input. It takes caller-supplied authenticated prior
objects plus workspace/instance/protocol pins and resolves up to 32 immutable
references into interpreter inputs, including the protected JSON payload and
INSTANCE versus WORKSPACE scope. It rejects duplicate, missing, wrong-revision,
cross-workspace and `participation.request` references. Eleven direct pinned
TypeScript `prepareSecureAction` cases passed the focused Rust1.89 locked-offline
`cargo test -p peerwork-core --lib secure_action_inputs --offline --locked`
test 1/1 at the stable registered source window. The test includes a valid
workspace-scope reference and a raw UTF-16 JSON payload. The first nine-case
run did not exercise malformed ID/revision inputs; direct TypeScript checks
then showed these fail at lookup with `REFERENCE_NOT_FOUND`, and the corrected
eleven-case focused rerun passed 1/1. Source SHA-256
`61457928b5aea4eb41f2d8b8569b2241ded52f3ebb4a0893f6ce4928bbceef7b`,
generator SHA-256 `5577292ff94bf78b5c36360510003e1d4aecdb59417b9fa075f1098b18ef574c`,
vector SHA-256 `1c1f390eec30c25a6dc465462880fa4a748dfbfa4c4817c40d3a6570f8bfd680`,
vendored TypeScript engine SHA-256
`f418278a29734baf46627319a23219e12d4c12901fe94498c3113675273ca809`,
and lock SHA-256 `9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.
Core owns the separate private registration and signed replay consumer. No
Agent entry flow or final effect was exercised; workflow compliance and
business acceptance remain unverified for this module.

The disjoint ACTION relation resolver is source-committed at `7e78469`.
It consumes previously interpreted relation specifications, authenticated
prior objects, and independently assigned record/slot facts; it substitutes
produced targets, requires an existing or assigned target revision, derives
the source-matched relation ID, and increments a prior relation revision.
Four direct pinned TypeScript `prepareSecureAction` vectors cover an existing
target, a forward produced target, a prior relation at revision 2, and a
Unicode relation kind/JSON-stringified ID. The focused Rust 1.89 locked-offline
`cargo test -p peerwork-core --lib secure_action_relations --offline --locked`
passed 1/1 with core's private registration on disk. Module SHA-256
`e0c48aa2aa5e51a76c50516b8f6920fe2c38a73d58c181b209c5b43648375eff`,
generator SHA-256 `959d575c06dee26dfc902ac9e587c14b45234e4388582e3b8c7aeec4cfa1caa2`,
vector SHA-256 `b929ac57f65f261f97f6a8c6f6248fa0ce96d6fd8bcadce63c5cf2a041a60980`,
vendored TypeScript engine SHA-256
`f418278a29734baf46627319a23219e12d4c12901fe94498c3113675273ca809`,
and lock SHA-256 `9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.
The test establishes this narrow object-construction parity; core's private
registration and replay consumer are separate checkpoints. No complete
ACTION proof, Agent entry workflow, or real service effect ran, so final
business behavior and workflow compliance are unverified here.
