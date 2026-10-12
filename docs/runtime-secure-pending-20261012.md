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
TypeScript service checkout `f828b6c`, and `PEERWORK_REFERENCE_ROOT` set.
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
