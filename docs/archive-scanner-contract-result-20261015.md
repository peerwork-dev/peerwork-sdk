# T058: archive expansion and scanner contract

Read-only finding on SDK `b7e37ea` and reference `f828b6c50a0a58d1e718af90f653b214adcc3328`: **fragment inflation and the nested protocol-format walk have matching source bounds. The native 102,400-commit header-scanner cap has no matching cap in the reference direct verifier. A genuine supported history rejected by that cap has not been demonstrated.** This does not close archived-prefix/scanner acceptance or establish a defect. No code, test, build, fixture, database, network or remote operation ran.

| Domain | Native exact guard / location | Reference source contract / conclusion |
| --- | --- | --- |
| One HTTP journal response | transport.rs:11,248 and secure_journal_read.rs:27,383: at most **64 MiB** | Service page size is **50 commits** (`workspace-secure-contract.ts:126`, journal snapshot route); policies are separate page content. A 64 MiB response is not the collection budget or expanded replay size. No universal page-size bound for every historical stock was derived here. |
| Retained canonical input collection | secure_verified_read.rs:21–51,130–145,410–462: default **64 MiB**, configurable positive u64 converted to usize; checked addition; **1,024 policies**, commit rows use **usize::MAX** | Reference `workspace-journal-collect.ts:8–28` defaults to **2,048 pages × 50**, and separately caps collected canonical bytes at **32 MiB**. Its collector is not the direct verification contract or a large-history oracle. T047 already tested configurable native byte refusal/acceptance; no repeat needed. |
| Archived PUBLIC prefix restoration | secure_replay.rs:1283–1456: signed contiguous PRIVATE MIGRATE pages, exact source checkpoint, Owner/signature/epoch, decrypted canonical operation; inflate source objects; require unique PUBLIC originals **1..source_sequence**, then prepend originals to received commits | `workspace-secure-client.ts:97–111` performs corresponding restoration and exact coverage before verifying headers. There is **no separate native aggregate byte cap** in this restore function; it allocates the restored prefix in addition to retained incoming wires. The configurable collection budget only counted incoming canonical policies/commits. Those two sizes cannot be equated. |
| Header scanner after restoration | secure_chain.rs:16–19,98–102: **1,024 policies / 102,400 commits**; each commit canonical wire **196,608 bytes**, parser depth **64** | Reference `verifyPolicyChain:53` matches the 1,024 policy cap; `verifyJournalHeaders:114–123` checks each signed commit/link and **196,608-byte** wire, with **no explicit total commit-count limit**. Native replay invokes the scanner on **restored** wires (`secure_replay.rs:1530–1540`). Incoming count alone does not establish the restored count fits. |
| Fragment decoding | migration_fragments.rs:14–15,236–327: nonempty part ≤**16,384 bytes**, count **1..2,048**, aggregate actual decoded fragment bytes ≤**32 MiB**, exact descriptors/index/count/provenance/canonical JSON, parser depth **2,048** | `workspace-secure-migration.ts:6–18` has the same part/count/decoded aggregate, uniqueness and canonical checks. Ordinary non-fragment objects do not consume this decoded-fragment aggregate. This is a **source-compatible bound**, not evidence all archive allocations are ≤32 MiB. Native parser depth 2,048 has no explicit matching JS JSON.parse depth bound; source reachability of a deeper legitimate object remains unproven. |
| Nested archive/format inspection | migration_fragments.rs:360–398,464–499: recursive depth ≤**8**, cumulative visited objects ≤**65,536**, at most **8 fragment-inflation layers**, cumulative encoded-data estimate ceil(base64 characters ×3/4) ≤**32 MiB** | Exact matching rules in `workspace-secure-format-ceiling.ts:21–45`, including the estimated-byte accounting distinct from the decoder's actual bytes. This closes a **source-contract discriminator**: these values are shared behavior, not a native-only restriction. It is a format-ceiling walk, not the general signed-chain scanner; do not apply its 65,536 limit as a blanket commit cap. |
| Recovery recursion | secure_replay.rs:1525–1528: depth ≤**32** | `workspace-secure-client.ts:169` also requires recoveryDepth≤32. This is not archive depth, collection bytes or source wire size. |

Service source constraints are separate: `workspace-secure-store.ts:542,581,667` limits signed policy/commit wires to 196,608 bytes; `SECURE_LIMITS.objectBytes` is 98,304. The ordinary secure workspace is 32 MiB, secure global storage 512 MiB; conversion staging/activation uses the global path (`store:663,667,670`). T050/T053/T055 demonstrated finite actual producers, not a universal restored-count or decoded-memory theorem. Fresh legacy writes have the current 9 MiB/49,000 normal accounting allowance; historical stock admission and PUBLIC activation accounting require their own provenance/guards, as recorded in T055. Global storage allowance alone proves neither scanner reachability nor source compatibility.

The independent remaining issue is therefore precise: **native expands an authenticated archived prefix before applying a fixed 102,400-entry scanner limit; reference direct verification has no corresponding explicit entry limit, and the current producer work has not proved the expanded source can exceed it.** There is no concrete supported rejection to label a product failure, and no justified blanket limit increase. Likewise parser-depth compatibility is unproven, rather than a demonstrated unsupported history.

Smallest next actual regression: reuse the now-demonstrated T055 *fresh current public API* producer (legacy PUBLIC create, two Owner view changes, real one-item PUBLIC conversion, PRIVATE conversion). Its PRIVATE transport has **14 current commits**, while independent restoration yields **27 total signed commits** (13 archived PUBLIC +14 current). Generate a fresh synthetic source through that same API; pin incoming canonical byte/count values and independently verified source checkpoint, then pass the exact signed pages/current synthetic keyring through the existing native verified-read/replay path. Require restored sequence/head/full logical objects match reference, original 13 PUBLIC links/signatures are checked, fresh public read/reopen is idempotent, and a changed/missing archived original refuses before releasing a verified result. This is a small **expanded-prefix accounting baseline**, not a 102,400-boundary or >64 MiB pass; do not manufacture signatures/history or use the 32 MiB collector as the large oracle. A real scanner-boundary acceptance needs a separately proven legal producer with **restored**, not merely downloaded, count beyond 102,400. Source-compatible fragment/format guard values can reuse the existing parity/unit tests; no new bulk family is justified by this audit.

T043/T045/T047 and the original plan's archive/scanner obligations remain separately recorded; T050/T053/T055 large-witness status is unchanged. This audit started 12:12:20 UTC; targeted findings were sent by 12:14. No runtime timing or acceptance is inferred from source inspection.

Exact inspected source hashes follow (generated directly from the named files):

- SDK crates/core/src/secure_chain.rs: `c427fc97d79f9174a9bc813e95d15058dec2895c97b8f0d3b858612363f67765`

- SDK crates/core/src/secure_replay.rs: `313798ed5d97548fb17326409cf3ea1136e72b9b7ea85d5e45278c6d4fdd83d1`

- SDK crates/core/src/migration_fragments.rs: `cc247bfe8da766fbab242dc4b9469faca85dade52870d5f82be97a77da939dd5`

- SDK crates/runtime/src/secure_verified_read.rs: `e91d3bcfdf0d833301f438729b2eacc315b5d37f7620a9e3129f25c0927346fe`

- SDK crates/runtime/src/secure_journal_read.rs: `53ef33dd89fdc3f1d900ba58e4d679cfa45fbd8988fdbe5dfb8597985d3ca66b`

- SDK crates/runtime/src/transport.rs: `719af07ec9d4fd49ab074f7d1fa9207d051dca5f05ce7bbb59464b6d5903824c`

- Reference src/workspace-secure-contract.ts: `115400201d7afa2d3913d066929896256c031acf63c35a79ed0e4e9a42a9cde0`

- Reference src/workspace-secure-client.ts: `35d33c4cbe271af7f27a886c33daadc2f6e28a70d11a8e917bfc9c1a4a1bc5ce`

- Reference src/workspace-secure-migration.ts: `be612b50305796a88dd1de90c1213bf7518b8bf74e7a6fb41067f2b9c67a8f57`

- Reference src/workspace-secure-format-ceiling.ts: `629d4c8dfcbe012307b07d6efdaadc7beb78036bd883a3198a7f3a92d9374a38`

- Reference src/workspace-journal-collect.ts: `767c75ff779157d05ed7e340a22e43b090879415f5a5d08e15c57a61ab744885`

- Reference src/workspace-secure-store.ts: `61033155cfb0b042497703a39329e1d981d571ba9c87e5b8eabd3d8c01643dd0`
