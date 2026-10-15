# T103: real multi-output PUBLIC→PRIVATE conversion

**PASS for the one genuine tiny API chain; >64MiB history remains UNPROVEN.** The first actual T103 fixture completed both conversions with unchanged currentf828, the accepted finite8×16 manifest and the official one-item planner. T100 remains FAILED/incomplete and immutable. No Agent ran: workflow compliance is untested separately from scripted API correctness. No bulk/native SDK test/build/product edit, DB seed, quota/rate override, old runtime, other private profile, remote/prod/auth or release action occurred.

Actual runtime source is `e3817d5`, based on SDKd71139c; later `728e71f` adds OFFLINE analysis only. `tests/multi-output-t103/tiny.mjs:25–26` visibly wraps actual `legacy.submit` and `agent.post` in `PostAdmission.run` BEFORE public request/proof/15s-timeout construction. Every legacy command and conversion-context post uses those wrappers. The fetch wrapper:30 only forwards/observes; it never queues. Host mechanically gates HTTP on syntax and the accepted deterministic T102 ordering check. Sourcef828 and its204 compiled-file closure `6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc` are checked before service execution. The one-item planner is the guarded official compiled source with only batch64→1 and relocated import URLs; validation, signer, crypto and server limits stay intact.

A sole creator makes NEW0700 `.test-data/t103-runtime`; an exclusive0600 selected-owner.pem is file- and parent-fsynced. Actual producer imports that SAME file with Node createPrivateKey/reference signingIdentityFromKey before business, and publishes only selected path/actor/key/origin/phase/pending metadata. Before PRIVATE it closes the agent, explicitly reopens that selected file and saved public client state with a fresh agent handle, and asserts identical actor/key. `signer-reopened-before-private.json` records this actual reopen. No replacement identity is generated on reopen. Final metadata is CONVERTED_PRIVATE/pending[]. Private PEM/keyring/client-state files and their hashes are excluded from logs/Git/manifest. The fresh selected identity remains available for authorized same-fixture recovery.

The genuine chain is PUBLIC legacy workspace.create, protocol.publish, instance.create, explicit Owner WRITE grant for seed/many, seed, and TWO many actions using the real prior seed record/revision in body and exact_input_refs. Each produces8 records and128 unique relations. Accounting/source snapshots are persisted before each assertion:

| Phase | Logical accounted bytes | Retained rows/source objects |
| --- | ---: | ---: |
| Bootstrap | 4,638 | 6 |
| Fixed setup incl seed | 52,381 | 22 |
| First many | 107,902 | 161 |
| Second many | 163,423 | 300 |

Each repeat adds **55,521 logical bytes/139 rows**, not multiplied bootstrap rows. The final legacy source contains17 records and256 relations. Source canonical bytes, logical row accounting, HTTP body bytes and signed artifact bytes are separate domains.

One-item PUBLIC conversion completes300 MIGRATE commits plus FINISH at sequence301. Full direct verifyJournal matches the signed checkpoint and agent's entire300-object result. PRIVATE completes301 additional MIGRATE commits plus FINISH at sequence603, replaying601 MIGRATE operations across both archive levels and returning601 objects (original300 plus301 archived PUBLIC commits). Full direct verifyJournal matches checkpoint and entire agent result. Separate OFFLINE checks bind every original300 source object exactly to the accepted PUBLIC plaintext, and every PUBLIC commit to a unique PRIVATE signed migration descriptor. No cipher key extraction is used for that offline coverage check.

Actual source max value37,759 bytes is below98,304; largest PUBLIC/PRIVATE signed commits are38,863/53,299 below196,608; largest policy1,224. All13 snapshot pages have zero fragments. This tiny case therefore uses zero decoded fragment bytes and one nested PUBLIC archive level. PUBLIC signed commits total470,056, responses180,175 and policy1,159 (stored651,390). PRIVATE final commits total1,068,653, responses180,990 and both policies2,383 (stored1,252,026). Configured secure global512MiB checks remain unchanged and all actual stages/FINISH accept; actual transient peak was not independently measured. Legacy source163,423/300 is far below current NORMAL9MiB/49,000; normal PUBLIC-FINISH event/outbox capacity was genuinely accepted. No large-limit pass follows from these small numbers.

## Execution, caller waits and corrected rate scope

Original owned handle47243 exits0: **17:16:42.989168–17:22:03.924939UTC,320.935773s**. PUBLIC137.307s; PRIVATE182.387s. There are613 successful POSTs (10×201,603×200),40 successful GETs, no non-success HTTP response. Exactly601 conversion-page POSTs and2 FINISH POSTs occur. Caller admission waits total**299.530s**, including multiple actual56–57s waits followed by successful requests; remainder21.405773s is aggregate non-wait work, not a benchmark or isolated network/crypto duration. Service/projector/client close is invoked and server close awaited in finally; service-exit records closed/waited. No separate PID-absence probe is claimed. Final service counters are1 retained ordinary command and302 secure commits after normal PRIVATE purge; this is not a claim that all initial legacy rows remain in the live tables.

**Rate-scope correction:** earlier messages incorrectly called120/min a hard conversion floor. `workspace-http.ts:63–68` admits secure bootstrap/append but conversion begin/pages/FINISH instead use authorizedRead. `workspace-kernel.ts:739` checks signed proof/nonce capacity, not that per-minute admission. Ordinary command admission remains120/min. Our explicitly selected90/min CALLER policy was preserved and caused the measured wait; it is not a source-imposed conversion minimum or evidence of unlimited throughput. No fast rerun occurred. The previously stated6h29 source floor is retracted. The old8h39 figure was only an obsolete caller model; corrected finite-model POST accounting below includes all N legacy writes and gives a different caller-only estimate.

## Genuine wire pairs and capacity limitation

`relation-wire-pairs.json` maps actual legacy descriptor→signed PUBLIC commit→signed PRIVATE commit. Measured per-kind wire ranges:

| Kind | PUBLIC | PRIVATE |
| --- | ---: | ---: |
| Relation | 1,355–1,359 | 3,270–3,278 |
| Record | 1,501 | 3,467 |
| Repeat command | 4,322 | 7,224 |
| Event | 1,266 | 3,151 |
| Outbox | 3,335 | 5,910 |

The first offline accounting assertion exited1 (55,513 versus55,521): conversion source strips public_outbox.published, while quota accounting retains its8-byte integer. Original error/output remain. A trailing cat misleadingly made the tool wrapper exit0; the Node assertion exit1 is explicitly recorded. The changed scalar calculation adds that source-proven8-byte accounting field; subprocess status is now captured before assertion. Corrected offline checks exit0 without another service run. This test-oracle/domain error does not invalidate the actual HTTP pass or reset T100 failures.

**No complete finite tuple is proved.** Planning uses minimum actual wire sizes under the fixed-shape monotone-length hypothesis and conservative numeric-string accounting. The quota-only N168 model would visit70,123 objects under recursive format inspection and is rejected, despite fitting nominal quota. The source-backed format count is3L+1: original L objects +L+1 PUBLIC archives +L recursively visited source objects, where L=22+139N. `workspace-secure-format-ceiling.ts:21–41` and public-format collect/inflate limit65,536 visits, depth8 and8 fragment layers. CandidateN150 gives L20,872,62,617 visits/depth1; actual tiny reconstruction has901 visits. Minimum length-model N is146; N150 gives margin: PRIVATE subset69,387,150 versus67,108,864, logical source model8,424,723 versus9,437,184, rows20,874 versus49,000. However future1024/2048-byte wire-growth allowances,8,192 normal-FINISH reservation and global peak model469,465,140 versus536,870,912 are **planning reservations, not a complete source-derived upper proof**. Future fragment absence/decoded budget must be bounded from that final wire proof, not inferred from this zero-fragment sample. Tuple_proven remains false and no large history exists.

Next precise prerequisite is a bounded exact finite wire/global/FINISH/format upper proof for this smaller candidate, followed only if authorized by an actual large execution. The model entails41,905 total POSTs including setup/writes; at the preserved90/min caller policy its aligned-window lower wait model is27,900s (7h45m), not a required service floor. Real cost also includes signing, storage, snapshot paging and repeated verification; no bulk starts in this package. A future large oracle must use direct full signed verification rather than mistake the ordinary TS32MiB collector ceiling for a native failure.

Evidence uses existing `.test-data/t103/evidence.json` path/hash/size schema. Public artifacts, commands, source pins, first offline failure/corrected results and actual terminals are retained; private keys, client state and SQLite DB files are excluded. Ledger start17:14; visible actual wiring freeze17:16:19 within3min; first actual stage timestamps above. Original T100/runtime interruptions remain separate; no T103 business retry occurred. Unmeasured prep/review subdurations are not reconstructed; root acceptance/integration timing is root-owned. All task handles are closed.
