# T033 installed PUBLIC action recovery across scope revocation

Both named dispositions PASS on immutable source `7dd319713708c417e5bc6026be1cf32ca598cfde`, artifact manifest `85aa7882e72280b896fc3d127627265bc9dbcecd0a2df51c9af40818b5433ea6` and source manifest `9e2900b85d4097ab3e3b0e9f403f5a56ff22442a3e90df857e6f83f91d083e0e`. This is scripted, operator-synthetic installed CLI evidence; no SDK rebuild, production change, Agent workflow or acquisition claim.

The member uses public native recipient publication, actor/key-pinned certificate discovery, public admission and action APIs. The declared synthetic TS Owner uses f828 public `memberScopes`/`setMemberScopes` to replace only that member's write scopes with `[]`. Full signed native reads and retained service policy artifacts bind the new policy hash; membership, certificates, Owner, keys and epoch remain unchanged. Native identity secrets are never read/exported.

| Disposition | Observed result after revocation |
|---|---|
| Applied, unresolved original action | Original command reconciles to historical ACCEPTED sequence 3, while current signed read is sequence 4 with empty scopes. Exact original receipt/message/author remain readable. Saved retry returns the original result without POST; a new write refuses `ACTION_PREPARE_FAILED`. Original accepted count is exactly one. |
| Sent HTTP503 before APPLY | This is AFTER send/before APPLY. Original command remains publicly PENDING with unchanged command/request/commit hashes and no receipt/effect. Current signed read is sequence 3 with empty scopes. Stale saved retry refuses `VERIFICATION_FAILED` before POST; a new write refuses `ACTION_PREPARE_FAILED`. Original accepted count is zero. |

Historical acceptance does not restore present permission. The unapplied saved retry is refused by exact saved checkpoint/head/policy validation after policy advancement; the separate new-write refusal establishes current write denial. Both corrected cases observe zero commit POSTs after revocation, including fresh status/retry/new-write/read, and preserve read access.

First attempt `88651`, source `437efc28df86f0ec4eea2317a4734e1532755705`, exited 1 before scope mutation: the original action was accepted at sequence 3, then the TS Owner constructor rejected a trailing-slash origin (`TRUSTED_ORIGIN_REQUIRED`). The second case had not started. The sole changed helper line in `6a951cd` normalizes that strict TS boundary with `new URL(origin).origin`; native origin/authority inputs and business assertions are unchanged. Fresh corrected attempt `90870` exited 0 with both cases PASS. The original log/DB/WAL remain retained. No SDK defect was inferred.

This repeats the origin-shape adapter failure family. Syntax/diff checks ran, but no separate live constructor/origin prelaunch probe occurred: root's request arrived after the changed run. A future fixture should cheaply assert the strict boundary before starting a service; no retrospective preflight or extra rerun is claimed.

Actual invocations (from this isolated worktree), prefixed with the exact artifact-manifest environment variable above:

```sh
python3 tests/scope-revocation/host.py scope-revocation-first
python3 tests/scope-revocation/host.py scope-revocation-origin-corrected
```

Observed UTC boundaries: task start 10:04:45; source/syntax ready 10:07:14; first launch 10:08:01 and failed terminal 10:08:34; cause 10:09:04; corrected launch 10:09:32 and terminal 10:09:52; evidence freeze 10:11:08. The observed launch-to-terminal intervals are 33s and 20s; inner service/setup/review subdivisions are unmeasured. Root acceptance/integration follow separately.

Retained evidence is under `.test-data/scope-revocation/`: `invocations.json`, `first.log` (SHA `2f683de2a3e06a2facecd1239ab2f1e9177d16735187d71e46b68da4ec3ca992`), `corrected.log` (`477fc5dd9c24e5327f05579605e6548b9ab15e4cfc1acc0d3a2defe784fdb465`), `effects-summary.json` (`2f1b9f3cb792574eb27094f4debb32383febe3ae77b433cfe063d3f1e5d27f22`) and the 312-row `evidence-manifest.json` (`1e2264791f3c653caf22f523906391574afa65034d4155e7317189cc12074186`). It binds public call inputs/outputs, exact requests, scope transitions, all three service DB+WAL files and terminal records. All three owned services stopped/waited with exit −15 and empty stderr; immutable source687/artifact14 guards passed after shutdown. Ephemeral SHM is not semantic evidence. The TS scope mutation remains a fixture-only public API operation; this does not add a native mutation facade or establish all-operation revocation coverage.
