# Installed restored replay count across Python, Node and CLI (T083)

**First actual run passed.** One unchanged authentic archived fixture was read through each installed public interface. Limit26 returns `RESOURCE_LIMIT` without a verified value; limit27 returns the exact signed27-commit head/policy and all25 reference objects. Fresh-handle repeat and omitted/default limit return the same result. Public identity IDs and attachment inventory stay unchanged. One shared transport-omission negative returns `VERIFICATION_FAILED`; normal transport then restores the original full result.

## Frozen source and installed artifacts

T082 cohort source: `a69929f1e1d44612b92be007df17ecb750529df5`; source inventory797 SHA `2bc8abf8c52dbb93aa32ff3545cce08c2139d4d778c6fedda31436386a7641f0`. Cohort base: `/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/resource-sdk-t082-20261015`. Its14-subject artifact manifest SHA is `4e924c841da539aa9325f630bd0f217eb55df5006a393333d331c4a2ce9285e9`.

The runner mechanically requires build/install/verify terminal0, this exact source inventory hash and all14 artifact subject hashes before creating the runtime leaf or starting service. It rechecks them after service. No artifact was modified. Exact installed subjects:

| Subject | SHA-256 |
|---|---|
| Python wrapper | c629f6fbae38ce4d50e62be16ab77160c26713a384393ce1e57722e164d553ce |
| Python native | 7bf329f4b605299efb3632b2116fa77a51a7a5221448a8cff3c03e28eb7cd9a8 |
| Node wrapper | a13499548bb043d95949ea60374ef478314af0b8fdd752be5022df2447a33e51 |
| Node addon | 157f6d7a9a24e51b2561445eaf42c70d02260f951e83e2ad67f9d42eeacc17fa |
| CLI | 6b40befeb8d1641168c1722eb2d2e09e15ef5fca7e704a7eb25df6c0590298b1 |

All are from the new coherent cohort, not old-native/new-wrapper combinations. Test source checkpoint `24efc0a` contains four new task-only adapters. No product changes/builds occurred in T083.

## Actual calls and preserved fixture

The exact T059/T063 profile remains at `/work/t059-archive-service-env-fixed/native` in the existing rootfs, with its original attachment already ATTACHED and source exports absent. The existing source/DB/origin/known synthetic receipt seed were reused; no producer, import, new attachment, source copy, DB seed or private-content extraction was performed. Only new PUBLIC installed Python package, Node modules and CLI executable were bound read-only into a new isolated runtime leaf. The native protected profile stayed at its bound path and was accessed through public APIs. Public identity info before/after matches fixture actor/key; this proves ID stability, not an independent private-key byte comparison.

Each interface actually executes its own installed API: Python `SecureOwnerWorkspaceClient(..., max_replay_commits=26/27).read`, Node `openSecureOwnerWorkspaces({maxReplayCommits:26/27}).read`, CLI `secure owner-read CONFIG_JSON WORKSPACE_ID` with `max_replay_commits` in protected config JSON. Ordinary profile flags are not used for Owner selection. Node and CLI reads run in fresh child processes; Python creates fresh client handles. Installed module locations are asserted by the consumer. No hidden native store/identity/journal contents are read by the test.

Verified head: `528da57d9c49b38d5d95ea35f5ec4c80656c6c8225235d9a836e42e64360e8e6`; policy: `b5f689b1eb892391191b656bf55e82f162d9af17353be476bd917c537ee0026d`. Actual results for Python, Node and CLI: 14 incoming /27 restored commits,25 exact objects,26 refusal,27 success, default/repeat equality and unchanged public attachment/identity. The shared negative removes one archived original from the actual journal response, not from DB; it fails verification, then normal read succeeds.

Actual service metadata: **14→14 commits,11 journal GETs,0 POSTs,0 HTTP errors,1 removed archived packet**, same origin/receipt seed, no producer. Child and whole host exited0. Service reports `closed:true, waited:true` (in-process reference server; no invented external PID/exit code).

## Runtime, timing and evidence

Actual consumer Python is **3.13.5 / glibc2.41**, using the installed cp311-abi3 extension through the accepted host-runtime overlay. Node is **v24.20.0**, exact public runtime executable hash retained. This is native Linux x64 execution, not a claim that this HTTP gate ran inside the build's glibc2.28 minimum runtime. CLI/native subject hashes above bind actual execution. Node/CLI work is orchestrated by Python; this is actual three-interface API coverage, not an independent-language isolation test.

Task started14:57:27 UTC. Runner preparation was ready15:01:57. T082 release was15:01:44, overlapping preparation; there was no additional idle wait after readiness. Owned actual handle95595 ran **15:02:19.312947–15:02:22.333376 UTC (3.020454s)**, first run terminal0. No T083 failure or retry occurred. T079's earlier compile/error-mapping failures remain in its accepted report; they are not relabelled by this new installed result.

Evidence root: `.test-data/t083/`. Key records: `http.log`, `terminal.json`, `http/result.json`, `http/continuation-consumer.json`, `http/continuation-service-exit.json`, `http/calls.json`, three `http/*-limit27.json` full verified results, CLI raw terminal records, `frozen-inputs.json`, `guard-before.json`, `guard-after.json`, `node-runtime.json`, and exact launch `command.json`. Manifest `evidence.json` uses the existing `{inputs:[{path,sha256,size}], evidence:[...], binaries:[...]}` shape. Raw source/profile/DB/key files are not included in Git or the manifest.

Reproduction (requires released cohort and the preserved synthetic fixture): `PEERWORK_T083_ARTIFACT_MANIFEST_SHA256=4e924c841da539aa9325f630bd0f217eb55df5006a393333d331c4a2ce9285e9 python3 tests/installed-replay-count/host.py`. The runtime leaf refuses reuse. This closes the affected installed count-option parity gate only; it does not prove >102400 histories, >64MiB acceptance, other platforms, every dependent client operation, or natural Agent workflow.
