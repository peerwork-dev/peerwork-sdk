# Configurable replay-count installed cohort (T082)

One coherent Linux x64 GNU release cohort was built from exact SDK source `a69929f1e1d44612b92be007df17ecb750529df5`. CLI, ABI3 wheel and root/platform npm packages passed offline installation, actual native loading and the bounded count-option smoke. These are build/local-interface results; T083 owns separate HTTP acceptance. No Agent, other OS, compiler-free runtime, reproducibility, signing or publication claim.

Source archive SHA `72f84f4de29f5cd00f9a09449d337f68b86dc3d249aa94a91f03473b8253efd2`; 797-row source manifest `2bc8abf8c52dbb93aa32ff3545cce08c2139d4d778c6fedda31436386a7641f0`; 14-entry artifact manifest `4e924c841da539aa9325f630bd0f217eb55df5006a393333d331c4a2ce9285e9`. Base is SDK main `.build-artifacts/resource-sdk-t082-20261015`, with a new physical `rootfs`; guest source remains `/work/sdk-config-t062-20261015` to reuse the stopped T064 cache safely. None of T064's private work/profile/identity/DB/fixture directories were copied. The whitelist copied public system runtime/toolchain paths, explicit public `/etc` files, public Cargo registry, build tools, newly archived source and owned release target only. No hardlink mutation was used. Unchanged source mtimes were retained only after per-file hash equality. Library/facade outputs were invalidated while native ICU/provider build-script outputs and fingerprints were preserved; no cold ICU build occurred. Ten prior artifact manifests and all their entries remained unchanged.

Actual `prepare-and-build.py`/`run-install-verify.py` stage commands, inputs and timestamps are retained in the base. Build owner50381 and install/verify/smoke owner1819 are terminal0. The first actual build and all actual package/smoke stages passed:

| Stage | Observed seconds | UTC interval |
|---|---:|---|
| Successful resumed preparation | 11.704 | 14:59:01.204902–14:59:12.909191 |
| Release build | 82.744 | 14:59:12.909446–15:00:35.653715 |
| Offline install | 6.003 | 15:01:21.822863–15:01:27.825523 |
| Artifact/ELF/RECORD verification | 1.190 | 15:01:27.825704–15:01:29.015379 |
| Strict package/notices/old guards | 2.801 | 15:01:29.015571–15:01:31.816874 |
| Installed module probes | 0.195 | 15:01:31.817045–15:01:32.011795 |
| Unprivileged consumer smoke | 1.758 | 15:01:32.011962–15:01:33.770366 |

Wheel RECORD has 10 entries, nine hashed, and py.typed; the native module and wrapper equal the source-bound installed bytes. Root/platform tar closure and notices pass the frozen release inspector. All three ELF GLIBC floors are <=2.28. Rust1.89, CPython3.11 and Node24.20 are the existing pinned build/runtime tools; this build root contains compilers.

`tests/installed-resource-cohort-t082.py` performs fresh offline pip and npm `--ignore-scripts` installs as actual UID/EUID65534 into user-owned space/non-ASCII paths, copies/invokes the CLI, and records exact loaded wrapper/native paths and hashes. Python and Node accept default102400 and Python explicit27; zero and overflow are refused (Python u64 overflow, Node unsafe-integer overflow, CLI u64 flag overflow). CLI Owner help includes max_replay_commits. Public identity creation is explicit; Node/CLI public reopen and local Owner operations share that protected identity/profile. No identity contents or keys are read by the harness and no HTTP is attempted. Five fresh user-installed file hashes equal their corresponding frozen built/package bytes (`fresh-installed-byte-bindings.json`).

Two preparation/collection errors are retained, separately from first-pass SDK stages. Initial owner88229 exited1 before source extraction/Cargo because a broad `/etc` copy attempted unreadable shadow/gshadow files; no read succeeded. The changed successful preparation copies only explicit public config files and never escalates access to password databases. Later normal offline collection could not read duplicate public calls/result files under UID65534's protected home; it uses the complete root-owned launcher stdout instead, without changing permissions or rerunning the SDK. Original preparation script and both failure records remain retained. No build/runtime retry or green resampling occurred.

Evidence: base `result.json` SHA `084b200d22706f42ef87bbe9d7fb382ccfbc7d3903ecb751c9a6defa49e4eb3f`, `evidence-manifest.json` SHA `1489225c281dcc1bea214f551e737636b48f088c8b8941db447431fc10eb9c2f` (43 metadata files, separately from 14 artifact subjects). It pins exact scripts, source/cache records, raw stage logs/terminals, inspection outputs, full public smoke calls/result/stdout, user-file hash bindings and failure records. Helper SHA `48e2ce7306eaec621ecfbee4ccd997c5827b08a2db925b98460d9ff3e0a42ec6`. Final source/artifact guards passed again after smoke. All owned handles closed; no service was created. Fresh local identity files stay protected and are excluded from evidence collection.

Ledger start14:56:06 UTC; admission read14:56:39 observed ~15.7GiB available RAM and119GiB free disk. First preparation refusal observed14:58:24; its precise execution/preparation split is unknown. Artifact release was observed15:01:44, before report prose, for independent T083 use. Root acceptance/integration time belongs to the same25-minute budget and is recorded by root.
