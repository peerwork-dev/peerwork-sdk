# Installed MET HTTP result, 2026-10-14

PASS for three independent scripted installed Python, Node and native CLI cases on immutable SDK source `c5e7a3d8e59ff913da545db2c82e6969646fbe1a`. Fixture source is `1a47c29` (two-line successor of reviewed `292dc857`). The original three first attempts failed in fixture calls; the corrected affected retry passed. No SDK product change or rebuild was made.

The existing cohort is `/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/current-sdk-c5e7a3d`: source archive SHA1366bc1f37e2fcbc068a96ef3f407d9ba2aa7adb8b43f92e132c7fc10741ed5b, 493-row source manifest SHA3b9de2409d0afe40e915cba8f913bee98f3c0367f6d55cb6df49f47fe3d9badf, and 14-entry artifact manifest SHA271e94cf10c812b09bad974358c51b8bbb157afbb7d99fb02c3b90c44e36dd92. All artifact hashes still matched after the HTTP run. Installed wheel/npm/CLI use the established glibc2.28 namespace. The unchanged f828 reference closure contains 204 compiled modules, SHA6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc.

| Run | Command (from this fixture worktree) | Owned terminal | Effects |
|---|---|---|---|
| Original292dc | `python3 tests/acquisition-http/host.py acquisition-http-c5e-first` | 25690, exit1 | All three heads/commit counts remained1, no command POST |
| Corrected1a47 | `python3 tests/acquisition-http/host.py acquisition-http-c5e-route-read-retry` | 44180, exit0 | Each head/commit count5; four command POSTs, including exactly two install POSTs |

Both calls used the explicitly approved outer host context for local socket/namespace operations; consumers used `env -i` in the isolated rootfs with no inherited SDK/proxy/auth environment. Each case had fresh protected service, identity, observations and consumer directories. All twelve service processes across the two runs were terminated and waited; kernel exits-15, catalog exits0, service stderr empty. No live owned handles remain.

Python and CLI first completed explicit config-aware identity import and signed sequence1 read, then their fixture count URL doubled the slash in the READY origin and received404. Node imported the selected identity, then called a nonexistent action-session `read()` method, returning the fixture's generic failure. The successor strips the trailing slash for the count endpoint and uses the existing public Node `readSecureWorkspace(options)` function. Independent source review cleared those exact fixes. It preserves the original signed predicates, observer, setup and synthetic exclusions.

In the successful retry, every interface independently verified missing-identity info without parent creation, imported the explicitly selected fixture Owner, and verified actor/key and signed sequence1. Each recorded pre-outcome enrollment, retrieved and inspected the exact catalog package, deliberately selected a new installation and called public BEGIN/continue with the AUTHOR/PROPOSE grant. Exact signed END and progress package/protocol/instance identities were checked at sequence3. Two genuinely distinct tasks then proposed exact declared candidates with separate command IDs. Each ACCEPTED result's command/sequence/commit hash and receipt effect were bound to fresh signed record readback, including schema, selected instance, author and declared title/body. The second task deliberately selected the existing signed ACTIVE installation and made no install call or additional structure POST. Command retry did not POST or change effects; observation retry returned DUPLICATE.

| Interface | New task | Existing task | Total outer POSTs | Install POSTs after both tasks | Observations |
|---|---|---|---|---|---|
| Python | signed sequence4 | signed sequence5 | 4 | 2 | 9 |
| Node | signed sequence4 | signed sequence5 | 4 | 2 | 9 |
| CLI | signed sequence4 | signed sequence5 | 4 | 2 | 9 |

The observer saw eight layers per case: four outer requests and their four inner forwarded requests. It stores only bounded command/action metadata, byte lengths and body hashes. Full source/result proofs stay separately protected; minimized ledger export excludes raw workspace, actor, instance, source and task payload. Every journey/principal remains `operator_synthetic`; no external attestation or relabeling was used. All 17 external metric values were null. Repeated as-of scorecard reads returned the same immutable snapshot.

Evidence is under this tree's `.build-target/` and the physical rootfs `/root/workdir/message/.worktrees/peerwork-sdk-historical-direct-facades-20261014/.build-artifacts/historical-direct-873a37d/rootfs-managed/work/`. The first state is `acquisition-http-c5e-first`; retry state is `acquisition-http-c5e-route-read-retry`. The following bounded manifest links the exact source overlay, protected summaries/results, observer logs, terminal logs and shutdown records (55 files):

| Evidence | SHA-256 |
|---|---|
| `.build-target/acquisition-http-evidence.json` | ebde9160654a7021dca7630826f2840d2dedeb86a4d897f4e2796985655d7220 |
| `.build-target/acquisition-http-effects.json` | 6cbf89e93dc1bc9b76ad49e5a1de5966b4a2eb0cbb7d340b597263256ea5475d |
| `.build-target/acquisition-http-first.log` | 2463ac1c793729157fb7ff4133f312ee494820c35bb5bc4c1dd40b8695e68ee0 |
| `.build-target/acquisition-http-route-read-retry.log` | a17ea1dee2ad1708a848a2d2db6a24edecd5995f0c648e0466f7339586f87679 |

This closes only the named installed MET new/existing public-package task associations and synthetic exclusion flow. Catalog projection is seeded fixture setup, not publication/upload or publisher/visibility provenance. The observation adapters bind local evidence associations; they do not establish independent controller or external-population truth. Business correctness passed for these scripted cases; natural-Agent workflow compliance was not tested. Full independent proposal/adoption/task, optional parameters, historical/staged/composition variants, Python cancellation, publication and external journeys retain their separate outstanding gates. Later main staged changes are excluded from the tested c5e artifacts.
