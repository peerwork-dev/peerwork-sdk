# T101 — installed GNU extra-runtime Kernel acceptance

FIRST-PASS in the named scope on immutable T097 source `0daef2a865bc3b09b7c76274883d47680668051c`, source833 manifest `3de0a579bed63d0551219ff9956b8aaaf2be21146f8c04cab6e3b407b54ed139` and artifact14 manifest `cc7ef12666290b9011ec5f8615ce75b0a36a948ad7a2373c9984bbbc68ba4d1e`. No SDK build, interpreter download, product edit or frozen-artifact write occurred.

The existing public manylinux CPython 3.12.15, 3.13.16 and 3.14.8 **GIL** interpreters and GNU Node22.23.0 were available. Node's existing official archive still hashes to `14d7de44f235534799f8b171a4050d9a6a4bc99c87e053a25d3d54afa580aa20`. A new runtime view copied only public `/usr`/loader libraries, selected Python prefixes/internal targets, Node22, named public OS config/CA files and exact T097 package inputs. Old work/home/profile/key/DB trees were excluded. Admission completed 17:02:26 UTC, within the first three minutes; preparation took 5.247s. Each selected interpreter ran as UID65534; Python GIL, OS CA parsing and localhost/NSS prerequisites passed. Absolute Python symlinks were resolved inside the guest, then canonical paths were prefixed with the new root for hashing, avoiding the earlier T038 collector error.

Each fresh UID/EUID65534 space/Unicode consumer installed the exact cp311-abi3 wheel using offline pip, or explicit root/platform npm tarballs using `--offline --ignore-scripts --omit=optional`. A task-local CLI copy served only explicit identity create/reopen support. Actual installed wrapper/native paths and hashes matched the five canonical T097 subjects; the three Python cases loaded the same native ABI3 bytes. `admission.json`, `runtime-binary-pins.json`, per-case summaries and install/call records retain versions, GIL checks, resolved executable paths and file hashes.

| Runtime | Child exit | Install + actual Kernel case |
| --- | --- | --- |
| CPython 3.12.15 GIL | 0 | 3.189s |
| CPython 3.13.16 GIL | 0 | 4.671s |
| CPython 3.14.8 GIL | 0 | 4.050s |
| GNU Node22.23.0 | 0 | 2.968s |

Each runtime observed CONFIG_INVALID through public KernelError with the promised RuntimeError/Error compatibility, retained ValueError/TypeError shape validation, and actual HTTP503 DISCOVERY_FAILED without exposing the sentinel response body or creating a failed-discovery journal. Safe code/message/operation/target metadata was saved before domain-error assertions. Each prepared its own original command, observed public PENDING and pending ID, obtained a verified ACCEPTED result, freshly reopened and retried the same ID/result. One fresh host reference service ended with exactly **four commands/four workspaces**; this is an effects count, not a claim to count all HTTP attempts.

Original handle `16910` exited 0, 18.183s, 17:05:19–17:05:37 UTC. There were no failures, retries or late-observer reruns. Source/artifact guards returned 0 before the group, after each case and at completion. The f828/204-module reference service was stopped and waited (exit -15), stderr empty; all four local 503-server threads joined. All owned handles are closed.

Evidence base: SDK main `.build-artifacts/kernel-runtimes-t101-20261015/`; `result.json`, `terminals.json`, `first.terminal.json`, per-runtime `*-summary.json`, `*-calls.json`, `*-install-calls.json`, error metadata and `service-shutdown.json`. The existing-schema `evidence-manifest.json` inventories public source/log/runtime metadata only; the observer did not read/copy identity, profile or DB contents. Helper source: `tests/kernel-runtimes-t101.py`.

CPython3.11/Node24/CLI were not repeated as Kernel runtime cases; host Node24 and CLI identity calls were supporting tools, and CPython3.12 also coordinated the Node case without Python SDK calls. Scope excludes free-threading, other OSes, full business/private/TLS matrices, language-runtime absence, compiler-free closure, Agent/acquisition, signing and public release.
