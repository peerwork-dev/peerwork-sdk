# Installed CPython 3.12–3.14 identity result

On 2026-10-15, one native x86_64 Linux run passed on the existing CPython 3.12.15, 3.13.16 and 3.14.8 interpreters. Each installed the unchanged `8900e8066ef8d07117a3b85771e831e4f84ffba8` cp311-abi3 wheel into its own fresh offline venv, imported from that venv, and ran the existing `tests/installed-protected-identity-smoke.py` unchanged (SHA-256 `d87e351434d2eeb25bd625ea052a923ca9a971197545565cfc4e6d1d337c6fe0`).

Command: `bash /root/workdir/message/.test-data/cpython-extra-8900-20261015/run.sh`. Owned session `78864` exited **0** on its first attempt. The existing rootfs was entered through the established isolated mount/chroot launcher; these were native interpreters, with no emulation, runtime download or SDK rebuild. No CPython 3.11 SDK check was repeated.

For each Python version, the smoke created three fresh identities through installed Python, Node and CLI, then reopened each through all three interfaces and compared exact public IDs: **3 creations and 9 reopens per version**, all passed. State paths contained spaces and non-ASCII characters and were created under private mode-0700 directories. The helper neither reads identity contents nor contacts a service. Node24 and CLI came from the same immutable 8900 installed cohort.

Each `import.json` records `sys.version`, executable/prefix, machine, `peerwork.__file__`, native module path and both hashes. All wrapper hashes equal `7a7b6647e999a570ddcaa14cabfeaec34301412fc09cf27c75300ad0fb96bb35`; all native hashes equal `86d221f642cf094802618e3dd33147f5e5c30cee054c5a88c20b35c727afd6a4`, matching the wheel. Wheel SHA-256 is `912661a11c1824731661f68c7b85413e8c984c7911c73368fe9ee33180044586`. The unchanged 584-file source and 14-entry artifact manifests verified before and after the run.

Evidence root: `/root/workdir/message/.test-data/cpython-extra-8900-20261015/`.

| File | SHA-256 |
| --- | --- |
| `summary.json` | `493ddfc92d0af2fa4f26f34262195d2da3c564424eab7579b69dd385e6080a86` |
| `evidence.json` (15 files: scripts, original smoke, run log, summary, three install/import/smoke records) | `12b2f830dedb318ed2cdb98b26a3b28b8e18f17bcd75620b4150e71d81790350` |

This closes installed import and protected identity lifecycle on these three existing Linux x64 interpreters. It does not establish their full async/HTTP/business behavior, free-threaded Python support, other native platforms, release signing or publication. No service, actor or network workflow was run.
