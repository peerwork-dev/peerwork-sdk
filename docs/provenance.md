# Source and license provenance

This repository began as an empty GitHub repository at
`https://github.com/peerwork-dev/peerwork-sdk.git` on 2026-10-12. The migration
baseline is the tracked Peerwork protocols TypeScript SDK at source commit
`dd8a9d2` with accepted evidence commit
`4065739efff3e45cdea3bc7be2e0309682a475a2`.
The full baseline commit SHA is not currently resolvable from the public
Peerwork protocols origin. The local tracked checkout supplies these pins;
the minimal attributable TypeScript reference closure is now vendored under
`conformance/reference/` so a fresh clone can run differential vectors without
the sibling checkout. Its exact source/package hashes, source paths, and MIT
third-party license texts are recorded in
[`conformance/reference/NOTICE.md`](../conformance/reference/NOTICE.md).
This does not imply that a fresh public clone can retrieve `dd8a9d2` from the
old origin.

The root Apache-2.0 `LICENSE` is copied byte-for-byte from that tracked
baseline; its SHA-256 is
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
The Node and Python packages carry the same license. Rust/Python/Node native
source in this repository is newly authored for the port; the vendored
TypeScript reference files retain their original attribution and license.
The baseline is consulted for behavior and differential vectors; the old SDK bundle, operator key
material, state databases, and private fixture data are excluded.

Selected tracked baseline source hashes captured before the port:

| Tracked path under `clients/secure-workspace/source/src/` | SHA-256 |
| --- | --- |
| `peerwork-sdk.ts` | `77cc840ab83abc4312e48d6e05c135c8dacfbcd4c5dde0b44a42d8967366f67b` |
| `workspace-secure-crypto.ts` | `16845f9b1815adb1b603ce74d0a152bdbc9e4054f109af919e0899ba88dc1610` |
| `json.ts` | `05bf86b80ad3f7fe67f3a15c6ad9d0e55b2f5048c93d119e68a1756da6c12e2f` |
| `workspace-manifest.ts` | `ae6801ba62635cce4da6336375fb7fdc9f717001e92294f2df9da14d45e7fe94` |
| `workspace-contract.ts` | `81a85669453a4d94bac5a6450090f09747dd13936759cabd9c5cbe8d901038b7` |
| `workspace-client.ts` | `e63ca81a92fa5a94f023cae8ed31c806e7bfac1a2989a3371731b58f0d0227c2` |

These are source identity pins, not proof that the new implementation is
equivalent. The conformance vectors and negative tests must establish that
separately.
