# Pinned TypeScript conformance reference

`src/` contains the minimal tracked TypeScript source closure needed by the
current kernel/secure canonicalization, E2EE cross-open, interpreter, and
secure-engine generators. It was
copied byte-for-byte from the accepted local baseline commit
`dd8a9d2e5a4cb315a980e7e35e94a7469d3a8afa` (evidence
`4065739efff3e45cdea3bc7be2e0309682a475a2`) at
`clients/secure-workspace/source/src/` on 2026-10-12. The original project
uses Apache-2.0; the matching full license is the repository root `LICENSE`
(SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`).
The baseline full commit was not retrievable from the configured public GitHub
origin at this pin, so these files provide a reviewable source oracle without
requiring an operator's sibling checkout.

| Source file | SHA-256 |
|---|---|
| `errors.ts` | `01b028bbcb802f839aaa532e5d61ff71ac597653086adaa8332046c411398d6b` |
| `json.ts` | `05bf86b80ad3f7fe67f3a15c6ad9d0e55b2f5048c93d119e68a1756da6c12e2f` |
| `protocol-compiler.ts` | `c35d9bbd2d4e70ab89cc1627ced29acee7d8e2918ee305a90bc65a022995b10d` |
| `protocol-package-closure.ts` | `b708803da3403b44452c75ff7986c4aad4ea56661401b06a251f900cc4aeccd3` |
| `protocol-package-runtime.ts` | `497da87a5be68905655490ea3dc143ffdaea92f784e30d6da27c1df748cbc5c3` |
| `protocol-package.ts` | `e5770ec3af07f70cd1fb8a3dd63e88789e47ebc495b3ed1036d36dc12a989152` |
| `workspace-contract.ts` | `81a85669453a4d94bac5a6450090f09747dd13936759cabd9c5cbe8d901038b7` |
| `workspace-coordination-contract.ts` | `79c58a5146cf09b575f39f4c3ba8bfbffc2bd05e2aefc3a1e62c492d36214787` |
| `workspace-coordination.ts` | `67114b11b60cd03b12e39b86a912afbb1a51c7054618133fa5de1a2c05002249` |
| `workspace-field-protection.ts` | `783f2d2575fe730b8a13ca50957d101f2f3259c5928e676196c30a64bbeb9d73` |
| `workspace-interpreter.ts` | `ab92752306c8728f0b0af608d2e16bbb61b63cc560ba9e932836497aacbd6c2a` |
| `workspace-manifest.ts` | `ae6801ba62635cce4da6336375fb7fdc9f717001e92294f2df9da14d45e7fe94` |
| `workspace-protocol-composition.ts` | `44439b0a7caceef26dc7d5a482109e8cb3c38e9c6e44ef82054381e7c07da445` |
| `workspace-protocol-execution.ts` | `be5554c5671fc40f45b5f1be4b4ac9f6a352cd4054ad97bf3317ae1a6e581a60` |
| `workspace-protocol-object-install.ts` | `1eb243544b3578de382a175987ac2236c331c678dabf10b6ffb1fc7d108e9bbc` |
| `workspace-protocol-object-source.ts` | `a740c8b0ef6f864272f992c69fbe96ab22daaa005a593ef5571be161e7854b3b` |
| `workspace-protocol-object-stage.ts` | `bc19fbe7d1a76e5ce86e31360b43abd3181c681b96bfd66e1011577c8d2e9b9d` |
| `workspace-protocol-package-source.ts` | `18ad9a8529302c48148a73b8d1c2126fa74a9be94e3c84bd69dc1360e613d459` |
| `workspace-secure-client.ts` | `59ae3f841a5aeb1c1dabb5187dfc8443af0aa6c4a47a6fc3333b1d3eca3f4fbd` |
| `workspace-secure-composition.ts` | `2087108e1cbba4b17b3d3202193327659e6b406ee9149fd6fd9b4a6870ac77a9` |
| `workspace-secure-contract.ts` | `115400201d7afa2d3913d066929896256c031acf63c35a79ed0e4e9a42a9cde0` |
| `workspace-secure-crypto.ts` | `16845f9b1815adb1b603ce74d0a152bdbc9e4054f109af919e0899ba88dc1610` |
| `workspace-secure-engine.ts` | `f418278a29734baf46627319a23219e12d4c12901fe94498c3113675273ca809` |
| `workspace-secure-field-policy.ts` | `7a88a9fe8caf70a756b65ba440625c2a4c8e396bfb5764ad2f2d1c722d0292f8` |
| `workspace-secure-format-ceiling.ts` | `629d4c8dfcbe012307b07d6efdaadc7beb78036bd883a3198a7f3a92d9374a38` |
| `workspace-secure-format-transition.ts` | `9314cb9a910ffa1503e1840119496be7122bb3a793091d1de775b0f66cc0ab10` |
| `workspace-secure-install.ts` | `2eedede26e77f7357d9680eb8ded97422ba3a77221436cdc71578aaa7f3a078e` |
| `workspace-secure-member-keys.ts` | `20ad857f654e63f8a0b00daaac92145045bf79edb84164623665e5bc4640041d` |
| `workspace-secure-migration.ts` | `be612b50305796a88dd1de90c1213bf7518b8bf74e7a6fb41067f2b9c67a8f57` |
| `workspace-secure-permissions.ts` | `744044c9e2f51bd1cdb29c4dd710e2736c299324dc2b4d67486544bf74d5a3bf` |
| `workspace-secure-recovery.ts` | `0b526f6e481a2379435ae6d278eecc6d79660321e06a5caaad2f3ac1995051ea` |
| `workspace-structure-contract.ts` | `ecf9a81fed907ae142fc02feb06a1b82206a61ef147caa6cceb80e429c951352` |
| `workspace-structure.ts` | `ad4da8cb5503a0b16327e85da35d6d0bb733fa396b4681441fa7f6f6eb82c817` |
| `workspace-workflow.ts` | `9516f182ba31cd3e2932e0384ad6b5596c361b7b4759c75743131961f778da6e` |

`conformance/package-lock.json` pins Node package tarball URLs and integrity
digests for esbuild `0.28.2`, hpke `1.1.7`, zod `4.5.4`,
`@noble/hashes` `2.3.0` (integrity
`sha512-oN+QwyX7VSHotibwubG3kpzbwKrfnyR6OOO+3Nk/53ADL7FmgHHz4TgrbaYKvvOw09u6QTx0oiH1cNCIOuN0CQ==`), and esbuild's optional
platform binaries. These are third-party MIT packages. Their license texts are
copied from those exact installed package versions in `licenses/`: esbuild
(SHA-256 `b40ec5baec7bb34fa5b1c09521fa3cd52d5fad7adafed74932a2010d3612a681`),
hpke (`22a4d289748aa231f979407509900eb64cdf1e67f39e60a90f340d88648afbb0`),
zod (`3f1189b28e3866e0d979968d466b78f813f76827cfdca1fbb124cc0a5c8841f8`),
and noble-hashes (`4f221aee6e072336700c408c68ab3b96a3fc09f6aebe6f48f1bd99e5ef13faec`).
Node `24.20.0` was used for the recorded run. The `node_modules/` installation
is disposable and ignored; it contains no copied project state or credentials.

From the new repository root, the current self-contained regeneration sequence is:

```sh
(cd conformance && npm ci --ignore-scripts)
cargo build -p peerwork-core --example e2ee_bridge
node conformance/generate-ts-vectors.mjs
node conformance/cross-open-ts-rust.mjs
node conformance/generate-interpreter-vectors.mjs
node conformance/generate-secure-engine-vectors.mjs
```

The cross-open script's default bridge path is relative to the repository root
(`target/debug/examples/e2ee_bridge`), so run it there after the Cargo build.
The sandbox's `spawnSync` runtime reports EPERM during esbuild's install-time
binary probe even when the binary prints its version successfully; the locked
optional platform package works for the asynchronous generator builds after
`--ignore-scripts` installation.
`PEERWORK_TS_SOURCE` and `PEERWORK_REFERENCE_NODE_MODULES` remain
optional audit overrides. The source closure here covers these entrypoints;
full policy/journal differential tests will require their additional
tracked dependencies to be added and pinned separately.
