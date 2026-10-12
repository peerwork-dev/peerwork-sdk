# Pinned TypeScript conformance reference

`src/` contains the minimal tracked TypeScript source closure needed by the
current kernel/secure canonicalization and E2EE cross-open generators. It was
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
| `workspace-coordination-contract.ts` | `79c58a5146cf09b575f39f4c3ba8bfbffc2bd05e2aefc3a1e62c492d36214787` |
| `workspace-field-protection.ts` | `783f2d2575fe730b8a13ca50957d101f2f3259c5928e676196c30a64bbeb9d73` |
| `workspace-interpreter.ts` | `ab92752306c8728f0b0af608d2e16bbb61b63cc560ba9e932836497aacbd6c2a` |
| `workspace-manifest.ts` | `ae6801ba62635cce4da6336375fb7fdc9f717001e92294f2df9da14d45e7fe94` |
| `workspace-secure-contract.ts` | `115400201d7afa2d3913d066929896256c031acf63c35a79ed0e4e9a42a9cde0` |
| `workspace-secure-crypto.ts` | `16845f9b1815adb1b603ce74d0a152bdbc9e4054f109af919e0899ba88dc1610` |
| `workspace-secure-recovery.ts` | `0b526f6e481a2379435ae6d278eecc6d79660321e06a5caaad2f3ac1995051ea` |
| `workspace-structure-contract.ts` | `ecf9a81fed907ae142fc02feb06a1b82206a61ef147caa6cceb80e429c951352` |
| `workspace-workflow.ts` | `9516f182ba31cd3e2932e0384ad6b5596c361b7b4759c75743131961f778da6e` |

`conformance/package-lock.json` pins Node package tarball URLs and integrity
digests for esbuild `0.28.2`, hpke `1.1.7`, zod `4.5.4`, and esbuild's optional
platform binaries. These are third-party MIT packages. Their license texts are
copied from those exact installed package versions in `licenses/`: esbuild
(SHA-256 `b40ec5baec7bb34fa5b1c09521fa3cd52d5fad7adafed74932a2010d3612a681`),
hpke (`22a4d289748aa231f979407509900eb64cdf1e67f39e60a90f340d88648afbb0`),
and zod (`3f1189b28e3866e0d979968d466b78f813f76827cfdca1fbb124cc0a5c8841f8`).
Node `24.20.0` was used for the recorded run. The `node_modules/` installation
is disposable and ignored; it contains no copied project state or credentials.

From the new repository root after `cd conformance && npm ci`, run
`node conformance/generate-ts-vectors.mjs` and
`node conformance/cross-open-ts-rust.mjs` (build the Rust `e2ee_bridge` example
first). `PEERWORK_TS_SOURCE` and `PEERWORK_REFERENCE_NODE_MODULES` remain
optional audit overrides. The source closure here covers these entrypoints;
full policy/journal/evaluator differential tests will require their additional
tracked dependencies to be added and pinned separately.
