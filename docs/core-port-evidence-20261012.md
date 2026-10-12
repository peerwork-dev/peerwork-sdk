# Native core port checkpoint — 2026-10-12

Source baseline: tracked `dd8a9d2` in `/root/workdir/message/.worktrees/cmo-sdk-cli-20261012`, with evidence commit `4065739`. Core behavior was read from `clients/secure-workspace/source/src/workspace-manifest.ts`, `workspace-secure-crypto.ts`, `workspace-contract.ts`, `workspace-client.ts`, and `json.ts`. The Rust source is a fresh implementation; `conformance/generate-ts-vectors.mjs` executes the pinned TypeScript functions and writes `conformance/ts-differential-vectors.json`. The independent Ed25519 known answer in `crates/core/tests/wire.rs` is RFC 8032 §7.1 test 1.

The first checkpoint implements distinct kernel and secure canonicalization, safe integer and key restrictions, UTF-16 member sort order, JavaScript array-index enumeration for kernel objects, SHA-256, canonical base64url, Ed25519 actor/key IDs, domain signatures, compact JWS signing, whole-artifact signature binding, duplicate member rejection, and discovery-pinned receipt signature/result binding. A validated receipt is only a foundation for a verified read; journal replay, member permissions, E2EE decryption, source/checkpoint binding, and read authorization are not implemented. `capability_manifest()` marks verified reads/actions/recovery false.

Observed command: `cargo test -p peerwork-core --offline --locked` from the new repo root, exit 0, 5 integration tests passed. Initial Cargo attempt failed because crates.io DNS was unavailable; distribution lane populated the approved dependency cache, then offline tests passed. TypeScript generator command used exact source and existing dependency directory:

```sh
PEERWORK_TS_SOURCE=/root/workdir/message/.worktrees/cmo-sdk-cli-20261012/clients/secure-workspace/source/src \
PEERWORK_REFERENCE_NODE_MODULES=/root/workdir/message/.worktrees/cmo-integrated-build-20261010/node_modules \
/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node conformance/generate-ts-vectors.mjs
```

Open compatibility issue: TypeScript `JSON.parse` and both canonicalizers accept an escaped unpaired UTF-16 surrogate and re-emit its escape. `serde_json` rejects this input because Rust `String` cannot represent it. The differential vector records the exact accepted bytes as base64url, and the Rust test records the current rejection. This is a valid-input parity blocker, not a security acceptance or a full wire compatibility claim. A JS-string/UTF-16 wire representation and parser will be needed. Numeric spellings `1.0` and `1e0` normalize to `1`; receipt integer validation accepts these spellings. Duplicate decoded JSON member names, including escaped equivalents, are rejected by both implementations.

Remaining phases: vetted P-256 HPKE/AES-256-GCM encodings and independent vectors; authenticated journal replay, exact authorized history and structure; protocol evaluator/refs/effects; signed policy/readiness; command and action intent persistence/reconciliation/migration/concurrency; real HTTP acceptance and platform packaging. No production service or remote publication was changed by this lane.
