# Historical Owner ENFORCE format transition: bounded native result

The actual-service Rust test at isolated SDK commit `bd04d74632f0b3f2c5e03c655b7b1c1f2ba21d4d` passed (exec session `18880`, 1/1, 167.04 s). Its product producer and runtime are commits `4422035d12d7555bfd8ce27d3c23f7c7cf7600d4`, `58aa84486b87771f6a4b9b5f3daedec5fb25b5b5`, and `05f576f785d5511534658d1d776eb850999db5f0`. The exact tested file SHA-256 values were:

- `crates/core/src/prepared_owner_format.rs`: `3b6078ec4041fa61c81d2b508e67bee9a796d5fcf72102cc9189a9bb81f04b05`
- `crates/runtime/src/secure_owner_format_transition.rs`: `8272d932da7d4afa856036218c201928bdea9427ccfdd84f9f72b2d59971f6f2`
- `crates/runtime/src/secure_owner_create.rs`: `839339bc4975b76beb814215da5b302bf083ca76c0b886b3f13ddc75922bed4b`
- `tests/reference-kernel-server.mjs`: `50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0`
- `tests/format-two-material.mjs`: `70e3085e105344c80edc15216e736a8b69028185681d3fffd0dd4e850ccd63cf`

The service was the pinned f828 kernel at `/root/workdir/message/.worktrees/e2ee-main-integration-20261006`. Test setup used the separately pinned historical TS client `ae5d1151c2a1e72bc599eb4022291cf8496beba3` to create a genuine PRIVATE wire-v1 Owner workspace and encrypted legacy record. Native historical Owner attachment then imported that test-created Owner state. The local reference fixture called the kernel's official `activateProtocolCutover` lifecycle method to enter ENFORCE; no production cutover phase or service database was hand-edited. Native submit, retry, install, and read used actual local HTTP requests.

The test observed a dropped response to native Owner wire-v1→v3 policy-only upgrade, discovered the saved generated ID from protected local history, and reconciled it against the signed sequence and policy. The old encrypted record remained readable. A native format-one DIRECT install moved the upgraded v3/NONE workspace to STRUCTURED ACTIVE. A dropped response to the separate PRIVATE ceiling-one→two Owner transition was recovered by its saved ID, and authenticated policy read showed wire v3 with ceiling 2. A source-generated raw two-package format-2 closure from the pinned format-two fixture then went through native PRIVATE staging (`STAGED`) and staged BEGIN/PAGE/END installation (`ACCEPTED`). Stage `part_count` counted signed stage POST partitions, not packages; the test asserted its actual applied count and commit delta. After those later format-2 objects entered signed history, exact resumes of **both** older transition IDs returned `ACCEPTED` with no additional commit. This is the affected regression for re-proving saved requests from their authenticated source checkpoint rather than from the latest objects.

The test does not yet explicitly inspect the installed protocol and instance in signed readback, execute typed-array `replace`/`produce`, or have a distinct admitted member `consume` an exact produced reference. It does not exercise a wire-v2/STRUCTURED upgrade, PUBLIC upgrade, format-2 DIRECT install, or native migration of unresolved historical TS operations. Producer unit coverage includes only one synthetic v1→v3/NONE vector and saved-packet byte refusal; recursive historical ceiling eligibility still needs a focused negative. The elapsed time is debug/fixture cost, not release performance evidence. Linux execution does not establish macOS or Windows behavior.

Preserved earlier results: the first exploratory service attempt (21.46 s, uncommitted source) recovered the upgrade but failed a test oracle that tried to read a policy from a public read DTO. The corrected `58aa844` test passed the narrower upgrade subset in session `6706` (1/1, 29.26 s). The `05f576f` upgrade→format-one DIRECT→raise subset passed in session `44758` (1/1, 85.28 s). The first typed-closure extension in session `11574` failed after 93.34 s when its test equated two packages with two stage POST partitions. The next session `51673` failed after 83.78 s before staging because its test treated the digest-keyed `closure.packages` object as an array. These were fixture assertion errors, not product refusals; they remain distinct from the final `18880` result.

The focused command used Rust 1.89, the task-owned Cargo cache/target, pinned Node 24, `PEERWORK_REFERENCE_ROOT` and `PEERWORK_LEGACY_CLIENT_ROOT`, and ran:

```sh
cargo test -p peerwork-runtime secure_owner_format_transition::tests::actual_service_enforced_legacy_private_owner_upgrade_and_raise --offline --locked -- --nocapture
```

The source proof is bounded to native policy transition recovery and the format-two stage/install statuses and later-history retry. Natural Agent workflow compliance was not tested.
