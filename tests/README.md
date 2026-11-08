# SDK tests

The default source checks run the core/runtime/CLI Rust suites and selected
native build-policy and research-protocol checks. Tests use synthetic identities
and local fixtures; they do not use an operator's identity or production state.

Optional installed-image and interoperability harnesses need a separately
prepared fixture at `.test-data/installed-fixture` and a synthetic service source
at `/workspace/peerwork-service`. Supply the documented fixture arguments for a
particular harness. These conventional paths are not bundled credentials or a
production service endpoint. Use a dedicated test environment for network,
process and load checks.

Unicode names, paths, bodies and canonical-encoding values are intentional input
data. Preserve their semantics and upstream notices when updating a test.
