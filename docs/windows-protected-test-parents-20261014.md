# Protected Windows test parents

Source candidate `ab8da82ce4f32e257c10ac7b139a0119edaeef89` adds the
`cfg(test)` `protected_test_dir()` helper in
`crates/runtime/src/test_support.rs` (SHA-256
`f2b1ba3d5290be33116c096244f0611e41189b412d4e780ff28374cae847b858`).
It retains the temporary root for the test lifetime, uses a nested directory
created by `windows_fs::create_private_directory` on Windows, and retains a
0700 parent on Unix. The three existing `kernel_identity` tests and 19 more
tests in eight runtime files now use it. Production state checks are unchanged.

The exact affected test names are:

- `kernel_identity::tests::{explicit_create_reopen_and_incompatible_refusal,protected_pkcs8_pem_import_preserves_source_and_refuses_bad_input,protected_seed_import_preserves_source_and_refuses_overwrite}`
- `secure_grant_pending::tests::saved_owner_grant_is_exact_pending_and_reverified_after_restart`
- `secure_intents::tests::{saved_signed_commit_requires_every_immutable_row_pin_before_transport,lost_http_reply_then_restart_retries_identical_verified_packet,exact_packet_and_untrusted_response_survive_restart_without_acceptance}`
- `secure_journal_read::tests::{inline_pages_migrate_atomically_and_reopen_from_separate_files,additive_discovery_advances_protected_pin_and_refuses_rollback,chain_head_ignores_uncommitted_orphan_and_detects_page_mutation}`
- `secure_lifecycle::tests::{empty_lifecycle_persists_first_owner_pin,pending_keys_survive_reopen_without_regeneration_or_promotion,empty_pending_or_active_history_is_corrupt_on_reopen}`
- `secure_native_prepare::tests::{default_owner_workspace_uses_six_embedded_presets_without_posting,owner_bootstrap_stages_key_and_exact_packet_across_restart,native_protected_keys_stage_one_exact_pending_packet_without_reauthoring}`
- `secure_owner_format_transition::tests::old_private_saved_history_without_visibility_keeps_pending_packet`
- `secure_package_pending::tests::{exact_material_survives_restart_and_rejects_context_or_byte_change,input_bounds_refuse_before_first_write,damaged_saved_material_refuses_reopen}`
- `secure_recipient_state::tests::{published_rotation_preserves_exact_historical_recipient,recipient_create_reopen_and_signer_continuity}`

Rust 1.89 `cargo test --offline --locked -p peerwork-runtime --lib --no-run`
passed on the final committed bytes in session `88247`, using the isolated
`.build-target` and prior locked Cargo cache. Log:
`protected-test-dir-final-build.log`, SHA-256
`eaa5c6482b9bbcb22c181deee4cabb3e07b8a28def5ea44f75092ffe1be19330`.
Twenty-one exact, non-socket tests passed from the compiled test binary;
`protected-test-dir-offline.log` SHA-256
`f6b5a95d010262c2565e1db06cdd63ac723b37138d0656b77038224530433ef4`.
The remaining exact loopback test passed 1/1 in authorized local execution;
`protected-test-dir-loopback.log` SHA-256
`d9e8633a1de33058bfb7120f595c150f9f4ce5a9c9aa174fd38e853cc388dead`.
The first sandbox run reached `TcpListener::bind("127.0.0.1:0")` and failed
with `EPERM`, so it is an environment failure, preserved in
`protected-test-dir-affected.log` SHA-256
`706d3595e0991a0e46363b3792bdd4db14d6336fc91e0d03c2aa614d1ace9ead`.
That first log also records an accidental zero-test exact filter for an
incorrect identity test name; the corrected named identity test passed in the
21-test run. The import-order-only cleanup after test execution was followed
by the final-byte no-run compile; no behavior changed.

This is Linux regression evidence. Windows compilation and execution remain
unverified here. `secure_private_install.rs:2899` still has one raw temporary
parent and a raw nested state directory; the core owner will migrate that
fixture using the shared helper without changing its production code. These
fixtures do not establish readiness of the whole Windows runtime suite.
