# Recover a protected marker-only object source

Use the marker-intent route when a legacy PRIVATE source has retained full proof/parts but no saved pending packet. Existing selected-packet object-stage methods remain separate. Python exposes `object_stage_intent_candidates`, `inspect_object_stage_intent`, `attach_object_stage_intent`, `recover_object_stage_intent` and `_async` counterparts; Node exposes `objectStageIntentCandidates`, `inspectObjectStageIntent`, `attachObjectStageIntent`, `recoverObjectStageIntent`. Candidate discovery returns redacted advisory metadata, not signed acceptance. It reads the explicitly selected protected source/PEM and does not initialize or replace identity.

For CLI, `secure owner-object-intent-candidates --help` describes a `SOURCE_INPUT_JSON_FILE` containing `workspace_id`, `protected_ts_state_path`, `protected_ts_intent_db_path`, `protected_owner_pkcs8_path`, `expected_owner_actor_id`, and `expected_owner_key_id`. Choose a candidate by that workspace and `instance_id`; keep its exact `marker_hash` (lowercase SHA256). The optional `original_command_id` is provenance, never permission to recreate a packet. Do not print the raw source state, keyring, PEM or signed requests.

```sh
peerwork secure owner-object-intent-candidates owner-config.json source-input.json
peerwork secure owner-object-intent-inspect owner-config.json source-input.json MARKER_SHA256 original-options.json selected-material.json
peerwork secure owner-object-intent-attach owner-config.json source-input.json MARKER_SHA256 INSPECTED_TS_STATE_DIGEST original-options.json selected-material.json
peerwork secure owner-object-intent-recover owner-config.json ATTACH_ID MARKER_SHA256
```

`owner-config.json` selects origin, protected native `state_dir`, loopback policy and replay bound. Source-input selects protected paths and exact Owner/workspace; original-options selects the exact `instance_id`, manifest/dependencies, entrypoint, explicit grants/disclosure and original reviewed checkpoint when present. Material is the complete caller-selected `{ "v": 1, "closure": { ... }, "bindings": { ... } }`; it is not an install envelope or authorization. Keep the original options bytes/meaning; do not manufacture grants or change a proof to fit current state. Inspect authenticates full options/material/proof and current Owner/key/epoch, returning `ts_state_digest`; attach requires that inspected digest. Inspect/attach do not POST.

After attachment, retain both `attach_id` and marker hash. `object_stage_intent_marker_hash` identifies that marker; `pending_object_stage_command_id` stays null because no original packet exists. Zero accepted parts stays `PENDING_UNRESOLVED`. `ATTACHED_RESTRICTED` requires explicit recovery until full SOURCE plus the distinct native BEGIN and signed END yield `ATTACHED`/`ACCEPTED`; interruption uses the same protected plan and exact saved native requests after a fresh handle. Candidate/history output alone never establishes fresh remote acceptance. This thin facade package changes no runtime/core semantics or broad capability flags. Installed service acceptance is a later combined-artifact gate.
