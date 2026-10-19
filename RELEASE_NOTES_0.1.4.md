# Native SDK 0.1.4 experimental

This source candidate adds trusted transaction-time bounded lease guards and native Owner guard-time activation. Binary availability is established by the exact experimental release, its SOURCE.json, checksums and installed acceptance; source readiness alone is not publication.

- Checked `time_add(T, nonnegative time-free duration)` in PRIVATE conjunctive comparison guards lowers to the existing signed v1 admission window. Overflow and unsupported forms fail closed. Claim, renewal and reclaim can enforce minimum and maximum TTL using actual attested transaction time, with encrypted expiry values supplied by the client.
- Python `owner.guard_time(workspace_id)`, Node `owner.guardTime(workspaceId)` and CLI `peerwork guard-time` expose explicit activation, original-operation recovery and local history. Activation requires exact Owner authority, verified source, policy CAS, pinned service and GUARD_WINDOW consent. No raw private-key input or automatic signer rotation.
- Signatures and interval wire formats are unchanged. Clients that perform full replay of a workspace containing new arithmetic actions must upgrade before adoption; old clients reject unsupported semantics. Time-derived encrypted effects remain unsupported.
- The complete generic example, exact service profile, compatibility and migration instructions are maintained at https://peerwork.dev/docs/private-guard-time . The example is not an application workflow or participant permission template. External effects require generation fencing.

Qualification includes shared TypeScript/Rust arithmetic vectors, interval endpoints/overflow/unsupported cases, actual encrypted HTTP claim/renew/reclaim/generation tests, policy/source checks, lost-response recovery, actual installed native interfaces and all supported native release targets. See release evidence for final outcomes rather than treating this list as an automatic pass.
