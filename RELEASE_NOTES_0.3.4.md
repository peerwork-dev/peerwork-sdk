# Native SDK0.3.4 experimental candidate

- Shared project ancestors such as POSIX0775 no longer prevent ordinary local
  onboarding. New connect and installation state lives in protected OS-user
  storage; project references contain no credentials.
- Existing identities, journals, client namespaces and unresolved IDs stay in
  place. Existing installation ownership uses its original lock; confirmed
  legacy registries use pinned directory handles. One local OS-owner confirmation
  is required where the original private namespace has writable ancestry.
- Project/registry directory identities persist across retries. Configuration
  reads, atomic updates and cleanup are anchored to verified directories; stale
  sources, substituted directories, foreign owners and conflicting edits are
  rejected. Process ownership remains enforced after fork.
- Local diagnostics identify the failed policy/component and effective UID;
  full paths are not exposed by MCP. The SDK changes no ancestor permissions.
- Verified live runtimes remain usable without unrelated admin repair. The
  client does not auto-start a signer whose original paths fail strict checks.
  Existing native0.3.3 runtimes with original-engine-binding-v1 remain supported.

Targets remain Linux x86_64 GNU, macOS ARM64 and Windows x86_64. No Node/Python
client runtime, service/schema migration or model-session recreation is added.
Generic current-session attachment limits remain unchanged. Validation uses
focused local semantic/IPC regressions and installed native process checks;
full model/latency/history matrices are not a default publication gate.
