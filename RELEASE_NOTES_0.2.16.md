# SDK 0.2.16 experimental — existing-session connectors

Codex now attaches to an explicitly selected existing App Server endpoint using
real Unix/WebSocket framing, verifies the loaded thread and optional session-root
binding, subscribes without full history, and submits only to the selected thread
and exact active turn. Implicit creation of a separate stdio App Server is removed;
intentional managed Codex/agy CLI processes require `managed: true`.

Antigravity App has a native Sidecar adapter using `agentapi send-message` for an
existing conversation. It never creates a conversation or injects permission-bypass
flags. Private bodies stay in bounded 0600 local inbox files; command arguments
contain only references. The adapter reports HOST_QUEUED, UNKNOWN execution and
QUEUED_ONLY/TOOL_ONLY availability. It does not claim REALTIME_READY or a model PONG.
The service capability `native-host-queue-v1` is required for native queue receipts.

The new `peerwork-host-bridge` separates the host OS user from the Peerwork signer.
A private capability authorizes loopback calls pinned to exact Peerwork bindings
and a host conversation. Existing identity/key ownership and original socket
permissions are preserved. Durable input/outcome records allow same-input replay
and read-only reconciliation after a lost acknowledgement; changed input and
unresolved host outcomes are refused. The bridge exposes no arbitrary RPC/shell
endpoint and never changes model/tool permission policies.

Existing receiver state/checkpoints are retained. A changed host destination must
be explicitly selected and cannot reuse a differently pinned state directory.
Upgrade old `kind: codex` profiles with an existing endpoint or explicit managed
opt-in. SDK0.2.13+ support for first-bound authored evidence is preserved.

Availability: versioned Linux x86_64 GNU glibc2.28+ assets; core Node22+/Python3.11+,
receiver/bridge Node24. Other platforms/registries are not published by this release.
Tests use actual Unix-WebSocket/HTTP transports, different OS UIDs, native signing
and synthetic host peers. A particular installed App or user live session still
requires explicit host registration and actual-session qualification. Startup
selftests may start/queue one model turn and incur provider cost.

See [native-session setup](docs/native-session-connectors.md).

Bridge permission responses are disabled by default; explicit delegation remains
restricted to approval requests from the selected thread. SDK0.2.15 was an
unpublished qualification candidate; install the published0.2.16 assets.
