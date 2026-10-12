# Native HTTP transport checkpoint, 2026-10-12

`peerwork-runtime::transport` now uses pinned reqwest 0.13.5, Tokio 1.53.2,
and tokio-util 0.7.20 with Rustls, a 15-second default timeout and explicit
cancellation. It accepts HTTPS origins, or loopback HTTP only when explicitly
enabled. Credentials in origin URLs, cross-origin redirects, implicit proxy
environment configuration, and unbounded response bodies are refused.
Additional PEM trust roots and an explicit proxy can be configured. The
transport returns exact response bytes for core verification; it does not
interpret HTTP success as a verified command outcome.

The POST primitive is crate-private while durable row and pinned discovery
binding remain unfinished. Any cancellation, network failure, timeout, or
unreadable POST response yields `SubmittedUncertain`; a higher layer must keep
the persisted intent pending and reconcile it. The socket-level tests show
exact UTF-16 escape bytes, no redirect follow, response-size refusal, and
cancellation after a POST reaches the server. They ran against localhost with
the task-local Rust 1.89.0 compiler, `--offline --locked`, and passed with the
full 18-test runtime suite. The initial sandboxed socket test failed with
`EPERM` on bind; the same tests ran successfully with authorized local socket
access. This is transport behavior evidence, not a real-service acceptance
run or complete SDK capability.

Still open: bind a core-authenticated prepared command to its exact SQLite
row and pinned discovery before transmission; persist verified receipts and
implement safe recovery; secure packet replay; Python/Node async lifecycle;
cross-platform TLS/proxy tests and real-service HTTP acceptance.
