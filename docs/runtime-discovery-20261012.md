# Kernel discovery continuity checkpoint, 2026-10-12

`KernelClient::open` now performs an actual HTTP GET through the configured
transport, requires a successful status, parses the exact response with the
core's lossless strict discovery schema, checks required features, and pins
the canonical origin plus exact discovery bytes in native SQLite. Discovery
is unsigned in the tracked TypeScript client. Its authority comes from the
configured HTTPS origin, TLS verification, strict schema, and persisted
continuity. Explicit loopback HTTP is available for local tests only.

On reopen, a changed origin or receipt key fails closed. The core's tracked
continuity rule permits additive features and newly named limits while
retaining the existing audience, key, semantics, and prior limits. The runtime
keeps the exact wire bytes, including escaped UTF-16, and caps discovery at
256 KiB; that cap is a native transport choice, not a TypeScript source limit.
No arbitrary external caller can write a discovery pin through the public
runtime API.

The actual localhost HTTP regression exercises first pin, rejected receipt
key rotation without rewriting the saved pin, additive feature update, and
changed-origin rejection after restart. The full Rust 1.89.0 locked offline
runtime suite passed 21/21 with authorized localhost socket access. This
checkpoint does not submit commands or establish signed receipt acceptance;
the capability manifest remains experimental.
