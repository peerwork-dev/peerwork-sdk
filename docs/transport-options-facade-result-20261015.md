# Transport options facade result

This checkpoint exposes the native transport settings through Python and Node client constructors while leaving existing call shapes unchanged when `transport` is omitted. The public option carries a positive timeout in milliseconds (default 15,000) and up to 16 nonempty CA file paths. Facades validate option shape and serialize paths only; they never read certificate contents. Native code remains responsible for file size, aggregate size, certificate parsing, and checked deadline construction.

Explicit options are sent to JSON-config native calls as `transport: { request_timeout_ms, additional_root_pem_files }`. Kernel, recipient-enrollment, and identity-directory bridges pass the same JSON as their new final optional native argument. `load_config` returns normalized transport settings only when the selected protected config specified transport; the Node facade maps those two fields to camelCase. Omission keeps the prior config JSON free of a `transport` key and sends the native bridge's absent optional value.

Python exposes `TransportOptions`; `load_config()` converts selected normalized settings to that same object, so callers can pass `config["transport"]` directly into a client. Node exposes `TransportOptions` and maps selected config to camelCase for direct reuse. Profile-backed actions, installers, private reads, admissions, and invitations reuse the same client transport config. Async methods reuse their parent's config. Existing positional constructor arguments, identity and authority selection, and TLS defaults remain as before.

Focused verification used native-boundary stubs only:

- `python3 tests/transport-options-python.py` — explicit and omitted marshalling, exported config shape, timeout/path validation, and all dedicated bridge positions passed.
- `python3 -m py_compile bindings/python/peerwork/__init__.py` — passed.
- Node 24.20.0: `node tests/transport-options-node.mjs` and `node --check bindings/node/index.cjs` — passed.
- TypeScript 7 strict check of `tests/transport-options-types.ts` — passed.

These checks establish facade mapping and type/syntax behavior, not real certificate loading, network behavior, async executor behavior, or a compiled installed SDK runtime. Native validation and TLS behavior are owned by the concurrent native checkpoint.
