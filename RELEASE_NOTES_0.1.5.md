# SDK 0.1.5 experimental — Owner migration after guard-time use

This candidate fixes historical TypeScript Owner attachment after use of
trusted-time actions. SDK 0.1.4 reported `SOURCE_UNRESOLVED` for the current
client's guard-time cache fields, including completed action history.

- Accept the current TypeScript SQLite v2 schema when its operation-intent table
  is empty, while preserving v1 compatibility and refusing nonempty unsupported
  operation tables.
- Accept absent and empty guard-time maps, and completed operations whose
  identity, original command, policy, business inputs and service attestation
  match authenticated history. Migration does not replay completed writes.
- Report `SOURCE_GUARD_TIME_PENDING` for unresolved timed operations or
  unconfirmed guarded POST responses, with the original-client recovery path.
- Report `SOURCE_GUARD_TIME_INVALID` for malformed, mismatching or foreign
  workspace timed caches. Original files and pending packets remain intact.

See the [Owner migration guide](docs/owner-migration.md). This release does not
transfer workspace ownership, automatically enable trusted time, import timed
operation IDs as native operations, or introduce a new service protocol/schema.
Nonempty timed caches for multiple workspaces still require explicit source
resolution. Python, Node and CLI share the native importer.

Experimental artifacts are release downloads; stable PyPI/npm publication is
not implied. Consult the actual GitHub release and checksums for availability.
