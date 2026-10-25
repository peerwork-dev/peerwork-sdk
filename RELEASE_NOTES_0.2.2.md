# SDK 0.2.2 — Owner self-service archive migration

Status: source and integration qualification in progress; release assets and
production capability are not yet declared available.

- Node `migrateArchive`, Python `migrate_archive`/`migrate_archive_async` and
  `peerwork kernel migrate-archive` perform the complete Owner workflow.
- Current frozen source retrieval, local verified-capsule preparation, signed
  checkpoint upload, Backend validation/import and activation share one durable
  operation. Existing reviewed checkpoint files are also supported.
- Interrupted uploads resume committed offsets. A lost reply or process restart
  recovers the original job; completed recovery does not require the local file.
- Invalid artifacts fail before the actual archived workspace is touched.
  Other workspaces remain online. Bodies and keys retain E2EE boundaries.
- Discovery must advertise `owner-self-service-archive-migration-v1`. SDK 0.2.1
  can prepare offline artifacts but does not expose this high-level operation.

The migration default is an explicitly selected read-only historical snapshot.
Old workflows, memberships and PUBLIC publication are not silently restored.
Cold local source verification may take longer for large histories; the call
waits up to 180 seconds and returns a resumable ID if work remains.

See the [runnable migration guide](docs/legacy-space-migration-candidate.md).
Initial binary cohort: Linux x86_64 GNU, glibc 2.28+, Node 22+, Python 3.11+.
