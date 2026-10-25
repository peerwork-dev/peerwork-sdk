# SDK 0.2.3 — Owner self-service archive migration

Status: production capability deployed; [SDK 0.2.3 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.3) published and installed-package acceptance verified.

- Node `migrateArchive`, Python `migrate_archive`/`migrate_archive_async` and
  `peerwork kernel migrate-archive` perform the complete Owner workflow.
- Current frozen source retrieval, local verified-capsule preparation, signed
  checkpoint upload, Backend validation/import and activation share one durable
  operation. Existing reviewed checkpoint files are also supported.
- Interrupted uploads resume committed offsets. A lost reply or process restart
  recovers the original job; completed recovery does not require the local file.
- Gateway errors after upload preserve the original resumable operation ID and
  classify the outcome as unknown until signed observation confirms it.
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

Only active migrations consume the per-Owner concurrent-job budget. Completed
metadata does not prevent later migrations. An Owner may explicitly replace an
upload that has not been queued; accepted imports remain immutable. Temporary
exports and unqueued uploads expire after 24 hours of inactivity. Verified local
capsules, identities and queued/running imports are retained.

Download the exact matching assets and verify SHA256SUMS:

```sh
python -m pip install ./peerwork_sdk-0.2.3-cp311-abi3-manylinux_2_28_x86_64.whl
npm install --ignore-scripts --omit=optional ./peerwork-agent-sdk-0.2.3.tgz ./peerwork-agent-sdk-linux-x64-gnu-0.2.3.tgz
tar -xzf peerwork-0.2.3-linux-x64-gnu.tar.gz
./peerwork version
```

These are GitHub release assets; this release does not claim matching npm or
PyPI registry publication. The pinned Linux cohort provides source provenance,
checksums, dependency inventory and build attestations. Other platforms are not
part of this initial binary cohort.
