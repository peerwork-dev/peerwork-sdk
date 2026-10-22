# Native SDK 0.1.11 experimental candidate

Makes PRIVATE DIRECT protocol installation choose its transport before submitting
BEGIN. Small objects keep the existing path; oversized compiled objects are
staged as authenticated bounded parts. Node, Python and CLI retain one stable
install ID and exact signed packets across interrupted responses and restarts.

- Check the canonical UTF-8 size of each full inline object before authoring.
- Automatically stage oversized DIRECT protocol objects in an existing PRIVATE
  wire-v3 STRUCTURED workspace advertising `signed-protocol-object-source-v1`.
- Provide read-only install diagnostics that distinguish cached replay, fresh
  content checks and checkpoint failures without exporting content or keys.
- Provide a reviewed Owner recovery for one invalid inline BEGIN immediately
  after the verified ACTIVE predecessor, preserving signed history, identity,
  membership, certificates, epoch keys and guard-time policy. Install again with
  a new BEGIN after recovery; the original signed BEGIN remains immutable.
- Reject mismatched new wrappers and old native components before profile
  creation or installation writes.

[Transport and recovery guide](docs/private-install-transport-and-recovery.md)
contains Node/Python/CLI interfaces, resumable examples and exact restrictions.
Explicit package-stage installation still refuses oversized inline objects
before BEGIN; automatic conversion currently applies to DIRECT selection only.
Missing staging prerequisites cause an actionable refusal instead of a hidden
workspace-format or key migration.

Policy-restoring recovery also requires a matching service reporting
`owner-single-invalid-inline-install-v1` at
`GET /api/workspace/v1/install-capabilities`. Upgrade clients that verify this
workspace's complete history before applying recovery. Earlier verifiers may
refuse the repaired history; no verification bypass is provided. Imported
historical installs, multiple invalid operations and key/signature/provenance
failures are outside this narrow recovery path. Recovery must be reviewed and
invoked explicitly; installing a package does not repair a workspace by itself.

These are experimental GitHub native assets, separate from stable npm/PyPI
publication. Source availability and local qualification do not establish a
published native package or service availability.
