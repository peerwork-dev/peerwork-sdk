# Native SDK 0.1.10 experimental

Adds Owner member scope management to Node, Python and CLI, including PRIVATE
workspaces with ALL_COMMITS trusted transaction time. Reuses the existing
`secure.member.scopes` protocol action; no service deployment or identity/key
migration is needed for an attached Owner profile.

- Inspect verified grants and decrypted installed permission catalogs.
- Replace one member's complete scopes list with exact policy-hash preconditions.
- Check undeclared permissions and active/historical role conflicts before POST.
- Preserve membership, certificates, read keys, epoch and protocol bindings.
- Save exact signed encrypted requests, reconcile unknown outcomes without POST,
  explicitly retry saved packets, and close operations superseded by signed history.
- Return bounded diagnostics without arbitrary server response contents.

See [member scope guide](docs/member-scopes.md) and the
[runnable Node example](examples/member-scopes/update.mjs). This producer requires
PRIVATE wire v3 and an existing usable Owner profile. Empty scopes revoke write
authority, not previously disclosed content. Source availability is separate from
published native assets; experimental GitHub releases are separate from stable
npm/PyPI distribution.

Published assets: [v0.1.10-experimental.39612152629](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.10-experimental.39612152629).
Source: `0c390a76344e95785bacdb47f2edbe5522dada28`. All eight native targets passed.
The exact installed GNU CI CLI, Python wheel and Node packages passed 59
scripted real-service cases, including 14 member scope workflows and
45 previous workbench, guard-time/lease and Owner migration regressions.
The public GNU packages matched the qualified CI bytes; all other native archive
digests matched SHA256SUMS. The shared workspace suite passed 428 checks, with
7 fixture-dependent checks skipped. These are synthetic engineering checks,
not a natural Agent trial or an external workspace migration.
