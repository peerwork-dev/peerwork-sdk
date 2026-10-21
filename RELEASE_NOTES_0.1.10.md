# Native SDK 0.1.10 experimental candidate

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
