# Unreleased: one business authority

Ordinary clients rely on current service membership, grants and protocol rules.
Historical SDK-generated operation scopes must not silently preserve a second
business permission list after an upgrade.

Identity-owned native clients and managed ordinary clients use a dynamic policy
for supported operations, rather than a saved API operation list. Current
service membership, grants and protocol rules decide business authority.

The shared CLI/MCP lifecycle normalizes known generated scopes once at client
selection, before Context or new work. It includes old `SERVICE_CURRENT`
projections and does not depend on an operation-specific recovery allowlist.
Historical role-action requests never create per-alias signer delegates.
Sender, member/protocol discovery and management share the ordinary Space client.
Sealed native-managed bootstraps continue through their authenticated local
owner without editing the original credential or runtime configuration.

Only a proven generated projection can be replaced through its authenticated
original issuer. Explicit signer delegation and original parent restrictions
remain enforced. Old credentials and operation namespaces stay available for
their original pending work. This changes no Workspace grants, identity, keys,
host destination or service API.
