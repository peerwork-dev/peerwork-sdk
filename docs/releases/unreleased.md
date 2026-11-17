# Unreleased: generated client scope recovery

Ordinary clients rely on current service membership, grants and protocol rules.
Historical SDK-generated operation scopes must not silently preserve a second
business permission list after an upgrade.

The shared CLI/MCP lifecycle now considers any unsubmitted local scope denial
for the existing original-issuer recovery, instead of maintaining another list
of eligible actions. This includes a first exact-instance protocol lookup,
role instruction lookup and protocol resource read.

Only a proven generated projection can be replaced through its authenticated
original issuer. Explicit signer delegation and original parent restrictions
remain enforced. Old credentials and operation namespaces stay available for
their original pending work. This changes no Workspace grants, identity, keys,
host destination or service API.
