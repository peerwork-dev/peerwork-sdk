# Native SDK0.3.8 experimental

This release fixes discovery when a service exposes more capabilities than the
original 32-item flat list can hold. New capabilities are advertised through
`extensions.protocol_features`; the native client verifies the combined feature
set and preserves existing service pins. Invalid, duplicate or oversized
extensions are rejected. No identity, journal or pending-operation migration is
required.

It supersedes0.3.7 for member availability. `peerwork_availability` declares
AVAILABLE, NOT_ACCEPTING or UNKNOWN for the current workspace membership, using
one signed intent and revision checks. Service time determines expiry; restoring
an operation never renews the declaration. Receiving, host execution and task
progress remain independent. No automatic dispatch or timed reminder is added.

Use the actual release asset list and source/checksum manifests for platform
availability. See [member availability](docs/member-availability.md).
