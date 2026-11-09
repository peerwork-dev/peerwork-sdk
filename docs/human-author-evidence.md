# Human Peer author evidence

Status: development candidate. The core library verifier exists on this work
branch; native runtime, CLI/MCP and service activation are still pending.
Published SDK 0.3.21 does not support Human Peer command authors. Do not treat
this document as an announced service endpoint or a released support version.

## Identity and signatures

A Human Peer has an offline recovery anchor, a rotatable operational account
root, and independent browser device keys. The Peer ID is the existing
key-derived actor hash of the recovery public key. Ordinary commands use a
device signature and retain that stable principal as actor_id.

The recovery anchor signs an account-root certificate in JWS domain
peerwork.account-root.v1+jws. Its payload binds the service audience, account,
Peer, root generation, operational signing key and account recipient public key.
The operational root signs a device certificate in domain
peerwork.human-device.v1+jws, binding the exact root certificate hash, device ID,
device signing key and separate device recipient public key.

A Human command carries an author reference with kind human-device-v1,
root_generation, root_certificate_hash, device_certificate_hash and device_id.
The command signature covers that entire reference. Certificate hashes are
lowercase SHA256 hex over exact compact JWS bytes, not reconstructed JSON.

The existing direct-key command entry point remains strict. A Human alias is
accepted only by the explicit proof-aware verifier, with the required original
root/device evidence. Missing proof never triggers a network fetch, historical
replay, directory guess or fallback to the actual device signer as principal.

## Core integration

The human_author module exposes verify_account_command, verify_root and
verify_device. An AuthorProofContext contains the selected immutable roots and
devices, each keyed by its exact certificate hash. It has format
peerwork.human-author-proofs.v1 and at most 32 entries in either map. Selected
certificate wires are limited to 4096 ASCII bytes before hashing or decoding.

Resolving a command reads two exact proof entries and verifies three signatures:
recovery-to-root, root-to-device and device-to-command. The result distinguishes
principal_actor_id from actual_signer_id and retains account, generation,
device and proof identifiers. Validated root/device Rust handles have private
constructors. Ordinary direct-key signatures keep their original actor invariant.

This result authenticates the author and validates the command shape. It grants
no Workspace membership, role, device activation or permission to execute.
The service must check active account/root/device/session/credential authority
in the same transaction as business authorization and acceptance.

Historical proof remains verifiable after revocation. A trusted original
acceptance receipt establishes when a command was accepted; a standalone old
signature or caller-supplied timestamp does not.

## Local verification

The library tests use independent Node-generated public proof vectors and
public certificates/commands produced by actual Chromium WebCrypto:

~~~sh
cargo test -p peerwork-core human_author
~~~

These tests require no production service, user identity or network directory.
The fixture files contain synthetic public evidence only. They establish the
core verifier boundary, not a completed account login, migration or SDK runtime
workflow.
