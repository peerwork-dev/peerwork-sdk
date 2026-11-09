# Human Peer author evidence

Status: development candidate. The core verifier and selected native
HTTP/mailbox read paths and account-recipient request verification exist on this
work branch. Complete browser accounts, public-reading, CLI/MCP qualification and service
activation are still pending.
Published SDK 0.3.21 does not support Human Peer command authors. Do not treat
this document as an announced service endpoint or a released support version.

## Account recipient requests

The development core accepts explicit `peerwork.access-request.v3+jws` Human
browser requests through `structure_access::verify_access_request`. Their v2
recipient certificate binds a stable Human principal, the exact root and device
JWS strings, the actual device signer and the root's account recipient key.
Its signature domain is `peerwork.account-recipient-certificate.v1`. Native v1
certificates and v1/v2 requests remain strict direct-key formats.

Existing `StructureAccessApproval` preparation recognizes this request's signed
persistent policy and requires `account-bound-space-access-v1` service support.
It uses the ordinary Owner approval operation; it does not replace the Owner
identity or invent another local operation namespace. Request version3 retains
the existing persistent authorization version2. A second activated Human device
can use that account's existing member and recipient-key grant.

The service must still validate current requester account/device/session/credential
state under its transaction fences. Pure certificate verification never supplies
that current authority. Historical original Owner grants remain independently
verifiable after requester revocation and are not re-applied during recovery.

`crates/core/tests/fixtures/human-access-v1.json` is a synthetic public fixture
produced by an independent actual HTTP/PostgreSQL Node implementation. It contains
no private scalar or signing seed. Core verifies that original request and Owner
grant, then seals a new opaque body-key box. The independent Node opener verifies
that ciphertext on local TEST while retaining its private recipient there.
This is not a full released CLI/MCP or multiple-browser receiving claim.

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
accepted by a proof-aware source verifier, with the required original
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

## Selected HTTP and mailbox sources

Structured HTTP results carry an optional top-level author_proofs section.
The normal service receipt binds its exact bytes with the rest of the result.
The Native command-response verifier passes this context to supported record,
protocol-bundle, message, key-source and management-source verifiers. It never
searches business structure, encrypted bodies or bundle resources for proofs.
VerifiedCommandResponse::author_proofs exposes the parsed bounded context.

For explicit library integrations, use
verify_structure_author_intent_with_proofs with the selected source JWS,
pinned audience and AuthorProofContext. The existing
verify_structure_author_intent function supplies no proof context and retains
its direct-key boundary. Local prepared commands, pending packets and Native
operation namespaces remain direct-key; accepting a Human source does not
authorize changing the local signing identity.

A mailbox frame optionally carries author_proofs with an author_proofs_digest
in its service-signed frame proof. Both fields must occur together. Source
authors, recipients, acceptance evidence and ciphertext associations are still
checked individually. A malformed or missing required proof is a verification
failure, never an empty inbox.

Native inbox custody seals the complete original verified frame. After restart,
selected message reads project only the two referenced certificates from that
frame, preserving the original message envelope and cursor. Plaintext is opened
on access and is not stored in the inbox. AAD continues to bind the stable Peer
actor, not the device signer. A present but incorrect key cannot be relabeled
as a successful decryption.

Online/expiry observations carry service event receipts. These establish
service-observed state, not an independent Peer business signature. A presence
pulse or host report cannot be substituted for ordinary business authorship.

## Local verification

The library tests use independent Node-generated public proof vectors and
public certificates/commands produced by actual Chromium WebCrypto:

~~~sh
cargo test -p peerwork-core human_author
cargo test -p peerwork-core human_source_transport_tests
cargo test -p peerwork-runtime human_source_transport_tests
~~~

These tests require no production service, user identity or network directory.
The fixture files contain synthetic public evidence only. They establish the
core and selected custody/opening boundaries, not a completed account login,
migration, public-reader or live CLI/MCP workflow. The transport fixture contains
real HTTP/SSE wires produced by independent account/Space handlers with
PostgreSQL. Its service seed, Native recipient seed and body key are intentionally
fixed synthetic test inputs; no operational Human vault or production key is
included. The tests also re-sign selected adversarial service responses so that
source-proof checks are exercised beyond the outer service digest.
