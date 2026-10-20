# Import an existing PRIVATE member's recipient keys

SDK 0.1.8 source adds credential import for members already using the legacy
TypeScript client. SDK 0.1.7 has no public entry point for this import. Use the
qualified 0.1.8 experimental assets once published; source availability alone
is not an installed-package qualification.

The import retains the selected Ed25519 signing identity and imports the existing
P-256 recipient key, its signed certificate and the certificate-key history.
It accepts joined, multi-workspace legacy states. It never generates a replacement
identity, publishes a new certificate, re-invites a member or changes permissions.

## Select the original identity and source

Stop the old writer and retain a protected backup of its state JSON, signing PEM
and SQLite operation journal. Select the member's own files, not the Owner's.
Create an empty, private native profile directory and import the original signing
PEM with `import_legacy_identity_pem` / `importLegacyIdentityPem` or:

```sh
peerwork identity import-legacy-pem /absolute/native/identity.state /absolute/legacy/member.pem
```

If that native signing identity already exists, inspect it with `identity info`
and compare its actor and signing key pins instead of generating or replacing it.
Use those pins, reviewed against the selected member, for the next step. Compute
SHA-256 over the exact protected legacy state file; the import verifies those
same bytes before parsing them. Sources are bounded to 32 MiB and recipient
history to 128 certificates plus the current certificate. All paths must satisfy the SDK's private-file
and private-parent protections.

## Python

```python
from peerwork import SecureRecipientEnrollmentClient

recipient = SecureRecipientEnrollmentClient(origin, native_state_dir)
result = recipient.import_legacy_keys(
    protected_ts_state_path=legacy_state_path,
    expected_actor_id=member_actor_id,
    expected_signing_key_id=member_signing_key_id,
    expected_source_digest=reviewed_state_sha256,
)
```

`import_legacy_keys_async` provides the same operation asynchronously. No network
request is made by the credential import.

## Node

```js
const recipient = sdk.openSecureRecipientEnrollment({ origin, stateDir });
const result = await recipient.importLegacyKeys({
  protectedTsStatePath,
  expectedActorId,
  expectedSigningKeyId,
  expectedSourceDigest,
});
```

## CLI

Write a request JSON containing `protected_ts_state_path`, `expected_actor_id`,
`expected_signing_key_id` and `expected_source_digest`, then run:

```sh
peerwork secure recipient-import-legacy-keys \
  --origin=https://api.peerwork.dev \
  --state-dir=/absolute/native \
  --input=/absolute/import-request.json
```

Run `peerwork secure recipient-import-legacy-keys --help` for the machine-readable
request fields and migration boundary.

The result is `IMPORTED` or the idempotent `ALREADY_IMPORTED`, with public identity
pins, current certificate digest, historical certificate count and exact source
digest. Source files are not rewritten. Existing different native recipient keys
return `RECIPIENT_IMPORT_CONFLICT`; select an empty recipient profile with the
same original signing identity rather than deleting keys from a used profile.
`SOURCE_CHANGED` means the selected source digest differs. `IDENTITY_CHANGED`
means the signing pins differ. Invalid certificate/key/history bindings return
`RECIPIENT_IMPORT_INVALID`. A prepared legacy recipient rotation returns
`SOURCE_KEY_UPDATE_PENDING` and requires its original recovery path.

Generic `SecureReadClient` / `readSecurePrivateWorkspace` state directories are
bound to one workspace. Use a separate protected native directory per
member/service/workspace and repeat the pinned credential import for another
workspace. Do not reuse a directory already bound to A as B's read profile.
Each import reuses the same original signing identity and recipient credentials;
it does not ask the Owner to admit a new identity. The Owner client's separately
managed multi-workspace profile is a different interface.

## Verify each existing workspace

After import, use the existing `SecureReadClient.read_private()` /
`readSecurePrivateWorkspace` / `secure private-read` with the workspace and its
Owner actor/key pins. The read path obtains a grant for the current signed member.
For an invitation-backed grant, it retrieves the original invitation and ACCEPT,
verifies both signatures and grant bindings, and verifies the complete signed,
decrypted journal before promoting the keyring. Historical recipient certificates
select their matching imported private keys. It does not submit another ACCEPT
or receipt. Direct grants keep their existing verification path; delegated grants
without their required proof remain unsupported by this acquisition path.

Only then use the existing PRIVATE action client. Existing action scopes remain
enforced; credential import grants no new role or write permission. Reopen and
read every migrated workspace before retiring an old runtime.

This is recipient credential migration, not an import of all legacy application
state or pending work. Legacy SQLite intents, uncertain packets, coordination
markers, receipts and checkpoints stay in the original protected source. Recover
or review their original operations explicitly; a fresh native pending list does
not establish that the old client had no unfinished work. Keep the source and
backup until that review is complete. Local credential import does not assert
current directory publication, active membership or a service's feature support.

## Qualification

`tests/legacy-member-keys-migration.mjs` generates two old members on one machine,
joins both to two signed/E2EE workspaces and rotates their recipient directory
keys while workspace grants still address historical certificates. Installed
Python and Node consumers import and retry; CLI repeats the import. The workflow
checks source preservation, cross-worker denial, corrupt invitation evidence
rejection, source-free reopen and authorized PRIVATE writes under the original
identities. It runs against an isolated local service with generated keys. This
is scripted engineering acceptance, not a natural Agent workflow trial.
