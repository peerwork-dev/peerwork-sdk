//! Protected exact grant evidence. Reopening re-verifies cryptographic grant
//! material at the caller's current time; nothing here activates epoch keys.

use crate::{
    kernel_identity::KernelIdentity,
    secure_recipient_state::RecipientState,
    secure_state::{SecureStateError, SecureStateStore},
    secure_verified_read::TransportReplayedJournal,
};
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::sha256_hex,
    replayed_secure_journal::StructureStatus,
    secure_keyring::SecretKeyring,
    verified_secure_grant::{
        verify_direct_key_grant, GrantError, GrantProofInput, InvitationProofInput,
        VerifiedGrantMaterial,
    },
    wire_json::{canonical_wire_value, parse_wire_json_bounded},
};
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"PEERWORK-PENDING-GRANT\n1\n";
const MAX_EVIDENCE: usize = 64 * 1024 * 1024;
const MAX_CHAIN: usize = 1024;

#[derive(Debug, Error)]
pub(crate) enum PendingGrantError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error(transparent)]
    Proof(#[from] GrantError),
    #[error("pending grant evidence is invalid or incomplete")]
    Invalid,
    #[error("pending grant origin, owner, workspace or local identity changed")]
    PinChanged,
    #[error("a different pending grant is already saved")]
    Conflict,
    #[error("signed grant does not bind to the completed source journal")]
    ReplayMismatch,
}

/// Private-constructor result of reverified signed grant material bound to
/// the same configured-origin, exact-checkpoint full replay that decrypted
/// with this keyring. Only this token may enter lifecycle promotion.
pub(crate) struct GrantActivationProof {
    material: VerifiedGrantMaterial,
    origin: String,
    workspace: String,
    owner_actor: String,
    owner_key: String,
    local_actor: String,
}

impl GrantActivationProof {
    pub(crate) fn keyring(&self) -> &SecretKeyring {
        self.material.keyring()
    }
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn workspace(&self) -> &str {
        &self.workspace
    }
    pub(crate) fn owner_actor(&self) -> &str {
        &self.owner_actor
    }
    pub(crate) fn owner_key(&self) -> &str {
        &self.owner_key
    }
    pub(crate) fn local_actor(&self) -> &str {
        &self.local_actor
    }
}

pub(crate) struct GrantEvidence<'a> {
    pub policies: &'a [&'a [u8]],
    pub commits: &'a [&'a [u8]],
    pub checkpoint: &'a [u8],
    pub grant: &'a [u8],
    pub certificate: &'a [u8],
    pub invitation: Option<(&'a [u8], &'a [u8])>,
    pub delegation: Option<&'a [u8]>,
}

/// One immutable pending grant per protected path. The policy/commit pages
/// must be fetched through the configured origin by the caller; this store
/// pins their exact bytes but cannot establish transport provenance itself.
pub(crate) struct SecureGrantPending {
    store: SecureStateStore,
    saved: Option<Zeroizing<Vec<u8>>>,
    origin: String,
    audience: String,
    workspace: String,
    owner_actor: String,
    owner_key: String,
    local_actor: String,
    local_key: String,
}

impl SecureGrantPending {
    pub(crate) fn open(
        path: &Path,
        origin: &str,
        audience: &str,
        workspace: &str,
        owner_actor: &str,
        owner_key: &str,
        identity: &KernelIdentity,
        recipient: &RecipientState,
        now: u64,
    ) -> Result<Self, PendingGrantError> {
        if origin.is_empty()
            || audience.is_empty()
            || workspace.is_empty()
            || owner_actor.is_empty()
            || owner_key.is_empty()
        {
            return Err(PendingGrantError::Invalid);
        }
        let store = SecureStateStore::open(path)?;
        let saved = store.read_exact_secret()?;
        let result = Self {
            store,
            saved,
            origin: origin.into(),
            audience: audience.into(),
            workspace: workspace.into(),
            owner_actor: owner_actor.into(),
            owner_key: owner_key.into(),
            local_actor: identity.actor_id().into(),
            local_key: identity.key_id().into(),
        };
        if let Some(bytes) = result.saved.as_ref() {
            result.verify_saved(bytes, recipient, now)?;
        }
        Ok(result)
    }

    /// Verifies before first durable write. Repeated calls accept only the
    /// identical signed bytes, never a re-sealed or re-signed replacement.
    pub(crate) fn stage(
        &mut self,
        evidence: GrantEvidence<'_>,
        recipient: &RecipientState,
        now: u64,
    ) -> Result<VerifiedGrantMaterial, PendingGrantError> {
        self.preflight(&evidence)?;
        let proof = self.verify(&evidence, recipient, now)?;
        let bytes = self.encode(&evidence)?;
        if let Some(saved) = &self.saved {
            if saved.as_slice() != bytes.as_slice() {
                return Err(PendingGrantError::Conflict);
            }
            return Ok(proof);
        }
        self.store.write_exact(&bytes)?;
        self.saved = Some(bytes);
        Ok(proof)
    }

    /// Re-opened material is returned only after fresh-time verification.
    /// Caller must still obtain complete replay/checkpoint authority before
    /// any promotion of the returned keyring.
    pub(crate) fn verified_pending(
        &self,
        recipient: &RecipientState,
        now: u64,
    ) -> Result<Option<VerifiedGrantMaterial>, PendingGrantError> {
        self.saved
            .as_ref()
            .map(|bytes| self.verify_saved(bytes, recipient, now))
            .transpose()
    }

    /// A saved grant's own signed chain must end at precisely the same
    /// checkpoint as the origin-bound, fully replayed transport history. The
    /// replay must have used exactly the reverified grant keyring and must be
    /// active rather than a structured snapshot prefix.
    pub(crate) fn bind_to_replay(
        &self,
        recipient: &RecipientState,
        now: u64,
        replay: &TransportReplayedJournal,
    ) -> Result<Option<GrantActivationProof>, PendingGrantError> {
        let Some(saved) = &self.saved else {
            return Ok(None);
        };
        if replay.origin() != self.origin
            || replay.source_actor_id() != self.local_actor
            || replay.source_key_id() != self.local_key
            || replay.replay().workspace_id() != self.workspace
            || replay.replay().owner_actor_id() != self.owner_actor
            || replay.replay().owner_signing_key() != self.owner_key
            || replay.replay().structure_status() == StructureStatus::Seeding
        {
            return Err(PendingGrantError::ReplayMismatch);
        }
        let (.., checkpoint, _, _, _, _, _) = decode(saved)?;
        let checkpoint_value =
            parse_wire_json_bounded(checkpoint, 8, 4096).map_err(|_| PendingGrantError::Invalid)?;
        let canonical_checkpoint =
            canonical_wire_value(&checkpoint_value, CanonicalPath::SecureArtifact)
                .map_err(|_| PendingGrantError::Invalid)?;
        if canonical_checkpoint != replay.checkpoint_canonical_json() {
            return Err(PendingGrantError::ReplayMismatch);
        }
        let material = self.verify_saved(saved, recipient, now)?;
        let ring_wire = material
            .keyring()
            .canonical_wire()
            .map_err(|_| PendingGrantError::Invalid)?;
        let public_empty = material.epoch() == 0 && material.keyring().epochs().next().is_none();
        let replayed_keyring_matches = if public_empty {
            // PUBLIC commits have no epoch ciphertext. Complete signed replay
            // still binds the selected policy and checkpoint; the grant
            // verifier separately proves the empty keyring and recipient.
            replay.grant_keyring_sha256().is_none()
        } else {
            replay.grant_keyring_sha256() == Some(sha256_hex(&ring_wire).as_str())
        };
        if !replayed_keyring_matches {
            return Err(PendingGrantError::ReplayMismatch);
        }
        Ok(Some(GrantActivationProof {
            material,
            origin: self.origin.clone(),
            workspace: self.workspace.clone(),
            owner_actor: self.owner_actor.clone(),
            owner_key: self.owner_key.clone(),
            local_actor: self.local_actor.clone(),
        }))
    }

    fn verify_saved(
        &self,
        bytes: &[u8],
        recipient: &RecipientState,
        now: u64,
    ) -> Result<VerifiedGrantMaterial, PendingGrantError> {
        let (pins, policies, commits, checkpoint, grant, certificate, offer, decision, delegation) =
            decode(bytes)?;
        let expected = [
            &self.origin,
            &self.audience,
            &self.workspace,
            &self.owner_actor,
            &self.owner_key,
            &self.local_actor,
            &self.local_key,
        ];
        if pins
            .iter()
            .zip(expected)
            .any(|(saved, current)| *saved != current.as_bytes())
        {
            return Err(PendingGrantError::PinChanged);
        }
        let evidence = GrantEvidence {
            policies: &policies,
            commits: &commits,
            checkpoint,
            grant,
            certificate,
            invitation: offer.zip(decision),
            delegation,
        };
        if offer.is_some() != decision.is_some() {
            return Err(PendingGrantError::Invalid);
        }
        self.verify(&evidence, recipient, now)
    }

    fn verify(
        &self,
        evidence: &GrantEvidence<'_>,
        recipient: &RecipientState,
        now: u64,
    ) -> Result<VerifiedGrantMaterial, PendingGrantError> {
        let result = verify_direct_key_grant(GrantProofInput {
            policy_wires: evidence.policies,
            commit_wires: evidence.commits,
            checkpoint_wire: evidence.checkpoint,
            grant_wire: evidence.grant,
            recipient_certificate_wire: evidence.certificate,
            recipient: recipient.recipient(),
            workspace_id: &self.workspace,
            trusted_owner_actor: &self.owner_actor,
            trusted_owner_key: &self.owner_key,
            now,
            expected_invitation: evidence.invitation.map(|(offer, decision)| {
                InvitationProofInput {
                    offer_wire: offer,
                    decision_wire: decision,
                }
            }),
            expected_delegation_wire: evidence.delegation,
            expected_delegation_origin: evidence.delegation.map(|_| self.origin.as_str()),
            expected_delegation_audience: evidence.delegation.map(|_| self.audience.as_str()),
        })?;
        if result.workspace_id() != self.workspace
            || result.recipient_actor() != self.local_actor
            || result.recipient_key() != self.local_key
        {
            return Err(PendingGrantError::PinChanged);
        }
        Ok(result)
    }

    fn encode(
        &self,
        evidence: &GrantEvidence<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, PendingGrantError> {
        if evidence.policies.is_empty()
            || evidence.policies.len() > MAX_CHAIN
            || evidence.commits.len() > MAX_CHAIN
        {
            return Err(PendingGrantError::Invalid);
        }
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(MAGIC);
        for value in [
            &self.origin,
            &self.audience,
            &self.workspace,
            &self.owner_actor,
            &self.owner_key,
            &self.local_actor,
            &self.local_key,
        ] {
            put(&mut out, value.as_bytes())?
        }
        out.extend_from_slice(&(evidence.policies.len() as u16).to_be_bytes());
        for wire in evidence.policies {
            put(&mut out, wire)?
        }
        out.extend_from_slice(&(evidence.commits.len() as u16).to_be_bytes());
        for wire in evidence.commits {
            put(&mut out, wire)?
        }
        for wire in [evidence.checkpoint, evidence.grant, evidence.certificate] {
            put(&mut out, wire)?
        }
        match evidence.invitation {
            Some((offer, decision)) => {
                out.push(1);
                put(&mut out, offer)?;
                put(&mut out, decision)?
            }
            None => out.push(0),
        }
        match evidence.delegation {
            Some(wire) => {
                out.push(1);
                put(&mut out, wire)?
            }
            None => out.push(0),
        }
        if out.len() > MAX_EVIDENCE {
            return Err(PendingGrantError::Invalid);
        }
        Ok(out)
    }

    /// Bound caller-owned aggregate bytes before the core parser, signature
    /// scan or HPKE work. Encoding performs the same bound defensively.
    fn preflight(&self, evidence: &GrantEvidence<'_>) -> Result<(), PendingGrantError> {
        if evidence.policies.is_empty()
            || evidence.policies.len() > MAX_CHAIN
            || evidence.commits.len() > MAX_CHAIN
        {
            return Err(PendingGrantError::Invalid);
        }
        let mut total = MAGIC.len() + 2 + 2 + 2;
        for part in [
            &self.origin,
            &self.audience,
            &self.workspace,
            &self.owner_actor,
            &self.owner_key,
            &self.local_actor,
            &self.local_key,
        ] {
            total = total
                .checked_add(4)
                .and_then(|n| n.checked_add(part.len()))
                .ok_or(PendingGrantError::Invalid)?;
        }
        for part in evidence
            .policies
            .iter()
            .copied()
            .chain(evidence.commits.iter().copied())
            .chain([evidence.checkpoint, evidence.grant, evidence.certificate])
            .chain(
                evidence
                    .invitation
                    .into_iter()
                    .flat_map(|(offer, decision)| [offer, decision]),
            )
            .chain(evidence.delegation)
        {
            if part.is_empty() || part.len() > MAX_EVIDENCE {
                return Err(PendingGrantError::Invalid);
            }
            total = total
                .checked_add(4)
                .and_then(|n| n.checked_add(part.len()))
                .ok_or(PendingGrantError::Invalid)?;
            if total > MAX_EVIDENCE {
                return Err(PendingGrantError::Invalid);
            }
        }
        if total > MAX_EVIDENCE {
            return Err(PendingGrantError::Invalid);
        }
        Ok(())
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PendingGrantError> {
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| PendingGrantError::Invalid)?;
    if bytes.is_empty()
        || bytes.len() > MAX_EVIDENCE
        || out
            .len()
            .checked_add(bytes.len())
            .and_then(|len| len.checked_add(4))
            .is_none_or(|len| len > MAX_EVIDENCE)
    {
        return Err(PendingGrantError::Invalid);
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

type Decoded<'a> = (
    [&'a [u8]; 7],
    Vec<&'a [u8]>,
    Vec<&'a [u8]>,
    &'a [u8],
    &'a [u8],
    &'a [u8],
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
);
fn decode(bytes: &[u8]) -> Result<Decoded<'_>, PendingGrantError> {
    if bytes.len() > MAX_EVIDENCE || !bytes.starts_with(MAGIC) {
        return Err(PendingGrantError::Invalid);
    }
    let mut reader = Reader {
        bytes: &bytes[MAGIC.len()..],
    };
    let mut pins = [b"".as_slice(); 7];
    for item in &mut pins {
        *item = reader.field()?
    }
    let policy_count = reader.count()?;
    if policy_count == 0 || policy_count > MAX_CHAIN {
        return Err(PendingGrantError::Invalid);
    }
    let mut policies = Vec::with_capacity(policy_count);
    for _ in 0..policy_count {
        policies.push(reader.field()?)
    }
    let commit_count = reader.count()?;
    if commit_count > MAX_CHAIN {
        return Err(PendingGrantError::Invalid);
    }
    let mut commits = Vec::with_capacity(commit_count);
    for _ in 0..commit_count {
        commits.push(reader.field()?)
    }
    let checkpoint = reader.field()?;
    let grant = reader.field()?;
    let certificate = reader.field()?;
    let (offer, decision) = match reader.flag()? {
        0 => (None, None),
        1 => (Some(reader.field()?), Some(reader.field()?)),
        _ => return Err(PendingGrantError::Invalid),
    };
    let delegation = match reader.flag()? {
        0 => None,
        1 => Some(reader.field()?),
        _ => return Err(PendingGrantError::Invalid),
    };
    if !reader.bytes.is_empty() {
        return Err(PendingGrantError::Invalid);
    }
    Ok((
        pins,
        policies,
        commits,
        checkpoint,
        grant,
        certificate,
        offer,
        decision,
        delegation,
    ))
}
struct Reader<'a> {
    bytes: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingGrantError> {
        if self.bytes.len() < len {
            return Err(PendingGrantError::Invalid);
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head)
    }
    fn field(&mut self) -> Result<&'a [u8], PendingGrantError> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if len == 0 || len > MAX_EVIDENCE {
            return Err(PendingGrantError::Invalid);
        }
        self.take(len)
    }
    fn count(&mut self) -> Result<usize, PendingGrantError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize)
    }
    fn flag(&mut self) -> Result<u8, PendingGrantError> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerwork_core::{
        canonical::{canonical, Path as CanonicalPath},
        crypto::{base64url, sha256_hex, sign_canonical},
        secure_keyring::SecretKeyring,
    };
    use serde_json::{json, Value};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn signed(payload: Value, domain: &str, identity: &KernelIdentity) -> Value {
        let signature = sign_canonical(domain, &payload, identity.signing_key()).unwrap();
        json!({"payload":payload,"signature":signature})
    }
    fn wire(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn saved_owner_grant_is_exact_pending_and_reverified_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = KernelIdentity::create(&dir.path().join("identity.state")).unwrap();
        let recipient = RecipientState::create(
            &dir.path().join("recipient.state"),
            &identity,
            1_700_000_000_000,
        )
        .unwrap();
        let now = 1_700_000_000_001;
        let workspace = base64url(&[42u8; 32]);
        let certificate = serde_json::to_value(recipient.certificate()).unwrap();
        let policy = signed(
            json!({"v":1,"workspace_id":workspace,
            "owner_id":identity.actor_id(),"signing_key":identity.key_id(),"version":1,
            "previous_policy":null,"effective_sequence":1,"visibility":"PRIVATE",
            "epoch":1,"members":[{"actor_id":identity.actor_id(),"certificate":certificate,
                "role":"OWNER","scopes":[]}],"issued_at":now-1}),
            "peerwork.secure.policy.v1",
            &identity,
        );
        let policy_hash = sha256_hex(
            canonical(&policy, CanonicalPath::SecureArtifact)
                .unwrap()
                .as_bytes(),
        );
        let checkpoint = json!({"v":1,"workspace_id":workspace,"owner_id":identity.actor_id(),
            "owner_key":identity.key_id(),"sequence":0,"head":null,"policy_hash":policy_hash});
        let ring = SecretKeyring::new_private(&workspace, 1).unwrap();
        let context = json!({"v":1,"grant_id":base64url(&[43u8;32]),"workspace_id":workspace,
            "actor_id":identity.actor_id(),"signing_key":identity.key_id(),
            "recipient":certificate,"policy_hash":policy_hash,"epoch":1,
            "invite_id":null,"acceptance_hash":null,"delegation":null,"issued_at":now});
        let context_wire = canonical(&context, CanonicalPath::SecureArtifact).unwrap();
        let box_value = ring
            .seal_to(recipient.recipient().public_jwk(), context_wire.as_bytes())
            .unwrap();
        let mut grant_payload = context;
        grant_payload["box"] = serde_json::to_value(box_value).unwrap();
        let grant = signed(grant_payload, "peerwork.secure.key-grant.v1", &identity);
        let policy_wire = wire(&policy);
        let checkpoint_wire = wire(&checkpoint);
        let grant_wire = wire(&grant);
        let certificate_wire = wire(&certificate);
        let policies = [&policy_wire[..]];
        let evidence = GrantEvidence {
            policies: &policies,
            commits: &[],
            checkpoint: &checkpoint_wire,
            grant: &grant_wire,
            certificate: &certificate_wire,
            invitation: None,
            delegation: None,
        };
        let path = dir.path().join("grant.state");
        let origin = "https://synthetic.invalid/";
        let mut pending = SecureGrantPending::open(
            &path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now,
        )
        .unwrap();
        assert!(pending.verified_pending(&recipient, now).unwrap().is_none());
        let too_many = vec![b"x".as_slice(); MAX_CHAIN + 1];
        let oversized = GrantEvidence {
            policies: &too_many,
            commits: &[],
            checkpoint: &checkpoint_wire,
            grant: &grant_wire,
            certificate: &certificate_wire,
            invitation: None,
            delegation: None,
        };
        assert!(matches!(
            pending.stage(oversized, &recipient, now),
            Err(PendingGrantError::Invalid)
        ));
        assert!(pending.verified_pending(&recipient, now).unwrap().is_none());
        let proof = pending.stage(evidence, &recipient, now).unwrap();
        assert_eq!(proof.epoch(), 1);
        assert!(proof.keyring().key_at(1).is_some());
        let exact = GrantEvidence {
            policies: &policies,
            commits: &[],
            checkpoint: &checkpoint_wire,
            grant: &grant_wire,
            certificate: &certificate_wire,
            invitation: None,
            delegation: None,
        };
        pending.stage(exact, &recipient, now).unwrap();
        let mut changed = grant_wire.clone();
        changed.push(b' ');
        let conflict = GrantEvidence {
            policies: &policies,
            commits: &[],
            checkpoint: &checkpoint_wire,
            grant: &changed,
            certificate: &certificate_wire,
            invitation: None,
            delegation: None,
        };
        assert!(matches!(
            pending.stage(conflict, &recipient, now),
            Err(PendingGrantError::Conflict)
        ));
        drop(pending);
        let reopened = SecureGrantPending::open(
            &path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 1,
        )
        .unwrap();
        assert!(reopened
            .verified_pending(&recipient, now + 1)
            .unwrap()
            .is_some());
        drop(reopened);
        assert!(matches!(
            SecureGrantPending::open(
                &path,
                "https://wrong.invalid/",
                "synthetic",
                &workspace,
                identity.actor_id(),
                identity.key_id(),
                &identity,
                &recipient,
                now + 1
            ),
            Err(PendingGrantError::PinChanged)
        ));
        // A direct grant has no opening-time expiry: the certificate is
        // checked at grant issuance by the tracked opener. Reopen still
        // passes a fresh `now` for invitation/delegation validity.
        assert!(SecureGrantPending::open(
            &path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 367 * 86_400_000
        )
        .is_ok());
        let delegation = signed(
            json!({"v":1,"workspace_id":workspace,
            "actor_id":identity.actor_id(),"signing_key":identity.key_id(),
            "device":certificate,"request_id":base64url(&[44u8;32]),
            "scope":[],"read":true,"origin":origin,"audience":"synthetic",
            "issued_at":now,"expires_at":now+10}),
            "peerwork.secure.device-delegation.v1",
            &identity,
        );
        let delegated_context = json!({"v":1,"grant_id":base64url(&[45u8;32]),
            "workspace_id":workspace,"actor_id":identity.actor_id(),
            "signing_key":identity.key_id(),"recipient":certificate,
            "policy_hash":policy_hash,"epoch":1,"invite_id":null,
            "acceptance_hash":null,"delegation":delegation,"issued_at":now+1});
        let delegated_context_wire =
            canonical(&delegated_context, CanonicalPath::SecureArtifact).unwrap();
        let delegated_box = ring
            .seal_to(
                recipient.recipient().public_jwk(),
                delegated_context_wire.as_bytes(),
            )
            .unwrap();
        let mut delegated_payload = delegated_context;
        delegated_payload["box"] = serde_json::to_value(delegated_box).unwrap();
        let delegated_grant = signed(delegated_payload, "peerwork.secure.key-grant.v1", &identity);
        let delegated_grant_wire = wire(&delegated_grant);
        let delegation_wire = wire(&delegation);
        let delegated_path = dir.path().join("delegated-grant.state");
        let mut delegated = SecureGrantPending::open(
            &delegated_path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 2,
        )
        .unwrap();
        delegated
            .stage(
                GrantEvidence {
                    policies: &policies,
                    commits: &[],
                    checkpoint: &checkpoint_wire,
                    grant: &delegated_grant_wire,
                    certificate: &certificate_wire,
                    invitation: None,
                    delegation: Some(&delegation_wire),
                },
                &recipient,
                now + 2,
            )
            .unwrap();
        drop(delegated);
        assert!(SecureGrantPending::open(
            &delegated_path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 9
        )
        .is_ok());
        assert!(SecureGrantPending::open(
            &delegated_path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 10
        )
        .is_err());
        let other_recipient = RecipientState::create(
            &dir.path().join("other-recipient.state"),
            &identity,
            now - 1,
        )
        .unwrap();
        assert!(SecureGrantPending::open(
            &path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &other_recipient,
            now + 1
        )
        .is_err());
        let state = SecureStateStore::open(&path).unwrap();
        let mut saved = state.read_exact_secret().unwrap().unwrap();
        let marker = b"\"signature\":\"";
        let offset = saved
            .windows(marker.len())
            .position(|part| part == marker)
            .unwrap()
            + marker.len();
        saved[offset] = if saved[offset] == b'A' { b'B' } else { b'A' };
        state.write_exact(&saved).unwrap();
        drop(state);
        assert!(SecureGrantPending::open(
            &path,
            origin,
            "synthetic",
            &workspace,
            identity.actor_id(),
            identity.key_id(),
            &identity,
            &recipient,
            now + 1
        )
        .is_err());
    }
}
