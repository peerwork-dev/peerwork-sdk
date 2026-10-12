//! Protected, restartable secure-journal transport evidence. Pages are exact
//! untrusted HTTP bytes. Neither this store nor an HTTP 200 verifies a policy,
//! commit, grant, effect, or final action outcome.

use crate::{
    kernel_client::KernelClient,
    kernel_identity::KernelIdentity,
    secure_state::{SecureStateError, SecureStateStore},
    transport::{TransportError, MAX_DISCOVERY_BYTES},
};
use ed25519_dalek::Signer;
use peerwork_core::{
    canonical::Path as CanonicalPath,
    crypto::{base64url, decode_base64url},
    discovery::{parse_discovery_wire, ParsedDiscovery},
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const MAX_PAGE: usize = 32 * 1024 * 1024;
const MAX_DOCUMENT: usize = 64 * 1024 * 1024;
const MAX_PAGES: usize = 2048;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
pub(crate) enum JournalReadError {
    #[error(transparent)]
    Store(#[from] SecureStateError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("secure journal page or protected read state is incompatible")]
    Incompatible,
    #[error("secure journal page limit exceeded")]
    TooLarge,
    #[error("server rejected secure journal read with HTTP {0}")]
    ServerRejected(u16),
    #[error("OS random source failed")]
    Entropy,
    #[error("system clock is outside supported timestamp range")]
    Clock,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPage {
    after: u64,
    exact_b64: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    origin: String,
    discovery_context: String,
    discovery_b64: String,
    actor_id: String,
    key_id: String,
    authority: String,
    workspace_id: String,
    pages: Vec<SavedPage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnverifiedJournalProgress {
    pub pages: usize,
    pub saved_commits: usize,
    pub checkpoint_sequence: Option<u64>,
    pub next_after: Option<u64>,
    pub complete_transport: bool,
}

struct PageFacts {
    checkpoint: String,
    policies: String,
    sequence: u64,
    next: Option<u64>,
    last: u64,
    commits: usize,
}

pub(crate) struct SecureJournalRead {
    store: SecureStateStore,
    document: Document,
}

impl SecureJournalRead {
    pub(crate) fn open(
        path: &Path,
        client: &KernelClient,
        identity: &KernelIdentity,
        workspace_id: &str,
        authority: &str,
    ) -> Result<Self, JournalReadError> {
        if !valid_id(workspace_id) || !valid_hex(authority) {
            return Err(JournalReadError::Incompatible);
        }
        let store = SecureStateStore::open(path)?;
        let discovery = client.discovery();
        let expected = Document {
            version: 2,
            origin: client.origin().into(),
            discovery_context: discovery.canonical_context().to_owned(),
            discovery_b64: base64url(discovery.raw_wire()),
            actor_id: identity.actor_id().into(),
            key_id: identity.key_id().into(),
            authority: authority.into(),
            workspace_id: workspace_id.into(),
            pages: Vec::new(),
        };
        let document = if let Some(bytes) = store.read_exact()? {
            if bytes.len() > MAX_DOCUMENT {
                return Err(JournalReadError::TooLarge);
            }
            parse_wire_json_bounded(&bytes, 12, MAX_DOCUMENT)
                .map_err(|_| JournalReadError::Incompatible)?;
            serde_json::from_slice::<Document>(&bytes)
                .map_err(|_| JournalReadError::Incompatible)?
        } else {
            expected.clone()
        };
        if document.version != 2
            || document.origin != expected.origin
            || !permits_discovery(&document, discovery)
            || document.actor_id != expected.actor_id
            || document.key_id != expected.key_id
            || document.authority != expected.authority
            || document.workspace_id != expected.workspace_id
            || document.pages.len() > MAX_PAGES
        {
            return Err(JournalReadError::Incompatible);
        }
        let opened = Self { store, document };
        opened.inspect()?;
        Ok(opened)
    }

    pub(crate) fn progress(&self) -> Result<UnverifiedJournalProgress, JournalReadError> {
        let (last, count) = self.inspect()?;
        Ok(UnverifiedJournalProgress {
            pages: self.document.pages.len(),
            saved_commits: count,
            checkpoint_sequence: last.as_ref().map(|p| p.sequence),
            next_after: last.as_ref().and_then(|p| p.next),
            complete_transport: last.as_ref().is_some_and(|p| p.next.is_none()),
        })
    }

    /// Exact pages are an internal replay input, never a public result DTO.
    pub(crate) fn exact_pages(&self) -> Result<Vec<Vec<u8>>, JournalReadError> {
        self.inspect()?;
        self.document
            .pages
            .iter()
            .map(|p| decode_base64url(&p.exact_b64).map_err(|_| JournalReadError::Incompatible))
            .collect()
    }

    pub(crate) async fn fetch_next(
        &mut self,
        client: &KernelClient,
        identity: &KernelIdentity,
        cancel: &CancellationToken,
    ) -> Result<UnverifiedJournalProgress, JournalReadError> {
        self.check_pins(client, identity)?;
        let (last, _) = self.inspect()?;
        if last.as_ref().is_some_and(|p| p.next.is_none()) {
            return self.progress();
        }
        if self.document.pages.len() == MAX_PAGES {
            return Err(JournalReadError::TooLarge);
        }
        let after = last.as_ref().and_then(|p| p.next).unwrap_or(0);
        let path = journal_path(&self.document.workspace_id, after, last.as_ref());
        let proof = sign_read_proof(
            &path,
            client.discovery(),
            identity,
            &self.document.authority,
        )?;
        let response = client
            .transport()
            .get_secure_journal_exact(&path, &proof, cancel)
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(JournalReadError::ServerRejected(response.status));
        }
        let facts = validate_page(
            &response.wire,
            &self.document.workspace_id,
            after,
            last.as_ref(),
        )?;
        let mut next = self.document.clone();
        next.pages.push(SavedPage {
            after,
            exact_b64: base64url(&response.wire),
        });
        let encoded = serde_json::to_vec(&next).map_err(|_| JournalReadError::Incompatible)?;
        if encoded.len() > MAX_DOCUMENT {
            return Err(JournalReadError::TooLarge);
        }
        self.store.write_exact(&encoded)?;
        self.document = next;
        let (_, count) = self.inspect()?;
        Ok(UnverifiedJournalProgress {
            pages: self.document.pages.len(),
            saved_commits: count,
            checkpoint_sequence: Some(facts.sequence),
            next_after: facts.next,
            complete_transport: facts.next.is_none(),
        })
    }

    fn check_pins(
        &self,
        client: &KernelClient,
        identity: &KernelIdentity,
    ) -> Result<(), JournalReadError> {
        if self.document.origin != client.origin()
            || !permits_discovery(&self.document, client.discovery())
            || self.document.actor_id != identity.actor_id()
            || self.document.key_id != identity.key_id()
        {
            return Err(JournalReadError::Incompatible);
        }
        Ok(())
    }

    fn inspect(&self) -> Result<(Option<PageFacts>, usize), JournalReadError> {
        let mut last: Option<PageFacts> = None;
        let mut count = 0;
        for saved in &self.document.pages {
            let after = last.as_ref().and_then(|p| p.next).unwrap_or(0);
            if last.as_ref().is_some_and(|p| p.next.is_none()) || saved.after != after {
                return Err(JournalReadError::Incompatible);
            }
            let wire =
                decode_base64url(&saved.exact_b64).map_err(|_| JournalReadError::Incompatible)?;
            let facts = validate_page(&wire, &self.document.workspace_id, after, last.as_ref())?;
            count += facts.commits;
            last = Some(facts);
        }
        Ok((last, count))
    }
}

fn journal_path(workspace: &str, after: u64, first: Option<&PageFacts>) -> String {
    let base = format!("/api/workspace/v1/secure/workspaces/{workspace}/journal?");
    if let Some(first) = first {
        format!(
            "{base}after={after}&at_head={}&at_sequence={}&limit=50",
            first_head(&first.checkpoint),
            first.sequence
        )
    } else {
        format!("{base}after=0&limit=50")
    }
}

fn first_head(checkpoint: &str) -> String {
    parse_wire_json_bounded(checkpoint.as_bytes(), 8, 4096)
        .ok()
        .and_then(|v| v.get("head").and_then(WireValue::as_string))
        .unwrap_or_default()
}

fn permits_discovery(saved: &Document, current: &ParsedDiscovery) -> bool {
    if saved.discovery_b64.len() > (MAX_DISCOVERY_BYTES * 4 / 3 + 8) {
        return false;
    }
    let Ok(raw) = decode_base64url(&saved.discovery_b64) else {
        return false;
    };
    let Ok(previous) = parse_discovery_wire(&raw, MAX_DISCOVERY_BYTES) else {
        return false;
    };
    previous.canonical_context() == saved.discovery_context
        && current.permits_update_from(&previous)
}

fn sign_read_proof(
    path: &str,
    discovery: &ParsedDiscovery,
    identity: &KernelIdentity,
    authority: &str,
) -> Result<String, JournalReadError> {
    if !valid_hex(authority) {
        return Err(JournalReadError::Incompatible);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JournalReadError::Clock)?
        .as_millis();
    if now > (MAX_SAFE - 60_000) as u128 {
        return Err(JournalReadError::Clock);
    }
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| JournalReadError::Entropy)?;
    let s = |v: &str| WireValue::String(v.encode_utf16().collect());
    let head = WireValue::Object(vec![
        ("alg".encode_utf16().collect(), s("EdDSA")),
        (
            "typ".encode_utf16().collect(),
            s("peerwork.kernel-read.v1+jws"),
        ),
        ("kid".encode_utf16().collect(), s(identity.key_id())),
    ]);
    let payload = WireValue::Object(vec![
        ("v".encode_utf16().collect(), WireValue::Number(1.0)),
        (
            "audience".encode_utf16().collect(),
            WireValue::String(discovery.audience_utf16().to_vec()),
        ),
        ("actor_id".encode_utf16().collect(), s(identity.actor_id())),
        ("authority".encode_utf16().collect(), s(authority)),
        ("method".encode_utf16().collect(), s("GET")),
        ("target".encode_utf16().collect(), s(path)),
        ("nonce".encode_utf16().collect(), s(&base64url(&nonce))),
        (
            "issued_at".encode_utf16().collect(),
            WireValue::Number(now as f64),
        ),
        (
            "expires_at".encode_utf16().collect(),
            WireValue::Number((now + 60_000) as f64),
        ),
    ]);
    let h = canonical_wire_value(&head, CanonicalPath::KERNEL)
        .map_err(|_| JournalReadError::Incompatible)?;
    let p = canonical_wire_value(&payload, CanonicalPath::KERNEL)
        .map_err(|_| JournalReadError::Incompatible)?;
    let input = format!("{}.{}", base64url(h.as_bytes()), base64url(p.as_bytes()));
    let signature = identity.signing_key().sign(input.as_bytes());
    Ok(format!("{input}.{}", base64url(&signature.to_bytes())))
}

fn validate_page(
    wire: &[u8],
    workspace: &str,
    after: u64,
    first: Option<&PageFacts>,
) -> Result<PageFacts, JournalReadError> {
    if wire.is_empty() || wire.len() > MAX_PAGE {
        return Err(JournalReadError::TooLarge);
    }
    let value =
        parse_wire_json_bounded(wire, 64, MAX_PAGE).map_err(|_| JournalReadError::Incompatible)?;
    if text(&value, "workspace_id")? != workspace || text(&value, "state")? != "ACTIVE" {
        return Err(JournalReadError::Incompatible);
    }
    let visibility = text(&value, "visibility")?;
    if visibility != "PRIVATE" && visibility != "PUBLIC" {
        return Err(JournalReadError::Incompatible);
    }
    let cp = value
        .get("checkpoint")
        .ok_or(JournalReadError::Incompatible)?;
    if text(cp, "workspace_id")? != workspace || number(cp, "v")? != 1 {
        return Err(JournalReadError::Incompatible);
    }
    let sequence = number(cp, "sequence")?;
    let head = text(cp, "head")?;
    if sequence < 1 || sequence < after || !valid_hex(&head) {
        return Err(JournalReadError::Incompatible);
    }
    let checkpoint = canonical_wire_value(cp, CanonicalPath::SecureArtifact)
        .map_err(|_| JournalReadError::Incompatible)?;
    let policies = value
        .get("policies")
        .and_then(|v| {
            if let WireValue::Array(a) = v {
                Some(a)
            } else {
                None
            }
        })
        .ok_or(JournalReadError::Incompatible)?;
    if policies.is_empty() || policies.len() > 1024 {
        return Err(JournalReadError::Incompatible);
    }
    let policy_text = canonical_wire_value(
        &WireValue::Array(policies.clone()),
        CanonicalPath::SecureArtifact,
    )
    .map_err(|_| JournalReadError::Incompatible)?;
    let commits = value
        .get("commits")
        .and_then(|v| {
            if let WireValue::Array(a) = v {
                Some(a)
            } else {
                None
            }
        })
        .ok_or(JournalReadError::Incompatible)?;
    if commits.len() > 50 {
        return Err(JournalReadError::Incompatible);
    }
    if let Some(first) = first {
        if checkpoint != first.checkpoint || policy_text != first.policies {
            return Err(JournalReadError::Incompatible);
        }
    }
    let mut last = after;
    for commit in commits {
        let payload = commit
            .get("payload")
            .ok_or(JournalReadError::Incompatible)?;
        if text(payload, "workspace_id")? != workspace {
            return Err(JournalReadError::Incompatible);
        }
        let current = number(payload, "sequence")?;
        if current <= last || current > sequence {
            return Err(JournalReadError::Incompatible);
        }
        last = current;
    }
    let next = match value.get("next") {
        Some(WireValue::Null) => None,
        Some(v) => Some(value_u64(v)?),
        _ => return Err(JournalReadError::Incompatible),
    };
    match next {
        Some(cursor) if !commits.is_empty() && cursor == last && cursor < sequence => {}
        None if last == sequence => {}
        _ => return Err(JournalReadError::Incompatible),
    }
    Ok(PageFacts {
        checkpoint,
        policies: policy_text,
        sequence,
        next,
        last,
        commits: commits.len(),
    })
}

fn text(value: &WireValue, key: &str) -> Result<String, JournalReadError> {
    value
        .get(key)
        .and_then(WireValue::as_string)
        .ok_or(JournalReadError::Incompatible)
}
fn number(value: &WireValue, key: &str) -> Result<u64, JournalReadError> {
    value
        .get(key)
        .map(value_u64)
        .unwrap_or(Err(JournalReadError::Incompatible))
}
fn value_u64(value: &WireValue) -> Result<u64, JournalReadError> {
    match value {
        WireValue::Number(n)
            if n.is_finite() && *n >= 0.0 && *n <= MAX_SAFE as f64 && n.fract() == 0.0 =>
        {
            Ok(*n as u64)
        }
        _ => Err(JournalReadError::Incompatible),
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 43
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page(workspace: &str, head: &str, sequences: &[u64], next: Option<u64>) -> Vec<u8> {
        serde_json::to_vec(&json!({"workspace_id":workspace,"state":"ACTIVE","visibility":"PRIVATE",
            "policies":[{"payload":{"workspace_id":workspace,"version":1,"visibility":"PRIVATE"}}],
            "commits":sequences.iter().map(|sequence|json!({"payload":{"workspace_id":workspace,"sequence":sequence}})).collect::<Vec<_>>(),
            "checkpoint":{"v":1,"workspace_id":workspace,"owner_id":"owner","owner_key":"key",
                "sequence":2,"head":head,"policy_hash":"policy"},"next":next})).unwrap()
    }

    #[test]
    fn exact_page_cursor_and_checkpoint_survive_reparse() {
        let workspace = "a".repeat(43);
        let head = "b".repeat(64);
        let first = page(&workspace, &head, &[1], Some(1));
        let facts = validate_page(&first, &workspace, 0, None).unwrap();
        assert_eq!(facts.next, Some(1));
        assert_eq!(journal_path(&workspace,1,Some(&facts)),format!(
            "/api/workspace/v1/secure/workspaces/{workspace}/journal?after=1&at_head={head}&at_sequence=2&limit=50"));
        let second = page(&workspace, &head, &[2], None);
        assert!(validate_page(&second, &workspace, 1, Some(&facts))
            .unwrap()
            .next
            .is_none());
        let changed = page(&workspace, &"c".repeat(64), &[2], None);
        assert!(matches!(
            validate_page(&changed, &workspace, 1, Some(&facts)),
            Err(JournalReadError::Incompatible)
        ));
        let skipped = page(&workspace, &head, &[2], Some(2));
        assert!(matches!(
            validate_page(&skipped, &workspace, 1, Some(&facts)),
            Err(JournalReadError::Incompatible)
        ));
        let wrong_next = page(&workspace, &head, &[2], Some(1));
        assert!(matches!(
            validate_page(&wrong_next, &workspace, 1, Some(&facts)),
            Err(JournalReadError::Incompatible)
        ));
    }

    #[test]
    fn saved_discovery_only_permits_additive_continuity() {
        let key = peerwork_core::crypto::key_id(&[27; 32]);
        let base = serde_json::json!({"semantics":"peerwork.kernel.v1",
            "audience":"https://control.example",
            "command_type":"peerwork.kernel-command.v1+jws",
            "receipt_type":"peerwork.kernel-receipt.v1+jws",
            "receipt_public_key":key,"limits":{"old":1},
            "protocol_features":["old"],"manifest_language":"v1"});
        let parse = |v: &serde_json::Value| {
            let wire = serde_json::to_vec(v).unwrap();
            parse_discovery_wire(&wire, wire.len()).unwrap()
        };
        let original = parse(&base);
        let mut document = Document {
            version: 2,
            origin: "https://control.example/".into(),
            discovery_context: original.canonical_context().into(),
            discovery_b64: base64url(original.raw_wire()),
            actor_id: "a".repeat(43),
            key_id: "b".repeat(43),
            authority: "c".repeat(64),
            workspace_id: "d".repeat(43),
            pages: Vec::new(),
        };
        assert!(permits_discovery(&document, &original));
        let mut added = base.clone();
        added["limits"]["new"] = serde_json::json!(2);
        added["protocol_features"] = serde_json::json!(["old", "new"]);
        assert!(permits_discovery(&document, &parse(&added)));
        added["receipt_public_key"] = serde_json::json!(peerwork_core::crypto::key_id(&[28; 32]));
        assert!(!permits_discovery(&document, &parse(&added)));
        document.discovery_b64 = base64url(b"{}");
        assert!(!permits_discovery(&document, &original));
    }
}
