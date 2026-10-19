//! Explicitly adopted publisher-attested state. This is not full journal replay.
//! All content remains lossless WireValue through signature, decryption and output.
use crate::{
    canonical::Path,
    crypto::{self, verify_secure_signed_wire},
    e2ee::{open_content_wire, SealedContent},
    wire_json::{canonical_wire_value, parse_wire_json_js_bounded, WireValue as W},
};
use serde::Deserialize;
use std::collections::HashMap;
pub const BOOTSTRAP_BYTES: usize = 2 * 1024 * 1024;
pub const NODE_BYTES: usize = 16384;
pub const COMMIT_BYTES: usize = 196608;
pub const EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
pub const TOTAL_BYTES: usize = 12 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadViewError(pub &'static str);
impl std::fmt::Display for ReadViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ReadViewError {}
type R<T> = Result<T, ReadViewError>;
pub(crate) fn check(ok: bool, code: &'static str) -> R<()> {
    if ok {
        Ok(())
    } else {
        Err(ReadViewError(code))
    }
}
fn invalid() -> ReadViewError {
    ReadViewError("READ_VIEW_INVALID")
}
pub fn parse(bytes: &[u8], max: usize) -> R<W> {
    parse_wire_json_js_bounded(bytes, 64, max)
        .map_err(|_| ReadViewError("READ_VIEW_RESOURCE_OR_JSON_INVALID"))
}
pub fn wire(v: &W) -> R<String> {
    canonical_wire_value(v, Path::SecureArtifact).map_err(|_| invalid())
}
pub(crate) fn size(v: &W, max: usize) -> R<usize> {
    let n = wire(v)?.len();
    check(n <= max, "READ_VIEW_RESOURCE_LIMIT")?;
    Ok(n)
}
pub(crate) fn g<'a>(v: &'a W, k: &str) -> R<&'a W> {
    v.get(k).ok_or_else(invalid)
}
pub(crate) fn s(v: &W, k: &str) -> R<String> {
    g(v, k)?.as_string().ok_or_else(invalid)
}
pub(crate) fn n(v: &W, k: &str) -> R<u64> {
    let n = g(v, k)?.as_number().ok_or_else(invalid)?;
    check(
        n >= 0.0 && n <= 9007199254740991.0 && n.fract() == 0.0,
        "READ_VIEW_INVALID",
    )?;
    Ok(n as u64)
}
pub(crate) fn arr(v: &W) -> R<&[W]> {
    if let W::Array(a) = v {
        Ok(a)
    } else {
        Err(invalid())
    }
}
pub(crate) fn string(s: &str) -> W {
    W::String(s.encode_utf16().collect())
}
pub(crate) fn number(n: u64) -> W {
    W::Number(n as f64)
}
pub(crate) fn obj(fields: Vec<(&str, W)>) -> W {
    W::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.encode_utf16().collect(), v))
            .collect(),
    )
}
pub(crate) fn payload(v: &W) -> R<&W> {
    g(v, "payload")
}
pub fn hash(v: &W) -> R<String> {
    Ok(crypto::sha256_hex(wire(v)?.as_bytes()))
}
pub fn token(t: &str) -> bool {
    t.len() == 43
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub(crate) fn digest(t: &str) -> bool {
    t.len() == 64
        && t.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key(t: &str) -> bool {
    t.len() <= 512 && t.bytes().all(|b| (32..=126).contains(&b))
}
pub(crate) fn signed(v: &W, domain: &str, k: &str) -> R<()> {
    check(
        verify_secure_signed_wire(wire(v)?.as_bytes(), domain, k).map_err(|_| invalid())?,
        "READ_VIEW_SIGNATURE_INVALID",
    )
}
pub(crate) fn actor(k: &str) -> R<String> {
    let bytes: [u8; 32] = crypto::decode_base64url(k)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(crypto::actor_id(&bytes))
}
pub(crate) fn equivalent(a: &W, b: &W) -> R<bool> {
    Ok(wire(a)? == wire(b)?)
}
#[derive(Clone, Debug, Deserialize)]
pub struct ReadViewPin {
    pub origin: String,
    pub workspace_id: String,
    pub owner_actor_id: String,
    pub owner_key_id: String,
    pub audience: String,
    pub service_key: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ReadViewSelection {
    #[serde(rename = "get")]
    Get { object_kind: String, id: String },
    #[serde(rename = "list")]
    List {
        instance_id: String,
        schema: String,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        cursor: Option<serde_json::Value>,
    },
}
fn primary(kind: &str, id: &str) -> R<String> {
    check(
        !kind.is_empty()
            && kind.len() <= 64
            && kind.as_bytes()[0].is_ascii_lowercase()
            && kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && !id.is_empty()
            && id.encode_utf16().count() <= 256,
        "READ_VIEW_QUERY_INVALID",
    )?;
    let mut out = format!("p/{kind}/");
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char)
        } else {
            out.push_str(&format!("%{b:02X}"))
        }
    }
    check(key(&out), "READ_VIEW_QUERY_INVALID")?;
    Ok(out)
}
fn instance_prefix(instance: &str, schema: &str) -> R<String> {
    check(
        token(instance)
            && !schema.is_empty()
            && schema.len() <= 80
            && schema.as_bytes()[0].is_ascii_alphabetic()
            && schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "READ_VIEW_QUERY_INVALID",
    )?;
    Ok(format!("i/{instance}/{schema}/"))
}
#[derive(Clone, Debug)]
struct NodeRef {
    hash: String,
    min: String,
    max: String,
    count: u64,
}
fn node_ref(v: &W) -> R<NodeRef> {
    let r = NodeRef {
        hash: s(v, "hash")?,
        min: s(v, "min")?,
        max: s(v, "max")?,
        count: n(v, "count")?,
    };
    check(
        digest(&r.hash)
            && key(&r.min)
            && key(&r.max)
            && r.count <= 100000
            && if r.count == 0 {
                r.min.is_empty() && r.max.is_empty()
            } else {
                r.min <= r.max
            },
        "READ_VIEW_NODE_INVALID",
    )?;
    Ok(r)
}
pub struct AuthorizedReadView {
    pin: ReadViewPin,
    root: W,
    root_hash: String,
    context: W,
    tree: NodeRef,
    visibility: String,
    key: Option<zeroize::Zeroizing<[u8; 32]>>,
    historical_keys: HashMap<u64, zeroize::Zeroizing<[u8; 32]>>,
    now: u64,
    expires: u64,
    bootstrap_bytes: usize,
    floor: W,
}
impl AuthorizedReadView {
    /// Synthetic/private callers must already own the epoch key. No transport key import is provided.
    pub fn open(
        boot: &W,
        pin: ReadViewPin,
        nonce: &str,
        now: u64,
        adopt: bool,
        floor: Option<&W>,
        epoch_key: Option<[u8; 32]>,
    ) -> R<Self> {
        check(adopt, "READ_VIEW_ADOPTION_REQUIRED")?;
        let bootstrap_bytes = size(boot, BOOTSTRAP_BYTES)?;
        check(
            token(&pin.workspace_id) && token(nonce),
            "READ_VIEW_INVALID",
        )?;
        let au = g(boot, "authority")?;
        let a = payload(au)?;
        let policy = g(boot, "policy")?;
        let p = payload(policy)?;
        let root = g(boot, "root")?;
        let r = payload(root)?;
        let observation = g(boot, "observation")?;
        let o = payload(observation)?;
        signed(
            observation,
            "peerwork.read-observation.v1",
            &pin.service_key,
        )?;
        check(
            n(a, "v")? == 1
                && s(a, "workspace_id")? == pin.workspace_id
                && s(a, "owner_id")? == pin.owner_actor_id
                && s(a, "owner_key")? == pin.owner_key_id
                && s(a, "origin")? == pin.origin
                && s(a, "audience")? == pin.audience
                && n(a, "generation")? > 0
                && n(a, "issued_at")? <= now
                && now < n(a, "expires_at")?,
            "READ_VIEW_AUTHORITY_INVALID",
        )?;
        check(
            actor(&pin.owner_key_id)? == pin.owner_actor_id
                && s(p, "workspace_id")? == pin.workspace_id
                && s(p, "owner_id")? == pin.owner_actor_id
                && s(p, "signing_key")? == pin.owner_key_id
                && n(p, "epoch")? == n(a, "epoch")?
                && hash(policy)? == s(a, "policy_hash")?
                && n(p, "version")? > 0,
            "READ_VIEW_POLICY_MISMATCH",
        )?;
        let publisher = s(a, "publisher_key")?;
        check(
            actor(&publisher)? == s(a, "publisher_id")?,
            "READ_VIEW_AUTHORITY_INVALID",
        )?;
        let members = arr(g(p, "members")?)?;
        check(
            members.len() <= 128
                && members.iter().any(|m| {
                    s(m, "actor_id").ok() == s(a, "publisher_id").ok()
                        && g(m, "certificate")
                            .and_then(payload)
                            .and_then(|c| s(c, "signing_key"))
                            .ok()
                            == Some(publisher.clone())
                }),
            "READ_VIEW_PUBLISHER_NOT_MEMBER",
        )?;
        signed(policy, "peerwork.secure.policy.v1", &pin.owner_key_id)?;
        signed(au, "peerwork.read-authority.v1", &pin.owner_key_id)?;
        const DEFINITION: &str = r#"{"v":1,"name":"objects-and-instance-heads","comparator":"ascii-v1","indexes":["primary","instance-schema-current"],"semantics":"AUTHORIZED_STATE"}"#;
        check(
            s(a, "definition_hash")? == hash(&parse(DEFINITION.as_bytes(), 1024)?)?,
            "READ_VIEW_DEFINITION_INVALID",
        )?;
        let authority_hash = hash(au)?;
        let root_hash = hash(root)?;
        let cp = g(r, "checkpoint")?;
        let epoch = n(a, "epoch")?;
        let visibility = s(r, "visibility")?;
        check(
            n(r, "v")? == 1
                && s(r, "authority_hash")? == authority_hash
                && n(r, "epoch")? == epoch
                && s(r, "definition_hash")? == s(a, "definition_hash")?
                && visibility == s(p, "visibility")?
                && ["PUBLIC", "PRIVATE"].contains(&visibility.as_str())
                && n(r, "root_number")? > 0
                && n(r, "issued_at")? >= n(a, "issued_at")?
                && n(r, "issued_at")? <= now
                && s(cp, "workspace_id")? == pin.workspace_id
                && s(cp, "owner_id")? == pin.owner_actor_id
                && s(cp, "owner_key")? == pin.owner_key_id
                && s(cp, "policy_hash")? == s(a, "policy_hash")?
                && n(cp, "sequence")? > 0
                && digest(&s(cp, "head")?),
            "READ_VIEW_ROOT_INVALID",
        )?;
        check(
            if n(r, "root_number")? == 1 {
                g(r, "previous_root")? == &W::Null
            } else {
                digest(&s(r, "previous_root")?)
            },
            "READ_VIEW_ROOT_INVALID",
        )?;
        signed(root, "peerwork.read-root.v1", &publisher)?;
        let observed = n(o, "observed_at")?;
        let expiry = n(o, "expires_at")?;
        check(
            n(o, "v")? == 1
                && s(o, "state")? == "ACTIVE"
                && s(o, "nonce")? == nonce
                && s(o, "workspace_id")? == pin.workspace_id
                && s(o, "origin")? == pin.origin
                && s(o, "audience")? == pin.audience
                && s(o, "service_key")? == pin.service_key
                && s(o, "authority_hash")? == authority_hash
                && s(o, "root_hash")? == root_hash
                && observed <= now
                && now < expiry
                && expiry - observed <= 60000,
            "READ_VIEW_OBSERVATION_INVALID",
        )?;
        check(equivalent(g(o, "checkpoint")?, cp)?, "VIEW_NOT_CAUGHT_UP")?;
        if let Some(f) = floor {
            check(
                n(f, "generation")? == n(a, "generation")?
                    && n(r, "root_number")? >= n(f, "root_number")?
                    && n(cp, "sequence")? >= n(g(f, "checkpoint")?, "sequence")?,
                "READ_VIEW_ROLLBACK",
            )?;
            if n(cp, "sequence")? == n(g(f, "checkpoint")?, "sequence")? {
                check(equivalent(cp, g(f, "checkpoint")?)?, "READ_VIEW_FORK")?
            }
            if n(r, "root_number")? == n(f, "root_number")? {
                check(root_hash == s(f, "root_hash")?, "READ_VIEW_FORK")?
            } else {
                let empty = W::Array(vec![]);
                let chain = g(boot, "continuity").unwrap_or(&empty);
                size(chain, 256 * 1024)?;
                let chain = arr(chain)?;
                check(
                    chain.len() <= 64
                        && chain.len() as u64 == n(r, "root_number")? - n(f, "root_number")? - 1,
                    "VIEW_CONTINUITY_REQUIRED",
                )?;
                let mut previous = s(f, "root_hash")?;
                let mut num = n(f, "root_number")?;
                for item in chain.iter().chain(std::iter::once(root)) {
                    num += 1;
                    let v = payload(item)?;
                    check(
                        s(v, "authority_hash")? == authority_hash
                            && n(v, "root_number")? == num
                            && s(v, "previous_root")? == previous,
                        "READ_VIEW_FORK",
                    )?;
                    signed(item, "peerwork.read-root.v1", &publisher)?;
                    previous = hash(item)?;
                }
            }
        }
        let context = obj(vec![
            ("v", number(1)),
            ("workspace_id", string(&pin.workspace_id)),
            ("authority_hash", string(&authority_hash)),
            ("epoch", number(epoch)),
            ("definition_hash", g(a, "definition_hash")?.clone()),
        ]);
        let tree = if visibility == "PRIVATE" {
            check(
                g(r, "tree")?.object_len() == Some(2),
                "READ_VIEW_ROOT_INVALID",
            )?;
            let k = epoch_key
                .as_ref()
                .ok_or(ReadViewError("READ_VIEW_KEY_REQUIRED"))?;
            let mut aad = context.clone();
            if let W::Object(fields) = &mut aad {
                fields.push(("kind".encode_utf16().collect(), string("root-descriptor")))
            }
            let decoded = decrypt(g(g(r, "tree")?, "box")?, &aad, k, NODE_BYTES)?;
            let tree = node_ref(&decoded)?;
            check(
                tree.hash == s(g(r, "tree")?, "hash")?,
                "READ_VIEW_ROOT_INVALID",
            )?;
            tree
        } else {
            node_ref(g(r, "tree")?)?
        };
        let saved_floor = obj(vec![
            ("root_hash", string(&root_hash)),
            ("root_number", g(r, "root_number")?.clone()),
            ("generation", g(a, "generation")?.clone()),
            ("checkpoint", cp.clone()),
        ]);
        Ok(Self {
            pin,
            root: root.clone(),
            root_hash,
            context,
            tree,
            visibility,
            key: epoch_key.map(zeroize::Zeroizing::new),
            historical_keys: epoch_key
                .map(|k| (epoch, zeroize::Zeroizing::new(k)))
                .into_iter()
                .collect(),
            now,
            expires: expiry.min(n(a, "expires_at")?),
            bootstrap_bytes,
            floor: saved_floor,
        })
    }
    /// Trusted Rust runtime adapter; keys never appear in a language-facing DTO.
    pub fn open_with_keyring(
        boot: &W,
        pin: ReadViewPin,
        nonce: &str,
        now: u64,
        adopt: bool,
        floor: Option<&W>,
        ring: &crate::secure_keyring::SecretKeyring,
    ) -> R<Self> {
        check(
            ring.workspace_id() == pin.workspace_id,
            "READ_VIEW_KEY_REQUIRED",
        )?;
        let epoch = n(payload(g(boot, "root")?)?, "epoch")?;
        let mut result = Self::open(
            boot,
            pin,
            nonce,
            now,
            adopt,
            floor,
            ring.key_at(epoch).copied(),
        )?;
        for epoch in ring.epochs() {
            if let Some(key) = ring.key_at(epoch) {
                result
                    .historical_keys
                    .insert(epoch, zeroize::Zeroizing::new(*key));
            }
        }
        Ok(result)
    }

    /// A delegated state root cannot move behind an already fully verified local checkpoint.
    pub fn require_checkpoint_floor(
        &self,
        sequence: u64,
        head: Option<&str>,
        policy_hash: &str,
    ) -> R<()> {
        let cp = g(payload(&self.root)?, "checkpoint")?;
        check(n(cp, "sequence")? >= sequence, "READ_VIEW_ROLLBACK")?;
        if n(cp, "sequence")? == sequence {
            check(
                Some(s(cp, "head")?.as_str()) == head && s(cp, "policy_hash")? == policy_hash,
                "READ_VIEW_FORK",
            )?;
        }
        Ok(())
    }

    pub fn root_hash(&self) -> &str {
        &self.root_hash
    }
    pub fn is_public(&self) -> bool {
        self.visibility == "PUBLIC"
    }
    pub fn check_elapsed(&self, ms: u64) -> R<()> {
        check(
            self.now.checked_add(ms).is_some_and(|n| n < self.expires),
            "READ_VIEW_OBSERVATION_EXPIRED",
        )
    }
    pub fn query<N, C, A>(
        &self,
        selection: &ReadViewSelection,
        mut load_node: N,
        mut load_commit: C,
        mut active: A,
    ) -> R<W>
    where
        N: FnMut(&str) -> R<W>,
        C: FnMut(&str) -> R<W>,
        A: FnMut() -> R<()>,
    {
        active()?;
        let (prefix, limit, cursor, exact) = match selection {
            ReadViewSelection::Get { object_kind, id } => {
                (primary(object_kind, id)?, 1, None, true)
            }
            ReadViewSelection::List {
                instance_id,
                schema,
                limit,
                cursor,
            } => (
                instance_prefix(instance_id, schema)?,
                limit.unwrap_or(20),
                cursor.as_ref(),
                false,
            ),
        };
        check((1..=20).contains(&limit), "READ_VIEW_QUERY_INVALID")?;
        let qhash = hash(&obj(vec![
            ("prefix", string(&prefix)),
            ("limit", number(limit as u64)),
            ("exact", W::Bool(exact)),
        ]))?;
        let mut after = None;
        if let Some(c) = cursor {
            let c = parse(&serde_json::to_vec(c).map_err(|_| invalid())?, 4096)?;
            let a = s(&c, "after")?;
            check(
                n(&c, "v")? == 1
                    && s(&c, "root_hash")? == self.root_hash
                    && s(&c, "query_hash")? == qhash
                    && key(&a)
                    && a.starts_with(&prefix),
                "READ_VIEW_CURSOR_INVALID",
            )?;
            after = Some(a);
        }
        let mut traversal = Traversal {
            view: self,
            prefix: &prefix,
            after: after.as_deref(),
            limit,
            entries: vec![],
            nodes: 0,
            node_bytes: 0,
            total: self.bootstrap_bytes,
        };
        traversal.visit(&self.tree, 1, &mut load_node, &mut active)?;
        let next = if !exact && traversal.entries.len() > limit {
            Some(s(&traversal.entries[limit - 1], "key")?)
        } else {
            None
        };
        traversal.entries.truncate(limit);
        let mut objects = vec![];
        let mut evidence = HashMap::<String, (W, W)>::new();
        let mut commit_bytes = 0;
        let mut other_bytes = 0;
        for entry in &traversal.entries {
            let entry_key = s(entry, "key")?;
            if exact && entry_key != prefix {
                continue;
            }
            active()?;
            let reference = g(entry, "value")?;
            let kind = s(reference, "kind")?;
            let id = s(reference, "id")?;
            check(
                n(reference, "revision")? > 0
                    && digest(&s(reference, "object_hash")?)
                    && digest(&s(reference, "commit_hash")?)
                    && n(reference, "commit_sequence")? > 0
                    && n(reference, "commit_sequence")?
                        <= n(g(payload(&self.root)?, "checkpoint")?, "sequence")?
                    && ["LIVE", "SUPERSEDED", "TOMBSTONE"]
                        .contains(&s(reference, "status")?.as_str())
                    && ["AUTHOR_SIGNED", "LEGACY_OWNER_ATTESTED"]
                        .contains(&s(reference, "provenance")?.as_str()),
                "READ_VIEW_OBJECT_INVALID",
            )?;
            check(
                entry_key == primary(&kind, &id)?
                    || entry_key.starts_with("i/") && entry_key.ends_with(&format!("/{id}")),
                "READ_VIEW_INDEX_MISMATCH",
            )?;
            if s(reference, "status")? != "LIVE" {
                continue;
            }
            let ch = s(reference, "commit_hash")?;
            if !evidence.contains_key(&ch) {
                check(evidence.len() < 20, "READ_VIEW_RESOURCE_LIMIT")?;
                let ev = load_commit(&ch)?;
                active()?;
                let commit = g(&ev, "commit")?;
                let policy = g(&ev, "policy")?;
                let extra = obj(vec![
                    ("policy", policy.clone()),
                    (
                        "guard_time_attestations",
                        ev.get("guard_time_attestations")
                            .cloned()
                            .unwrap_or(W::Array(vec![])),
                    ),
                ]);
                let cb = size(commit, COMMIT_BYTES)?;
                let eb = size(&extra, EVIDENCE_BYTES)?;
                commit_bytes += cb;
                other_bytes += eb;
                traversal.total += cb + eb;
                check(
                    other_bytes <= EVIDENCE_BYTES && traversal.total <= TOTAL_BYTES,
                    "READ_VIEW_RESOURCE_LIMIT",
                )?;
                self.verify_evidence(&ev, &ch, n(reference, "commit_sequence")?)?;
                let p = payload(commit)?;
                let op = if self.visibility == "PRIVATE" {
                    let mut context = p.clone();
                    if let W::Object(fields) = &mut context {
                        fields.retain(|(k, _)| {
                            !k.iter().copied().eq("body".encode_utf16())
                                && !k.iter().copied().eq("mode".encode_utf16())
                        });
                    }
                    decrypt(
                        g(p, "body")?,
                        &context,
                        self.historical_keys
                            .get(&n(p, "epoch")?)
                            .ok_or(ReadViewError("READ_VIEW_HISTORICAL_KEY_REQUIRED"))?,
                        COMMIT_BYTES,
                    )?
                } else {
                    g(p, "body")?.clone()
                };
                check(
                    n(&op, "v")? == 1 && arr(g(&op, "objects")?)?.len() <= 128,
                    "AUTHOR_EVIDENCE_INVALID",
                )?;
                evidence.insert(ch.clone(), (ev, op));
            }
            let (ev, op) = evidence.get(&ch).ok_or_else(invalid)?;
            check(
                n(payload(g(ev, "commit")?)?, "sequence")? == n(reference, "commit_sequence")?,
                "AUTHOR_EVIDENCE_INVALID",
            )?;
            let found = arr(g(op, "objects")?)?
                .iter()
                .find(|x| {
                    s(x, "kind").ok() == Some(kind.clone())
                        && s(x, "id").ok() == Some(id.clone())
                        && n(x, "revision").ok() == n(reference, "revision").ok()
                })
                .ok_or(ReadViewError("AUTHOR_EVIDENCE_INVALID"))?;
            size(found, 98304)?;
            check(
                hash(found)? == s(reference, "object_hash")?
                    && s(found, "provenance")? == s(reference, "provenance")?,
                "AUTHOR_EVIDENCE_INVALID",
            )?;
            if entry_key.starts_with("i/") {
                let v = g(found, "value")?;
                check(
                    entry_key
                        == format!(
                            "{}{}",
                            instance_prefix(&s(v, "instance_id")?, &s(v, "schema_ref")?)?,
                            id
                        ),
                    "READ_VIEW_INDEX_MISMATCH",
                )?;
            }
            objects.push(found.clone());
        }
        active()?;
        let cursor = next
            .map(|after| {
                obj(vec![
                    ("v", number(1)),
                    ("root_hash", string(&self.root_hash)),
                    ("query_hash", string(&qhash)),
                    ("after", string(&after)),
                ])
            })
            .unwrap_or(W::Null);
        let mut result = obj(vec![
            ("assurance", string("AUTHORIZED_STATE")),
            ("coverage", string("COMPLETE_INDEX_RANGE")),
            ("checkpoint", g(payload(&self.root)?, "checkpoint")?.clone()),
            ("root_hash", string(&self.root_hash)),
            ("floor", self.floor.clone()),
            ("objects", W::Array(objects.clone())),
            ("next", cursor),
            (
                "metrics",
                obj(vec![
                    ("byte_basis", string("CANONICAL_ARTIFACT_BYTES")),
                    ("bootstrap_bytes", number(self.bootstrap_bytes as u64)),
                    ("node_bytes", number(traversal.node_bytes as u64)),
                    ("nodes", number(traversal.nodes as u64)),
                    ("commit_bytes", number(commit_bytes as u64)),
                    ("commits", number(evidence.len() as u64)),
                ]),
            ),
        ]);
        if exact {
            if let W::Object(fields) = &mut result {
                fields.push((
                    "object".encode_utf16().collect(),
                    objects.into_iter().next().unwrap_or(W::Null),
                ));
            }
        }
        Ok(result)
    }
    fn verify_evidence(&self, ev: &W, expected: &str, sequence: u64) -> R<()> {
        let commit = g(ev, "commit")?;
        let p = payload(commit)?;
        let policy = g(ev, "policy")?;
        let q = payload(policy)?;
        check(
            hash(commit)? == expected
                && s(p, "workspace_id")? == self.pin.workspace_id
                && n(p, "sequence")? == sequence
                && s(p, "mode")? == self.visibility
                && n(q, "epoch")? == n(p, "epoch")?
                && s(q, "visibility")? == s(p, "mode")?
                && s(q, "workspace_id")? == self.pin.workspace_id
                && s(q, "owner_id")? == self.pin.owner_actor_id
                && s(q, "signing_key")? == self.pin.owner_key_id
                && hash(policy)? == s(p, "policy_hash")?,
            "AUTHOR_EVIDENCE_INVALID",
        )?;
        check(
            q.get("guard_time").is_none_or(|v| v == &W::Null),
            "READ_VIEW_UNSUPPORTED_GUARD_TIME",
        )?;
        check(
            g(p, "delegation")? == &W::Null,
            "READ_VIEW_UNSUPPORTED_DELEGATION",
        )?;
        signed(policy, "peerwork.secure.policy.v1", &self.pin.owner_key_id)?;
        let author = s(p, "actor_id")?;
        let author_key = s(p, "signing_key")?;
        check(actor(&author_key)? == author, "AUTHOR_EVIDENCE_INVALID")?;
        signed(commit, "peerwork.secure.commit.v1", &author_key)?;
        let member = arr(g(q, "members")?)?
            .iter()
            .find(|m| s(m, "actor_id").ok() == Some(author.clone()))
            .ok_or(ReadViewError("AUTHOR_EVIDENCE_INVALID"))?;
        let certificate = g(member, "certificate")?;
        verify_author_certificate(certificate, &author, &author_key, n(p, "issued_at")?)?;
        // Scope/transition validity remains the explicitly adopted publisher's judgment.
        Ok(())
    }
}
pub(crate) fn verify_author_certificate(
    certificate: &W,
    author: &str,
    author_key: &str,
    at: u64,
) -> R<()> {
    let c = payload(certificate)?;
    check(
        n(c, "v")? == 1
            && s(c, "actor_id")? == author
            && s(c, "signing_key")? == author_key
            && n(c, "issued_at")? <= at
            && at < n(c, "expires_at")?,
        "AUTHOR_CERTIFICATE_INVALID",
    )?;
    signed(
        certificate,
        "peerwork.secure.key-certificate.v1",
        author_key,
    )
}

pub(crate) fn decrypt(boxed: &W, context: &W, key: &[u8; 32], max: usize) -> R<W> {
    let sealed: SealedContent = serde_json::from_str(&wire(boxed)?).map_err(|_| invalid())?;
    let bytes = open_content_wire(key, &sealed, wire(context)?.as_bytes())
        .map_err(|_| ReadViewError("READ_VIEW_DECRYPT_FAILED"))?;
    let value = parse(&bytes, max)?;
    check(
        wire(&value)?.as_bytes() == bytes,
        "READ_VIEW_CONTENT_NONCANONICAL",
    )?;
    Ok(value)
}
struct Traversal<'a> {
    view: &'a AuthorizedReadView,
    prefix: &'a str,
    after: Option<&'a str>,
    limit: usize,
    entries: Vec<W>,
    nodes: usize,
    node_bytes: usize,
    total: usize,
}
impl Traversal<'_> {
    fn visit<N, A>(&mut self, r: &NodeRef, depth: usize, load: &mut N, active: &mut A) -> R<()>
    where
        N: FnMut(&str) -> R<W>,
        A: FnMut() -> R<()>,
    {
        check(depth <= 16, "READ_VIEW_RESOURCE_LIMIT")?;
        let upper = format!("{}\x7f", self.prefix);
        if r.count > 0
            && (r.max.as_str() < self.prefix
                || r.min >= upper
                || self.after.is_some_and(|a| r.max.as_str() <= a)
                || self.entries.len() > self.limit)
        {
            return Ok(());
        }
        self.nodes += 1;
        check(self.nodes <= 128, "READ_VIEW_RESOURCE_LIMIT")?;
        active()?;
        let artifact = load(&r.hash)?;
        active()?;
        let bytes = size(&artifact, NODE_BYTES)?;
        self.node_bytes += bytes;
        self.total += bytes;
        check(self.total <= TOTAL_BYTES, "READ_VIEW_RESOURCE_LIMIT")?;
        check(
            n(&artifact, "v")? == 1
                && hash(&artifact)? == r.hash
                && equivalent(g(&artifact, "context")?, &self.view.context)?
                && s(&artifact, "visibility")? == self.view.visibility,
            "READ_VIEW_NODE_HASH_MISMATCH",
        )?;
        let node = if self.view.visibility == "PRIVATE" {
            decrypt(
                g(&artifact, "body")?,
                &self.view.context,
                self.view
                    .key
                    .as_ref()
                    .ok_or(ReadViewError("READ_VIEW_KEY_REQUIRED"))?,
                NODE_BYTES,
            )?
        } else {
            g(&artifact, "body")?.clone()
        };
        check(n(&node, "v")? == 1, "READ_VIEW_NODE_INVALID")?;
        if s(&node, "kind")? == "leaf" {
            let entries = arr(g(&node, "entries")?)?;
            check(
                entries.len() <= 8 && entries.len() as u64 == r.count,
                "READ_VIEW_NODE_INVALID",
            )?;
            let mut prior = None;
            for e in entries {
                let k = s(e, "key")?;
                check(
                    key(&k) && !k.is_empty() && prior.as_ref().is_none_or(|p: &String| p < &k),
                    "READ_VIEW_NODE_INVALID",
                )?;
                prior = Some(k);
            }
            check(
                entries
                    .first()
                    .map(|e| s(e, "key"))
                    .transpose()?
                    .unwrap_or_default()
                    == r.min
                    && entries
                        .last()
                        .map(|e| s(e, "key"))
                        .transpose()?
                        .unwrap_or_default()
                        == r.max,
                "READ_VIEW_NODE_RANGE_MISMATCH",
            )?;
            for e in entries {
                let k = s(e, "key")?;
                if k.as_str() >= self.prefix
                    && k < upper
                    && self.after.is_none_or(|a| k.as_str() > a)
                {
                    self.entries.push(e.clone());
                    if self.entries.len() > self.limit {
                        break;
                    }
                }
            }
        } else {
            check(s(&node, "kind")? == "branch", "READ_VIEW_NODE_INVALID")?;
            let children = arr(g(&node, "children")?)?;
            check((2..=8).contains(&children.len()), "READ_VIEW_NODE_INVALID")?;
            let refs = children.iter().map(node_ref).collect::<R<Vec<_>>>()?;
            let mut prior = None;
            let mut count = 0;
            for c in &refs {
                check(
                    c.count > 0 && prior.as_ref().is_none_or(|p: &String| p < &c.min),
                    "READ_VIEW_NODE_INVALID",
                )?;
                prior = Some(c.max.clone());
                count += c.count;
            }
            check(
                count == r.count
                    && refs.first().is_some_and(|c| c.min == r.min)
                    && refs.last().is_some_and(|c| c.max == r.max),
                "READ_VIEW_NODE_RANGE_MISMATCH",
            )?;
            for c in refs {
                self.visit(&c, depth + 1, load, active)?;
                if self.entries.len() > self.limit {
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Authenticate the configured service clock before deriving any expiry decision.
pub fn observed_time(bootstrap: &W, pin: &ReadViewPin, nonce: &str) -> R<u64> {
    size(bootstrap, BOOTSTRAP_BYTES)?;
    let observation = g(bootstrap, "observation")?;
    signed(
        observation,
        "peerwork.read-observation.v1",
        &pin.service_key,
    )?;
    let p = payload(observation)?;
    check(
        s(p, "nonce")? == nonce
            && s(p, "origin")? == pin.origin
            && s(p, "service_key")? == pin.service_key,
        "READ_VIEW_OBSERVATION_INVALID",
    )?;
    n(p, "observed_at")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> Vec<W> {
        arr(g(
            &parse(
                include_bytes!("../tests/fixtures/workspace-read-view-v1.json"),
                1024 * 1024,
            )
            .unwrap(),
            "vectors",
        )
        .unwrap())
        .unwrap()
        .to_vec()
    }
    fn pin(v: &W) -> ReadViewPin {
        let p = g(v, "pin").unwrap();
        ReadViewPin {
            origin: s(p, "origin").unwrap(),
            workspace_id: s(p, "workspace").unwrap(),
            owner_actor_id: s(p, "ownerId").unwrap(),
            owner_key_id: s(p, "ownerKey").unwrap(),
            audience: s(p, "audience").unwrap(),
            service_key: s(p, "serviceKey").unwrap(),
        }
    }
    fn open(v: &W) -> R<AuthorizedReadView> {
        let key = if s(v, "visibility")? == "PRIVATE" {
            let k = &arr(g(g(v, "keyring")?, "keys")?)?[0];
            Some(
                crypto::decode_base64url(&s(k, "key")?)
                    .map_err(|_| invalid())?
                    .try_into()
                    .map_err(|_| invalid())?,
            )
        } else {
            None
        };
        AuthorizedReadView::open(
            g(v, "bootstrap")?,
            pin(v),
            &s(v, "nonce")?,
            n(v, "now")?,
            true,
            None,
            key,
        )
    }
    fn select(v: &W) -> ReadViewSelection {
        let q = g(v, "query").unwrap();
        ReadViewSelection::Get {
            object_kind: s(q, "kind").unwrap(),
            id: s(q, "id").unwrap(),
        }
    }
    fn set(v: &mut W, key: &str, new: W) {
        if let W::Object(fields) = v {
            let field = fields
                .iter_mut()
                .find(|(k, _)| k.iter().copied().eq(key.encode_utf16()))
                .unwrap();
            field.1 = new;
        } else {
            panic!()
        }
    }
    fn query(v: &W, view: &AuthorizedReadView, selection: &ReadViewSelection) -> R<W> {
        view.query(
            selection,
            |h| g(g(v, "nodes")?, h).cloned(),
            |h| g(g(v, "commits")?, h).cloned(),
            || Ok(()),
        )
    }
    #[test]
    fn read_view_frozen_public_private_vectors() {
        for v in fixtures() {
            let view = open(&v).unwrap();
            let result = query(&v, &view, &select(&v)).unwrap();
            assert!(equivalent(g(&result, "object").unwrap(), g(&v, "expected").unwrap()).unwrap());
            assert_eq!(n(g(&result, "metrics").unwrap(), "nodes").unwrap(), 1);
            assert_eq!(n(g(&result, "metrics").unwrap(), "commits").unwrap(), 1);
            assert_eq!(s(&result, "assurance").unwrap(), "AUTHORIZED_STATE");
            assert!(view.check_elapsed(100000).is_err());
        }
    }
    #[test]
    fn read_view_rejects_root_nonce_and_node_tamper() {
        for v in fixtures() {
            let boot = g(&v, "bootstrap").unwrap();
            assert!(
                AuthorizedReadView::open(boot, pin(&v), &"a".repeat(43), 13, true, None, None)
                    .is_err()
            );
            let mut changed = boot.clone();
            let mut root = g(&changed, "root").unwrap().clone();
            let mut payload = payload(&root).unwrap().clone();
            set(&mut payload, "root_number", number(2));
            set(&mut root, "payload", payload);
            set(&mut changed, "root", root);
            assert!(AuthorizedReadView::open(
                &changed,
                pin(&v),
                &s(&v, "nonce").unwrap(),
                13,
                true,
                None,
                None
            )
            .is_err());
            let view = open(&v).unwrap();
            assert!(view
                .query(
                    &select(&v),
                    |h| {
                        let mut node = g(g(&v, "nodes")?, h)?.clone();
                        set(&mut node, "v", number(2));
                        Ok(node)
                    },
                    |h| g(g(&v, "commits")?, h).cloned(),
                    || Ok(())
                )
                .is_err());
        }
    }
    #[test]
    fn read_view_rejects_author_and_missing_exact_does_not_fetch_neighbor() {
        let v = fixtures().remove(0);
        let view = open(&v).unwrap();
        assert!(view
            .query(
                &select(&v),
                |h| g(g(&v, "nodes")?, h).cloned(),
                |h| {
                    let mut ev = g(g(&v, "commits")?, h)?.clone();
                    let mut c = g(&ev, "commit")?.clone();
                    set(&mut c, "signature", string(&"a".repeat(86)));
                    set(&mut ev, "commit", c);
                    Ok(ev)
                },
                || Ok(())
            )
            .is_err());
        let id = s(g(&v, "query").unwrap(), "id").unwrap();
        let missing = ReadViewSelection::Get {
            object_kind: "workspaces".into(),
            id: id[..id.len() - 1].into(),
        };
        let result = view
            .query(
                &missing,
                |h| g(g(&v, "nodes")?, h).cloned(),
                |_| panic!("must not fetch prefix neighbor author"),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(g(&result, "object").unwrap(), &W::Null);
    }
    #[test]
    fn read_view_cursor_and_floor_bound() {
        let v = fixtures().remove(0);
        let view = open(&v).unwrap();
        let cursor = serde_json::json!({"v":1,"root_hash":"a".repeat(64),"query_hash":"b".repeat(64),"after":"i/x"});
        assert!(query(
            &v,
            &view,
            &ReadViewSelection::List {
                instance_id: "a".repeat(43),
                schema: "task.revision".into(),
                limit: Some(20),
                cursor: Some(cursor)
            }
        )
        .is_err());
        let mut floor = view.floor.clone();
        set(&mut floor, "root_hash", string(&"a".repeat(64)));
        assert!(AuthorizedReadView::open(
            g(&v, "bootstrap").unwrap(),
            pin(&v),
            &s(&v, "nonce").unwrap(),
            13,
            true,
            Some(&floor),
            None
        )
        .is_err());
    }
    #[test]
    fn read_view_source_certificate_and_unsupported_modes_fail_closed() {
        let v = fixtures().remove(0);
        let view = open(&v).unwrap();
        let mut wrong = pin(&v);
        wrong.origin = "https://wrong.example".into();
        assert!(AuthorizedReadView::open(
            g(&v, "bootstrap").unwrap(),
            wrong,
            &s(&v, "nonce").unwrap(),
            13,
            true,
            None,
            None
        )
        .is_err());
        let source = if let W::Object(entries) = g(&v, "commits").unwrap() {
            entries[0].1.clone()
        } else {
            panic!()
        };
        let mut delegated = source.clone();
        let mut commit = g(&delegated, "commit").unwrap().clone();
        let mut p = payload(&commit).unwrap().clone();
        set(&mut p, "delegation", obj(vec![]));
        set(&mut commit, "payload", p);
        let h = hash(&commit).unwrap();
        set(&mut delegated, "commit", commit);
        assert_eq!(
            view.verify_evidence(&delegated, &h, 1).unwrap_err().0,
            "READ_VIEW_UNSUPPORTED_DELEGATION"
        );
        let mut guarded = source.clone();
        let mut policy = g(&guarded, "policy").unwrap().clone();
        let mut q = payload(&policy).unwrap().clone();
        if let W::Object(fields) = &mut q {
            fields.push(("guard_time".encode_utf16().collect(), obj(vec![])));
        }
        set(&mut policy, "payload", q);
        let ph = hash(&policy).unwrap();
        set(&mut guarded, "policy", policy);
        let mut commit = g(&guarded, "commit").unwrap().clone();
        let mut p = payload(&commit).unwrap().clone();
        set(&mut p, "policy_hash", string(&ph));
        set(&mut commit, "payload", p);
        let h = hash(&commit).unwrap();
        set(&mut guarded, "commit", commit);
        assert_eq!(
            view.verify_evidence(&guarded, &h, 1).unwrap_err().0,
            "READ_VIEW_UNSUPPORTED_GUARD_TIME"
        );
        let mut broken = source.clone();
        let mut policy = g(&broken, "policy").unwrap().clone();
        set(&mut policy, "signature", string(&"a".repeat(86)));
        set(&mut broken, "policy", policy);
        assert!(view
            .verify_evidence(&broken, &hash(g(&source, "commit").unwrap()).unwrap(), 1)
            .is_err());
    }
    #[test]
    fn read_view_bounded_branch_range_and_missing_node() {
        let v = fixtures().remove(0);
        let view = open(&v).unwrap();
        let mut nodes = HashMap::<String, W>::new();
        let put =
            |body: W, min: String, max: String, count: u64, nodes: &mut HashMap<String, W>| {
                let artifact = obj(vec![
                    ("v", number(1)),
                    ("context", view.context.clone()),
                    ("visibility", string("PUBLIC")),
                    ("body", body),
                ]);
                let hash = hash(&artifact).unwrap();
                nodes.insert(hash.clone(), artifact);
                NodeRef {
                    hash,
                    min,
                    max,
                    count,
                }
            };
        let mut level = vec![];
        for first in (0..1000).step_by(8) {
            let entries = (first..(first + 8).min(1000))
                .map(|i| {
                    obj(vec![
                        ("key", string(&format!("p/{i:06}"))),
                        ("value", number(i)),
                    ])
                })
                .collect::<Vec<_>>();
            let min = s(&entries[0], "key").unwrap();
            let max = s(entries.last().unwrap(), "key").unwrap();
            let count = entries.len() as u64;
            level.push(put(
                obj(vec![
                    ("v", number(1)),
                    ("kind", string("leaf")),
                    ("entries", W::Array(entries)),
                ]),
                min,
                max,
                count,
                &mut nodes,
            ));
        }
        while level.len() > 1 {
            let mut next = vec![];
            for children in level.chunks(8) {
                if children.len() == 1 {
                    next.push(children[0].clone());
                    continue;
                }
                let refs = children
                    .iter()
                    .map(|r| {
                        obj(vec![
                            ("hash", string(&r.hash)),
                            ("min", string(&r.min)),
                            ("max", string(&r.max)),
                            ("count", number(r.count)),
                        ])
                    })
                    .collect();
                next.push(put(
                    obj(vec![
                        ("v", number(1)),
                        ("kind", string("branch")),
                        ("children", W::Array(refs)),
                    ]),
                    children[0].min.clone(),
                    children.last().unwrap().max.clone(),
                    children.iter().map(|c| c.count).sum(),
                    &mut nodes,
                ));
            }
            level = next;
        }
        let mut t = Traversal {
            view: &view,
            prefix: "p/",
            after: None,
            limit: 20,
            entries: vec![],
            nodes: 0,
            node_bytes: 0,
            total: 0,
        };
        t.visit(
            &level[0],
            1,
            &mut |h| nodes.get(h).cloned().ok_or_else(invalid),
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(t.entries.len(), 21);
        assert_eq!(s(&t.entries[19], "key").unwrap(), "p/000019");
        assert!(t.nodes < 12);
        let mut t = Traversal {
            view: &view,
            prefix: "p/",
            after: Some("p/000997"),
            limit: 20,
            entries: vec![],
            nodes: 0,
            node_bytes: 0,
            total: 0,
        };
        t.visit(
            &level[0],
            1,
            &mut |h| nodes.get(h).cloned().ok_or_else(invalid),
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(t.entries.len(), 2);
        let mut t = Traversal {
            view: &view,
            prefix: "p/",
            after: None,
            limit: 20,
            entries: vec![],
            nodes: 0,
            node_bytes: 0,
            total: 0,
        };
        assert!(t
            .visit(
                &level[0],
                1,
                &mut |_| Err(ReadViewError("MISSING_NODE")),
                &mut || Ok(())
            )
            .is_err());
    }
    #[test]
    fn read_view_author_certificate_time_and_signature() {
        let v = fixtures().remove(0);
        let policy = g(g(&v, "bootstrap").unwrap(), "policy").unwrap();
        let member = &arr(g(payload(policy).unwrap(), "members").unwrap()).unwrap()[0];
        let cert = g(member, "certificate").unwrap();
        let c = payload(cert).unwrap();
        let author = s(c, "actor_id").unwrap();
        let key = s(c, "signing_key").unwrap();
        assert!(verify_author_certificate(cert, &author, &key, n(c, "issued_at").unwrap()).is_ok());
        assert!(
            verify_author_certificate(cert, &author, &key, n(c, "expires_at").unwrap()).is_err()
        );
        let mut bad = cert.clone();
        set(&mut bad, "signature", string(&"a".repeat(86)));
        assert!(verify_author_certificate(&bad, &author, &key, 2).is_err());
    }
    #[test]
    fn read_view_private_protected_ring_entry_matches_frozen_vector() {
        let v = fixtures()
            .into_iter()
            .find(|v| s(v, "visibility").unwrap() == "PRIVATE")
            .unwrap();
        let ring = crate::secure_keyring::SecretKeyring::parse_wire(
            wire(g(&v, "keyring").unwrap()).unwrap().as_bytes(),
        )
        .unwrap();
        let view = AuthorizedReadView::open_with_keyring(
            g(&v, "bootstrap").unwrap(),
            pin(&v),
            &s(&v, "nonce").unwrap(),
            n(&v, "now").unwrap(),
            true,
            None,
            &ring,
        )
        .unwrap();
        let result = view
            .query(
                &select(&v),
                |h| g(g(&v, "nodes").unwrap(), h).cloned(),
                |h| g(g(&v, "commits").unwrap(), h).cloned(),
                || Ok(()),
            )
            .unwrap();
        assert_eq!(arr(g(&result, "objects").unwrap()).unwrap().len(), 1);
    }
}
