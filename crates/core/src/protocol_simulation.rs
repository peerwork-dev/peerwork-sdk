//! Offline, fixture-only execution using the production action evaluator.
//!
//! No network, filesystem, private keys, signatures or acceptance proofs exist
//! in this API. All exported fixture provenance is a caller assertion. Results
//! MUST NOT be passed to a verified-journal or receipt API as trusted evidence.
use crate::{
    canonical::Path,
    crypto::{actor_id, base64url, decode_base64url, sha256, sha256_hex},
    full_manifest::validate_full_manifest,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue as V},
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_OBJECTS: usize = 4096;
const MAX_STEPS: usize = 64;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
type R<T> = Result<T, SimulationError>;

#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("{code} at {stage}: {constraint}")]
pub struct SimulationError {
    pub code: &'static str,
    pub stage: &'static str,
    pub step: Option<usize>,
    pub action_id: Option<String>,
    pub constraint: String,
}
fn err(code: &'static str, constraint: &str) -> SimulationError {
    SimulationError {
        code,
        stage: "fixture",
        step: None,
        action_id: None,
        constraint: constraint.into(),
    }
}
fn object(fields: Vec<(&str, V)>) -> V {
    V::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.encode_utf16().collect(), v))
            .collect(),
    )
}
fn s(value: &str) -> V {
    V::String(value.encode_utf16().collect())
}
fn n(value: u64) -> V {
    V::Number(value as f64)
}
fn set(value: &mut V, key: &str, next: V) {
    if let V::Object(fields) = value {
        if let Some((_, v)) = fields
            .iter_mut()
            .find(|(k, _)| k.iter().copied().eq(key.encode_utf16()))
        {
            *v = next;
        } else {
            fields.push((key.encode_utf16().collect(), next));
        }
    }
}
fn field<'a>(v: &'a V, key: &str) -> R<&'a V> {
    v.get(key)
        .ok_or_else(|| err("SIMULATION_INPUT_INVALID", key))
}
fn text(v: &V) -> R<String> {
    v.as_string()
        .ok_or_else(|| err("SIMULATION_INPUT_INVALID", "UTF-8 identifier required"))
}
fn integer(v: &V) -> R<u64> {
    let x = v
        .as_number()
        .ok_or_else(|| err("SIMULATION_INPUT_INVALID", "integer required"))?;
    if x.is_finite() && x >= 0.0 && x <= MAX_SAFE as f64 && x.fract() == 0.0 {
        Ok(x as u64)
    } else {
        Err(err(
            "SIMULATION_INPUT_INVALID",
            "safe nonnegative integer required",
        ))
    }
}
fn array(v: &V) -> R<&[V]> {
    if let V::Array(a) = v {
        Ok(a)
    } else {
        Err(err("SIMULATION_INPUT_INVALID", "array required"))
    }
}
fn shape(v: &V, required: &[&str], optional: &[&str]) -> R<()> {
    let V::Object(fields) = v else {
        return Err(err("SIMULATION_INPUT_INVALID", "object required"));
    };
    if required.iter().any(|k| v.get(k).is_none())
        || fields.iter().any(|(k, _)| {
            !required
                .iter()
                .chain(optional)
                .any(|a| k.iter().copied().eq(a.encode_utf16()))
        })
    {
        return Err(err("SIMULATION_INPUT_INVALID", "missing or unknown field"));
    }
    Ok(())
}
fn parse(input: &str) -> R<V> {
    parse_wire_json_bounded(input.as_bytes(), 64, MAX_BYTES)
        .map_err(|_| err("SIMULATION_INPUT_INVALID", "bounded strict JSON required"))
}
fn wire(v: &V) -> R<String> {
    canonical_wire_value(v, Path::SecureArtifact)
        .map_err(|_| err("SIMULATION_INPUT_INVALID", "canonical JSON required"))
}
fn digest(v: &V) -> R<String> {
    Ok(sha256_hex(wire(v)?.as_bytes()))
}
fn token(v: &str) -> bool {
    v.len() == 43
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn generated(seed: &str, label: &str) -> String {
    base64url(&sha256(
        format!("peerwork.simulation.v1\0{seed}\0{label}").as_bytes(),
    ))
}
fn named_token(seed: &str, name: &str) -> R<String> {
    if name.is_empty() || name.len() > 128 {
        return Err(err(
            "SIMULATION_INPUT_INVALID",
            "bounded nonempty name required",
        ));
    }
    Ok(if token(name) {
        name.into()
    } else {
        generated(seed, name)
    })
}
fn normalized_manifest(raw: &V) -> R<V> {
    let checked = validate_full_manifest(raw).map_err(|e| {
        let code = match e {
            crate::full_manifest::ManifestError::Invalid => "SIMULATION_MANIFEST_INVALID",
            crate::full_manifest::ManifestError::Resource => "SIMULATION_LIMIT",
            crate::full_manifest::ManifestError::Unsupported => "SIMULATION_UNSUPPORTED",
        };
        err(code, &format!("{e:?}"))
    })?;
    let wrapped = parse(&checked)?;
    let manifest = field(&wrapped, "manifest")?.clone();
    if !array(field(&manifest, "dependencies")?)?.is_empty()
        || manifest.get("execution_requirements").is_some()
    {
        return Err(err(
            "SIMULATION_UNSUPPORTED",
            "unresolved dependencies/execution requirements require an explicit closure adapter",
        ));
    }
    Ok(manifest)
}
fn manifest_digest(manifest: &V) -> R<String> {
    digest(&object(vec![
        ("semantics", s("peerwork.kernel.v1")),
        ("manifest", manifest.clone()),
    ]))
}
fn strings(v: &V) -> R<Vec<V>> {
    let a = array(v)?;
    if a.len() > 64 {
        return Err(err("SIMULATION_LIMIT", "too many bindings"));
    }
    let mut seen = HashSet::new();
    for x in a {
        let t = text(x)?;
        if t.is_empty() || t.len() > 120 || !seen.insert(t) {
            return Err(err("SIMULATION_INPUT_INVALID", "invalid binding"));
        }
    }
    Ok(a.to_vec())
}
fn row(kind: &str, id: &str, value: V) -> V {
    object(vec![
        ("kind", s(kind)),
        ("id", s(id)),
        ("revision", n(1)),
        ("value", value),
        ("provenance", s("AUTHOR_SIGNED")),
    ])
}

/// Build a deterministic synthetic fixture, never a production identity.
/// `protocols` contains `{instance_id, manifest, state?}`. Short instance names
/// are resolved through the returned `instances` mapping. Actors may specify
/// name, workspace_role, protocol_roles and capabilities. Default scopes grant
/// available actions only; protocol roles/capabilities remain explicit.
pub fn build_fixture_json(request_json: &str) -> R<String> {
    let q = parse(request_json)?;
    shape(&q, &["schema", "protocols"], &["actors", "seed", "time_ms"])?;
    if text(field(&q, "schema")?)? != "peerwork.protocol-fixture.v1" {
        return Err(err("SIMULATION_INPUT_INVALID", "schema"));
    }
    let seed = q
        .get("seed")
        .map(text)
        .transpose()?
        .unwrap_or_else(|| "default".into());
    if seed.len() > 128 {
        return Err(err("SIMULATION_LIMIT", "seed"));
    }
    let now = q.get("time_ms").map(integer).transpose()?.unwrap_or(0);
    let workspace = generated(&seed, "workspace");
    let protocols = array(field(&q, "protocols")?)?;
    if protocols.is_empty() || protocols.len() > 32 {
        return Err(err("SIMULATION_LIMIT", "1..32 protocols required"));
    }
    let mut objects = Vec::new();
    let mut instances = Vec::new();
    let mut manifests = Vec::new();
    let mut ids = HashSet::new();
    let mut digests = HashSet::new();
    for p in protocols {
        shape(p, &["instance_id", "manifest"], &["state"])?;
        let name = text(field(p, "instance_id")?)?;
        let id = named_token(&seed, &name)?;
        if !ids.insert(id.clone()) {
            return Err(err("SIMULATION_INPUT_INVALID", "duplicate instance"));
        }
        let manifest = normalized_manifest(field(p, "manifest")?)?;
        let hash = manifest_digest(&manifest)?;
        let state = p
            .get("state")
            .unwrap_or(field(&manifest, "initial_state")?)
            .clone();
        crate::full_manifest::validate_state_array_state(&manifest, &state)
            .map_err(|_| err("STATE_ARRAY_TYPE_INVALID", "initial fixture state"))?;
        if digests.insert(hash.clone()) {
            objects.push(row(
                "protocols",
                &hash,
                object(vec![
                    ("workspace_id", s(&workspace)),
                    ("digest", s(&hash)),
                    ("manifest", manifest.clone()),
                    ("resolved_manifest", manifest.clone()),
                ]),
            ));
        }
        objects.push(row(
            "instances",
            &id,
            object(vec![
                ("id", s(&id)),
                ("workspace_id", s(&workspace)),
                ("protocol_digest", s(&hash)),
                ("state", state),
                ("revision", n(0)),
                ("event_revision", n(0)),
            ]),
        ));
        instances.push(object(vec![
            ("name", s(&name)),
            ("instance_id", s(&id)),
            ("protocol_digest", s(&hash)),
        ]));
        manifests.push((id, manifest));
    }
    let defaults = V::Array(vec![object(vec![("name", s("default"))])]);
    let specs = array(q.get("actors").unwrap_or(&defaults))?;
    if specs.is_empty() || specs.len() > 32 {
        return Err(err("SIMULATION_LIMIT", "1..32 actors required"));
    }
    let mut actors = Vec::new();
    let mut members = Vec::new();
    let mut names = HashSet::new();
    for a in specs {
        shape(
            a,
            &["name"],
            &["workspace_role", "protocol_roles", "capabilities"],
        )?;
        let name = text(field(a, "name")?)?;
        if name.is_empty() || name.len() > 128 || !names.insert(name.clone()) {
            return Err(err("SIMULATION_INPUT_INVALID", "actor name"));
        }
        // Public bytes for fixture identity matching only. No private signing key exists.
        let public = sha256(format!("simulation-public\0{seed}\0{name}").as_bytes());
        let key = base64url(&public);
        let actor = actor_id(&public);
        let role = a
            .get("workspace_role")
            .map(text)
            .transpose()?
            .unwrap_or_else(|| {
                if actors.is_empty() {
                    "OWNER".into()
                } else {
                    "MEMBER".into()
                }
            });
        if !matches!(role.as_str(), "OWNER" | "MEMBER") {
            return Err(err("SIMULATION_INPUT_INVALID", "workspace_role"));
        }
        let empty = V::Array(vec![]);
        let roles = strings(a.get("protocol_roles").unwrap_or(&empty))?;
        let caps = strings(a.get("capabilities").unwrap_or(&empty))?;
        let mut scopes = Vec::new();
        for (id, m) in &manifests {
            let actions = array(field(m, "actions")?)?
                .iter()
                .map(|a| field(a, "id").cloned())
                .collect::<R<Vec<_>>>()?;
            scopes.push(object(vec![
                ("instance_id", s(id)),
                ("actions", V::Array(actions)),
                ("protocol_roles", V::Array(roles.clone())),
                ("capabilities", V::Array(caps.clone())),
            ]));
        }
        members.push(object(vec![
            ("actor_id", s(&actor)),
            (
                "certificate",
                object(vec![("payload", object(vec![("signing_key", s(&key))]))]),
            ),
            ("role", s(&role)),
            ("scopes", V::Array(scopes)),
        ]));
        actors.push(object(vec![
            ("name", s(&name)),
            ("actor_id", s(&actor)),
            ("signing_key", s(&key)),
        ]));
    }
    let policy = object(vec![(
        "payload",
        object(vec![
            ("v", n(3)),
            ("workspace_id", s(&workspace)),
            ("visibility", s("PRIVATE")),
            ("epoch", n(1)),
            ("owner_id", field(&actors[0], "actor_id")?.clone()),
            ("signing_key", field(&actors[0], "signing_key")?.clone()),
            ("issued_at", n(0)),
            ("members", V::Array(members)),
            (
                "guard_time",
                object(vec![
                    ("v", n(1)),
                    ("mode", s("ALL_COMMITS")),
                    ("audience", s("simulation.invalid")),
                    (
                        "service_key",
                        s(&generated(&seed, "simulation-service-public")),
                    ),
                    ("disclosure", s("GUARD_WINDOW")),
                ]),
            ),
        ]),
    )]);
    let fixture = object(vec![
        ("provenance", object(vec![("kind", s("synthetic"))])),
        ("workspace_id", s(&workspace)),
        ("policy", policy),
        ("objects", V::Array(objects)),
        ("actors", V::Array(actors)),
        ("instances", V::Array(instances)),
        ("time_ms", n(now)),
        ("sequence", n(0)),
    ]);
    validate_fixture(&fixture)?;
    wire(&fixture)
}

fn project_fields(value: &V, keys: &[&str]) -> R<V> {
    Ok(object(
        keys.iter()
            .map(|key| Ok((*key, field(value, key)?.clone())))
            .collect::<R<Vec<_>>>()?,
    ))
}
fn decoded_projection(value: &V) -> R<V> {
    match value {
        V::String(units) => crate::wire_json::parse_js_json_string_bounded(units, 64, MAX_BYTES)
            .map_err(|_| err("SIMULATION_INPUT_INVALID", "encoded projection JSON")),
        other => Ok(other.clone()),
    }
}

/// Project a runtime-authenticated replay into a smaller, non-authoritative
/// simulation fixture. `policy` is `{payload, signature?}`, never a raw payload.
/// This pure function does not authenticate the supplied snapshot: even
/// `verified-export` remains an assertion by its caller. No signature, private
/// key or acceptance proof is copied to the fixture.
pub fn project_fixture_json(request_json: &str) -> R<String> {
    let q = parse(request_json)?;
    shape(
        &q,
        &[
            "schema",
            "workspace_id",
            "policy",
            "objects",
            "instance_ids",
            "actor_id",
            "source_digest",
            "time_ms",
            "sequence",
        ],
        &[],
    )?;
    if text(field(&q, "schema")?)? != "peerwork.protocol-export.v1" {
        return Err(err("SIMULATION_INPUT_INVALID", "schema"));
    }
    let workspace = field(&q, "workspace_id")?;
    let source = array(field(&q, "objects")?)?;
    if source.len() > MAX_OBJECTS {
        return Err(err("SIMULATION_LIMIT", "source objects"));
    }
    let selected = array(field(&q, "instance_ids")?)?;
    if selected.is_empty() || selected.len() > 32 {
        return Err(err("SIMULATION_LIMIT", "selected instances"));
    }
    let mut selections = HashSet::new();
    for id in selected {
        let id = text(id)?;
        if !token(&id) || !selections.insert(id) {
            return Err(err("SIMULATION_INPUT_INVALID", "selected instance token"));
        }
    }
    // Keep the latest projected version of each object. Historical records
    // have distinct record IDs and remain available for exact reference reads.
    let mut latest: HashMap<(String, String), &V> = HashMap::new();
    for o in source {
        let key = (text(field(o, "kind")?)?, text(field(o, "id")?)?);
        let revision = integer(field(o, "revision")?)?;
        if let Some(old) = latest.get(&key) {
            let previous = integer(field(old, "revision")?)?;
            if revision == previous && wire(o)? != wire(old)? {
                return Err(err(
                    "SIMULATION_INPUT_INVALID",
                    "conflicting source revisions",
                ));
            }
            if revision <= previous {
                continue;
            }
        }
        latest.insert(key, o);
    }
    let mut protocols = HashSet::new();
    let mut instances = Vec::new();
    for id in selected {
        let name = text(id)?;
        let instance = latest
            .get(&("instances".into(), name.clone()))
            .ok_or_else(|| err("INCOMPLETE_FIXTURE", "selected instance missing"))?;
        let value = field(instance, "value")?;
        if field(value, "workspace_id")? != workspace {
            return Err(err("SIMULATION_INPUT_INVALID", "instance workspace"));
        }
        let hash = text(field(value, "protocol_digest")?)?;
        protocols.insert(hash.clone());
        instances.push(object(vec![
            ("name", s(&name)),
            ("instance_id", id.clone()),
            ("protocol_digest", s(&hash)),
        ]));
    }
    let selected_value = |value: &V| {
        value
            .get("instance_id")
            .and_then(V::as_string)
            .is_some_and(|id| selections.contains(&id))
    };
    let selected_records = latest
        .iter()
        .filter_map(|((kind, id), o)| {
            (kind == "records" && o.get("value").is_some_and(&selected_value)).then_some(id.clone())
        })
        .collect::<HashSet<_>>();
    let mut output = Vec::new();
    // HashMap order is deliberately never part of deterministic fixture bytes.
    let mut ordered = latest.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|(a, _), (b, _)| a.cmp(b));
    for ((kind, id), o) in ordered {
        let value = field(o, "value")?;
        let keys: &[&str] = match kind.as_str() {
            "protocols" if protocols.contains(&id) => {
                if value.get("composition").is_some_and(|v| v != &V::Null) {
                    return Err(err(
                        "SIMULATION_UNSUPPORTED",
                        "composed source requires a qualified closure adapter",
                    ));
                }
                &["workspace_id", "digest", "manifest"]
            }
            "instances" if selections.contains(&id) => &[
                "id",
                "workspace_id",
                "protocol_digest",
                "state",
                "revision",
                "event_revision",
            ],
            "records" if selected_value(value) => &[
                "id",
                "workspace_id",
                "instance_id",
                "protocol_digest",
                "entity_id",
                "schema_ref",
                "payload",
                "actor_id",
                "revision",
                "created",
            ],
            "entity_heads" if selected_value(value) => &[
                "entity_id",
                "workspace_id",
                "instance_id",
                "record_id",
                "revision",
                "updated",
            ],
            "grants" if selected_value(value) => {
                return Err(err(
                    "SIMULATION_UNSUPPORTED",
                    "legacy grant history requires a qualified fixture adapter",
                ))
            }
            "protocol_status"
                if value
                    .get("digest")
                    .and_then(V::as_string)
                    .is_some_and(|hash| protocols.contains(&hash)) =>
            {
                if value.get("state") != Some(&s("ACTIVE")) {
                    return Err(err("PROTOCOL_SUSPENDED", "selected protocol status"));
                }
                continue;
            }
            // Existing relations affect collision/uniqueness checks. Never
            // silently omit them while claiming equivalent action semantics.
            "record_relations" => {
                let source_id = text(field(value, "record_id")?)?;
                let target_id = text(field(value, "target_record")?)?;
                if selected_records.contains(&source_id) || selected_records.contains(&target_id) {
                    return Err(err(
                        "SIMULATION_UNSUPPORTED",
                        "relation history requires a qualified fixture adapter",
                    ));
                }
                continue;
            }
            _ => continue,
        };
        let mut projected = project_fields(value, keys)?;
        if kind == "protocols" {
            set(
                &mut projected,
                "resolved_manifest",
                value
                    .get("resolved_manifest")
                    .unwrap_or(field(value, "manifest")?)
                    .clone(),
            );
        }
        for key in match kind.as_str() {
            "protocols" => vec!["manifest", "resolved_manifest"],
            "instances" => vec!["state"],
            "records" => vec!["payload"],
            _ => vec![],
        } {
            let decoded = decoded_projection(field(&projected, key)?)?;
            set(&mut projected, key, decoded);
        }
        let mut wrapper = project_fields(o, &["kind", "id", "revision", "provenance"])?;
        set(&mut wrapper, "value", projected);
        output.push(wrapper);
    }
    let signed_policy = field(&q, "policy")?;
    shape(signed_policy, &["payload"], &["signature"])?;
    let payload = field(signed_policy, "payload")?;
    let mut policy = project_fields(
        payload,
        &[
            "v",
            "workspace_id",
            "visibility",
            "epoch",
            "owner_id",
            "signing_key",
            "issued_at",
        ],
    )?;
    if let Some(guard) = payload.get("guard_time") {
        set(&mut policy, "guard_time", guard.clone());
    }
    let mut members = Vec::new();
    let mut actors = Vec::new();
    for member in array(field(payload, "members")?)? {
        let mut projected = project_fields(member, &["actor_id", "role"])?;
        let key = field(
            field(field(member, "certificate")?, "payload")?,
            "signing_key",
        )?
        .clone();
        set(
            &mut projected,
            "certificate",
            object(vec![(
                "payload",
                object(vec![("signing_key", key.clone())]),
            )]),
        );
        let scopes = array(field(member, "scopes")?)?
            .iter()
            .filter(|scope| scope.get("instance_id") == Some(&V::Null) || selected_value(scope))
            .cloned()
            .collect();
        set(&mut projected, "scopes", V::Array(scopes));
        members.push(projected);
        if member.get("actor_id") == q.get("actor_id") {
            actors.push(object(vec![
                ("name", s("current")),
                ("actor_id", field(member, "actor_id")?.clone()),
                ("signing_key", key),
            ]));
        }
    }
    if actors.len() != 1 {
        return Err(err("AUTHOR_NOT_MEMBER", "selected snapshot actor"));
    }
    set(&mut policy, "members", V::Array(members));
    let fixture = object(vec![
        (
            "provenance",
            object(vec![
                ("kind", s("verified-export")),
                ("source_digest", field(&q, "source_digest")?.clone()),
            ]),
        ),
        ("workspace_id", workspace.clone()),
        ("policy", object(vec![("payload", policy)])),
        ("objects", V::Array(output)),
        ("actors", V::Array(actors)),
        ("instances", V::Array(instances)),
        ("time_ms", field(&q, "time_ms")?.clone()),
        ("sequence", field(&q, "sequence")?.clone()),
    ]);
    validate_fixture(&fixture)?;
    let encoded = wire(&fixture)?;
    if encoded.len() > MAX_BYTES {
        return Err(err("SIMULATION_LIMIT", "export fixture bytes"));
    }
    Ok(encoded)
}

fn validate_fixture(f: &V) -> R<()> {
    shape(
        f,
        &[
            "provenance",
            "workspace_id",
            "policy",
            "objects",
            "actors",
            "instances",
            "time_ms",
            "sequence",
        ],
        &[],
    )?;
    integer(field(f, "time_ms")?)?;
    integer(field(f, "sequence")?)?;
    let provenance = field(f, "provenance")?;
    shape(provenance, &["kind"], &["source_digest"])?;
    let kind = text(field(provenance, "kind")?)?;
    if !matches!(kind.as_str(), "synthetic" | "verified-export") {
        return Err(err("SIMULATION_INPUT_INVALID", "fixture provenance"));
    }
    if let Some(d) = provenance.get("source_digest") {
        let d = text(d)?;
        if d.len() != 64 || !d.bytes().all(|x| x.is_ascii_hexdigit()) {
            return Err(err("SIMULATION_INPUT_INVALID", "source_digest"));
        }
    }
    if kind == "verified-export" && provenance.get("source_digest").is_none() {
        return Err(err(
            "SIMULATION_INPUT_INVALID",
            "verified-export requires asserted source_digest",
        ));
    }
    let workspace = field(f, "workspace_id")?;
    if !token(&text(workspace)?) {
        return Err(err("SIMULATION_INPUT_INVALID", "workspace_id"));
    }
    let policy = field(f, "policy")?;
    shape(policy, &["payload"], &[])?;
    let payload = field(policy, "payload")?;
    shape(
        payload,
        &[
            "v",
            "workspace_id",
            "visibility",
            "epoch",
            "owner_id",
            "signing_key",
            "issued_at",
            "members",
        ],
        &["guard_time"],
    )?;
    if field(payload, "workspace_id")? != workspace
        || text(field(payload, "visibility")?)? != "PRIVATE"
        || ![1, 3].contains(&integer(field(payload, "v")?)?)
    {
        return Err(err("SIMULATION_UNSUPPORTED", "fixture policy mode"));
    }
    integer(field(payload, "epoch")?)?;
    integer(field(payload, "issued_at")?)?;
    if let Some(g) = payload.get("guard_time") {
        crate::guard_time::parse_guard_time_policy(g)
            .map_err(|_| err("GUARD_TIME_POLICY_INVALID", "fixture guard policy"))?;
    }
    let objects = array(field(f, "objects")?)?;
    if objects.len() > MAX_OBJECTS {
        return Err(err("SIMULATION_LIMIT", "objects"));
    }
    let mut seen = HashSet::new();
    let mut manifests = HashMap::new();
    for o in objects {
        shape(o, &["kind", "id", "revision", "value", "provenance"], &[])?;
        if text(field(o, "provenance")?)? != "AUTHOR_SIGNED" {
            return Err(err(
                "SIMULATION_UNSUPPORTED",
                "object projection provenance",
            ));
        }
        let kind = text(field(o, "kind")?)?;
        let id = text(field(o, "id")?)?;
        if kind != "protocols" && !token(&id) {
            return Err(err("SIMULATION_INPUT_INVALID", "object id"));
        }
        let rev = integer(field(o, "revision")?)?;
        if rev == 0 || !seen.insert((kind.clone(), id.clone(), rev)) {
            return Err(err("SIMULATION_INPUT_INVALID", "duplicate object revision"));
        }
        let v = field(o, "value")?;
        match kind.as_str() {
            "protocols" => {
                shape(
                    v,
                    &["workspace_id", "digest", "manifest", "resolved_manifest"],
                    &[],
                )?;
                let manifest = normalized_manifest(field(v, "manifest")?)?;
                // Digest pins exact source bytes, not an implicitly normalized replacement.
                let hash = manifest_digest(field(v, "manifest")?)?;
                if text(field(v, "digest")?)? != hash
                    || id != hash
                    || wire(field(v, "resolved_manifest")?)? != wire(field(v, "manifest")?)?
                {
                    return Err(err(
                        "SIMULATION_MANIFEST_INVALID",
                        "manifest digest or unsupported resolved source",
                    ));
                }
                if manifests.insert(hash, manifest).is_some() {
                    return Err(err("SIMULATION_INPUT_INVALID", "duplicate protocol"));
                }
            }
            "instances" => {
                shape(
                    v,
                    &[
                        "id",
                        "workspace_id",
                        "protocol_digest",
                        "state",
                        "revision",
                        "event_revision",
                    ],
                    &[],
                )?;
                if field(v, "id")? != field(o, "id")? {
                    return Err(err("SIMULATION_INPUT_INVALID", "instance id binding"));
                }
                integer(field(v, "revision")?)?;
                integer(field(v, "event_revision")?)?;
            }
            "records" => {
                shape(
                    v,
                    &[
                        "id",
                        "workspace_id",
                        "instance_id",
                        "protocol_digest",
                        "entity_id",
                        "schema_ref",
                        "payload",
                        "actor_id",
                        "revision",
                        "created",
                    ],
                    &[],
                )?;
                if field(v, "id")? != field(o, "id")? {
                    return Err(err("SIMULATION_INPUT_INVALID", "record id binding"));
                }
                integer(field(v, "revision")?)?;
                integer(field(v, "created")?)?;
                if integer(field(v, "revision")?)? == 0
                    || ["instance_id", "entity_id", "actor_id"].iter().any(|key| {
                        v.get(key)
                            .and_then(V::as_string)
                            .is_none_or(|id| !token(&id))
                    })
                {
                    return Err(err("SIMULATION_INPUT_INVALID", "record bindings"));
                }
            }
            "entity_heads" => {
                shape(
                    v,
                    &[
                        "entity_id",
                        "workspace_id",
                        "instance_id",
                        "record_id",
                        "revision",
                        "updated",
                    ],
                    &[],
                )?;
                integer(field(v, "revision")?)?;
                integer(field(v, "updated")?)?;
            }
            "record_relations" => {
                return Err(err(
                    "SIMULATION_UNSUPPORTED",
                    "relation fixtures require a qualified projection adapter",
                ));
            }
            _ => {
                return Err(err(
                    "SIMULATION_UNSUPPORTED",
                    "unsupported fixture object kind",
                ))
            }
        }
        if field(v, "workspace_id")? != workspace {
            return Err(err("SIMULATION_INPUT_INVALID", "object workspace mismatch"));
        }
    }
    for o in objects
        .iter()
        .filter(|o| o.get("kind") == Some(&s("instances")))
    {
        let v = field(o, "value")?;
        let hash = text(field(v, "protocol_digest")?)?;
        let m = manifests
            .get(&hash)
            .ok_or_else(|| err("INCOMPLETE_FIXTURE", "instance protocol missing"))?;
        crate::full_manifest::validate_state_array_state(m, field(v, "state")?)
            .map_err(|_| err("STATE_ARRAY_TYPE_INVALID", "fixture state"))?;
    }
    for o in objects
        .iter()
        .filter(|o| o.get("kind") == Some(&s("records")))
    {
        let value = field(o, "value")?;
        let manifest = manifests
            .get(&text(field(value, "protocol_digest")?)?)
            .ok_or_else(|| err("INCOMPLETE_FIXTURE", "record protocol missing"))?;
        let schema = text(field(value, "schema_ref")?)?;
        let definition = field(manifest, "record_schemas")?
            .get(&schema)
            .ok_or_else(|| err("RECORD_SCHEMA_INVALID", "fixture record schema"))?;
        crate::secure_replay::validate_simple_record_schema(field(value, "payload")?, definition)
            .map_err(|code| err(code, "fixture record payload"))?;
        if !objects.iter().any(|i| {
            i.get("kind") == Some(&s("instances"))
                && i.get("id") == value.get("instance_id")
                && i.get("value").and_then(|v| v.get("protocol_digest"))
                    == value.get("protocol_digest")
        }) {
            return Err(err(
                "INCOMPLETE_FIXTURE",
                "record instance/protocol binding",
            ));
        }
    }
    let members = array(field(payload, "members")?)?;
    if members.is_empty() || members.len() > 128 {
        return Err(err("SIMULATION_LIMIT", "members"));
    }
    let mut actors = HashSet::new();
    for member in members {
        shape(member, &["actor_id", "certificate", "role", "scopes"], &[])?;
        if !actors.insert(text(field(member, "actor_id")?)?) {
            return Err(err("SIMULATION_INPUT_INVALID", "duplicate member"));
        }
        if !matches!(text(field(member, "role")?)?.as_str(), "OWNER" | "MEMBER") {
            return Err(err("SIMULATION_INPUT_INVALID", "workspace role"));
        }
        let cert = field(member, "certificate")?;
        shape(cert, &["payload"], &[])?;
        shape(field(cert, "payload")?, &["signing_key"], &[])?;
        let key = text(field(field(cert, "payload")?, "signing_key")?)?;
        let public: [u8; 32] = decode_base64url(&key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| err("SIMULATION_INPUT_INVALID", "fixture public identity"))?;
        if text(field(member, "actor_id")?)? != actor_id(&public) {
            return Err(err("AUTHOR_KEY_MISMATCH", "fixture public identity"));
        }
        let scopes = array(field(member, "scopes")?)?;
        if scopes.len() > 128 {
            return Err(err("SIMULATION_LIMIT", "scopes"));
        }
        for scope in scopes {
            shape(
                scope,
                &["instance_id", "actions", "protocol_roles", "capabilities"],
                &["expires_at"],
            )?;
            strings(field(scope, "actions")?)?;
            strings(field(scope, "protocol_roles")?)?;
            strings(field(scope, "capabilities")?)?;
            if field(scope, "instance_id")? != &V::Null
                && !objects.iter().any(|o| {
                    o.get("kind") == Some(&s("instances"))
                        && o.get("id") == scope.get("instance_id")
                })
            {
                return Err(err("INCOMPLETE_FIXTURE", "scope instance missing"));
            }
            if let Some(e) = scope.get("expires_at") {
                if e != &V::Null {
                    integer(e)?;
                }
            }
            // Global grants may name roles/capabilities belonging to other
            // protocols. Preserve them exactly: production resolves applicable
            // scope and evaluates guards, rather than demanding that every
            // name be declared by each selected manifest.
        }
    }
    for (name, id_field) in [("actors", "actor_id"), ("instances", "instance_id")] {
        let mappings = array(field(f, name)?)?;
        if mappings.is_empty() || mappings.len() > 32 {
            return Err(err("SIMULATION_LIMIT", "fixture mappings"));
        }
        let mut names = HashSet::new();
        for mapping in mappings {
            shape(
                mapping,
                &[
                    "name",
                    id_field,
                    if name == "actors" {
                        "signing_key"
                    } else {
                        "protocol_digest"
                    },
                ],
                &[],
            )?;
            if !names.insert(text(field(mapping, "name")?)?) {
                return Err(err("SIMULATION_INPUT_INVALID", "duplicate mapping"));
            }
            if name == "actors" {
                let actor = text(field(mapping, id_field)?)?;
                let member = members
                    .iter()
                    .find(|m| m.get("actor_id") == Some(&s(&actor)))
                    .ok_or_else(|| err("INCOMPLETE_FIXTURE", "mapped actor missing"))?;
                if field(
                    field(field(member, "certificate")?, "payload")?,
                    "signing_key",
                )? != field(mapping, "signing_key")?
                {
                    return Err(err("SIMULATION_INPUT_INVALID", "actor key binding"));
                }
            } else if !objects.iter().any(|o| {
                o.get("kind") == Some(&s("instances"))
                    && o.get("id") == mapping.get(id_field)
                    && o.get("value").and_then(|v| v.get("protocol_digest"))
                        == mapping.get("protocol_digest")
            }) {
                return Err(err("INCOMPLETE_FIXTURE", "mapped instance missing"));
            }
        }
    }
    Ok(())
}

/// Run a bounded sequence atomically in memory. On any error no successor
/// fixture or partial result is returned. The input string is never modified.
pub fn simulate_json(request_json: &str) -> R<String> {
    let q = parse(request_json)?;
    shape(&q, &["schema", "fixture", "steps"], &["seed"])?;
    if text(field(&q, "schema")?)? != "peerwork.protocol-simulation.v1" {
        return Err(err("SIMULATION_INPUT_INVALID", "schema"));
    }
    let mut fixture = field(&q, "fixture")?.clone();
    validate_fixture(&fixture)?;
    let initial_digest = digest(&fixture)?;
    let seed = q
        .get("seed")
        .map(text)
        .transpose()?
        .unwrap_or_else(|| initial_digest.clone());
    if seed.len() > 128 {
        return Err(err("SIMULATION_LIMIT", "seed"));
    }
    let steps = array(field(&q, "steps")?)?;
    if steps.len() > MAX_STEPS {
        return Err(err("SIMULATION_LIMIT", "steps"));
    }
    let mut results = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let result = simulate_step(
            &mut fixture,
            step,
            &format!("{seed}:{initial_digest}:{index}"),
        );
        match result {
            Ok(v) => results.push(v),
            Err(mut e) => {
                e.stage = "execute";
                e.step = Some(index);
                e.action_id = step.get("action_id").and_then(V::as_string);
                return Err(e);
            }
        }
    }
    let output=object(vec![("schema",s("peerwork.protocol-simulation-result.v1")),("simulated",V::Bool(true)),("authoritative",V::Bool(false)),("fixture_provenance",field(&fixture,"provenance")?.clone()),("assumptions",V::Array(vec![s("Fixture provenance and authority are caller assertions, not verified acceptance."),s("Fixture contains all records required by tested predicates; completeness is not authenticated."),s("Clock, public identity bytes and allocations are simulation-only; no wall clock or private keys are used."),s("This result does not validate production transport, admission, policy signatures or historical role changes.")])),("input_fixture_digest",s(&initial_digest)),("steps",V::Array(results)),("fixture_digest",s(&digest(&fixture)?)),("fixture",fixture)]);
    let encoded = wire(&output)?;
    if encoded.len() > MAX_BYTES {
        return Err(err("SIMULATION_LIMIT", "result bytes"));
    }
    Ok(encoded)
}
fn simulate_step(fixture: &mut V, step: &V, seed: &str) -> R<V> {
    shape(
        step,
        &["instance_id", "action_id"],
        &[
            "body",
            "expected_instance_revision",
            "exact_input_refs",
            "allocations",
            "actor_id",
            "time_ms",
        ],
    )?;
    let instance_name = text(field(step, "instance_id")?)?;
    let binding = array(field(fixture, "instances")?)?
        .iter()
        .find(|i| {
            i.get("name") == Some(&s(&instance_name))
                || i.get("instance_id") == Some(&s(&instance_name))
        })
        .ok_or_else(|| err("INCOMPLETE_FIXTURE", "instance"))?;
    let instance = field(binding, "instance_id")?.clone();
    let actors = array(field(fixture, "actors")?)?;
    let actor = if let Some(a) = step.get("actor_id") {
        actors
            .iter()
            .find(|i| i.get("name") == Some(a) || i.get("actor_id") == Some(a))
            .ok_or_else(|| err("INCOMPLETE_FIXTURE", "actor"))?
    } else {
        &actors[0]
    };
    let now = step
        .get("time_ms")
        .map(integer)
        .transpose()?
        .unwrap_or(integer(field(fixture, "time_ms")?)?);
    if now < integer(field(fixture, "time_ms")?)? {
        return Err(err(
            "SIMULATION_CLOCK_ROLLBACK",
            "time_ms must not decrease",
        ));
    }
    let sequence = integer(field(fixture, "sequence")?)?
        .checked_add(1)
        .filter(|n| *n <= MAX_SAFE)
        .ok_or_else(|| err("SIMULATION_LIMIT", "sequence"))?;
    let prior = array(field(fixture, "objects")?)?;
    let old = prior
        .iter()
        .filter(|o| o.get("kind") == Some(&s("instances")) && o.get("id") == Some(&instance))
        .max_by_key(|o| o.get("revision").and_then(V::as_number).unwrap_or(0.0) as u64)
        .ok_or_else(|| err("INCOMPLETE_FIXTURE", "instance state"))?;
    let old_value = field(old, "value")?;
    let input_state = field(old_value, "state")?.clone();
    let revision = step
        .get("expected_instance_revision")
        .unwrap_or(field(old_value, "revision")?)
        .clone();
    integer(&revision)?;
    let refs = step
        .get("exact_input_refs")
        .cloned()
        .unwrap_or(V::Array(vec![]));
    if array(&refs)?.len() > 32 {
        return Err(err("SIMULATION_LIMIT", "refs"));
    }
    for r in array(&refs)? {
        shape(r, &["record_id", "revision"], &[])?;
        integer(field(r, "revision")?)?;
    }
    let allocations = step.get("allocations").cloned().unwrap_or(V::Null);
    if allocations != V::Null {
        if array(&allocations)?.len() > 8 {
            return Err(err("SIMULATION_LIMIT", "allocations"));
        }
        for a in array(&allocations)? {
            shape(a, &["record_id", "entity_id"], &[])?;
        }
    }
    let mut input = object(vec![
        ("instance_id", instance.clone()),
        ("expected_instance_revision", revision),
        ("action_id", field(step, "action_id")?.clone()),
        ("body", step.get("body").cloned().unwrap_or(object(vec![]))),
        ("exact_input_refs", refs),
        ("allocations", allocations),
    ]);
    let mut context = object(vec![
        ("v", n(3)),
        ("workspace_id", field(fixture, "workspace_id")?.clone()),
        ("sequence", n(sequence)),
        ("command_id", s(&generated(seed, "command"))),
        ("action_id", field(step, "action_id")?.clone()),
        ("instance_id", instance.clone()),
        ("actor_id", field(actor, "actor_id")?.clone()),
        ("signing_key", field(actor, "signing_key")?.clone()),
        ("issued_at", n(now)),
        ("delegation", V::Null),
    ]);
    // Preserve interpreter constraints which the production object composer
    // deliberately collapses into INVALID_PAYLOAD. Both passes use the same
    // interpreter; object composition remains the final semantic gate below.
    let policy_payload = field(field(fixture, "policy")?, "payload")?;
    let checked =
        crate::secure_action_delegation::resolve_action_scope(&context, policy_payload, None)
            .map_err(|e| err(e.code(), e.code()))?;
    if !checked.permits_action() {
        return Err(err("AUTHOR_SCOPE_DENIED", "action scope"));
    }
    let mut roles = Vec::new();
    let mut caps = Vec::new();
    for scope in &checked.scopes {
        if scope.get("instance_id") != Some(&V::Null) && scope.get("instance_id") != Some(&instance)
        {
            continue;
        }
        for (key, items) in [("protocol_roles", &mut roles), ("capabilities", &mut caps)] {
            for value in array(field(scope, key)?)? {
                let units = value
                    .as_utf16()
                    .ok_or_else(|| err("SIMULATION_INPUT_INVALID", key))?
                    .to_vec();
                if !items.contains(&units) {
                    items.push(units);
                }
            }
        }
    }
    let auth = crate::interpreter::InterpreterAuth {
        actor_id: checked.actor_id,
        workspace_roles: vec![checked.role.encode_utf16().collect()],
        protocol_roles: roles,
        capabilities: caps,
    };
    let exact = crate::secure_action_inputs::resolve_exact_inputs(
        field(&input, "exact_input_refs")?,
        prior,
        field(fixture, "workspace_id")?,
        &instance,
        field(old_value, "protocol_digest")?,
    )
    .map_err(|code| err(code, code))?;
    let protocol = prior
        .iter()
        .find(|o| {
            o.get("kind") == Some(&s("protocols"))
                && o.get("id") == old_value.get("protocol_digest")
        })
        .ok_or_else(|| err("INCOMPLETE_FIXTURE", "protocol"))?;
    let manifest = field(field(protocol, "value")?, "resolved_manifest")?;
    let eval = object(vec![("actions", field(manifest, "actions")?.clone())]);
    crate::interpreter::evaluate_action(
        &eval,
        field(step, "action_id")?
            .as_utf16()
            .ok_or_else(|| err("SIMULATION_INPUT_INVALID", "action_id"))?,
        &input_state,
        field(&input, "body")?,
        &auth,
        &exact,
        if policy_payload.get("guard_time").is_some() {
            Some(now)
        } else {
            None
        },
    )
    .map_err(|e| {
        let code = match e {
            crate::interpreter::EvalError::InvalidPayload => "INVALID_PAYLOAD",
            crate::interpreter::EvalError::Forbidden => "FORBIDDEN",
            crate::interpreter::EvalError::ConstraintFailed => "CONSTRAINT_FAILED",
            crate::interpreter::EvalError::ResourceExhausted => "RESOURCE_EXHAUSTED",
        };
        err(code, code)
    })?;
    let candidates = (0..8)
        .map(|i| {
            object(vec![
                ("record_id", s(&generated(seed, &format!("record:{i}")))),
                ("entity_id", s(&generated(seed, &format!("entity:{i}")))),
            ])
        })
        .collect::<Vec<_>>();
    let effects = crate::secure_replay::simulate_action_objects(
        &mut input,
        &mut context,
        field(fixture, "policy")?,
        prior,
        &candidates,
        now,
    )
    .map_err(|code| err(code, code))?;
    let mut next = prior.to_vec();
    for effect in array(&effects)? {
        // State/history projection keeps latest mutable objects but every record.
        if effect.get("kind") != Some(&s("records")) {
            next.retain(|o| o.get("kind") != effect.get("kind") || o.get("id") != effect.get("id"));
        }
        next.push(effect.clone());
    }
    if next.len() > MAX_OBJECTS {
        return Err(err("SIMULATION_LIMIT", "result objects"));
    }
    let output_state = array(&effects)?
        .iter()
        .find(|o| o.get("kind") == Some(&s("instances")) && o.get("id") == Some(&instance))
        .and_then(|o| o.get("value"))
        .and_then(|v| v.get("state"))
        .cloned()
        .ok_or_else(|| err("SIMULATION_INTERNAL", "instance result"))?;
    set(fixture, "objects", V::Array(next));
    set(fixture, "time_ms", n(now));
    set(fixture, "sequence", n(sequence));
    validate_fixture(fixture)?;
    let result = object(vec![
        ("action_id", field(step, "action_id")?.clone()),
        ("instance_id", instance),
        ("time_ms", n(now)),
        ("input_state", input_state),
        ("input", input),
        ("effects", effects),
        ("output_state", output_state),
        (
            "guard_time",
            context.get("guard_time").cloned().unwrap_or(V::Null),
        ),
    ]);
    if wire(fixture)?.len() > MAX_BYTES {
        return Err(err("SIMULATION_LIMIT", "fixture bytes"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn manifest() -> Value {
        json!({"name":"test.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},"actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[{"op":"eq","left":{"from":"state","path":["count"]},"right":{"from":"literal","value":0}}],"effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]})
    }
    fn fixture(m: Value) -> Value {
        serde_json::from_str(&build_fixture_json(&json!({"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"v1","manifest":m}]}).to_string()).unwrap()).unwrap()
    }
    fn request(f: Value, steps: Value) -> String {
        json!({"schema":"peerwork.protocol-simulation.v1","fixture":f,"steps":steps}).to_string()
    }
    #[test]
    fn deterministic_simulation_never_mints_acceptance() {
        let q = request(
            fixture(manifest()),
            json!([{"instance_id":"v1","action_id":"set"}]),
        );
        let a = simulate_json(&q).unwrap();
        assert_eq!(a, simulate_json(&q).unwrap());
        let r: Value = serde_json::from_str(&a).unwrap();
        assert_eq!(r["simulated"], true);
        assert_eq!(r["authoritative"], false);
        assert!(r.get("receipt").is_none());
        assert_eq!(r["steps"][0]["input_state"]["count"], 0);
        assert_eq!(r["steps"][0]["output_state"]["count"], 1);
        assert_ne!(r["fixture_digest"], r["input_fixture_digest"]);
    }
    #[test]
    fn failed_sequence_has_no_partial_fixture_and_input_can_be_reused() {
        let f = fixture(manifest());
        let before = f.clone();
        let e = simulate_json(&request(
            f.clone(),
            json!([{"instance_id":"v1","action_id":"set"},{"instance_id":"v1","action_id":"set"}]),
        ))
        .unwrap_err();
        assert_eq!(e.step, Some(1));
        assert_eq!(f, before);
        assert!(
            simulate_json(&request(f, json!([{"instance_id":"v1","action_id":"set"}]))).is_ok()
        );
    }
    #[test]
    fn time_boundary_and_clock_rollback() {
        let mut m = manifest();
        m["actions"][0]["variants"][0]["when"] = json!([
            {"op":"gte","left":{"from":"time"},"right":{"from":"literal","value":5}},
            {"op":"lt","left":{"from":"time"},"right":{"from":"literal","value":9}}]);
        let f = fixture(m);
        for t in [5, 8] {
            assert!(
                simulate_json(&request(
                    f.clone(),
                    json!([{"instance_id":"v1","action_id":"set","time_ms":t}])
                ))
                .is_ok(),
                "{t}"
            );
        }
        for t in [4, 9] {
            assert!(
                simulate_json(&request(
                    f.clone(),
                    json!([{"instance_id":"v1","action_id":"set","time_ms":t}])
                ))
                .is_err(),
                "{t}"
            );
        }
        let e=simulate_json(&request(f,json!([{"instance_id":"v1","action_id":"set","time_ms":5},{"instance_id":"v1","action_id":"set","time_ms":4}]))).unwrap_err();
        assert_eq!(e.code, "SIMULATION_CLOCK_ROLLBACK");
    }
    #[test]
    fn invalid_roles_and_missing_refs_are_not_ignored() {
        let mut f = fixture(manifest());
        f["policy"]["payload"]["members"][0]["scopes"][0]["protocol_roles"] =
            json!(["duplicate", "duplicate"]);
        assert_eq!(
            simulate_json(&request(f, json!([]))).unwrap_err().code,
            "SIMULATION_INPUT_INVALID"
        );
        let mut m = manifest();
        m["protocol_roles"] = json!(["reviewer"]);
        m["actions"][0]["variants"][0]["when"] =
            json!([{"op":"has_protocol_role","role":"reviewer"}]);
        assert_eq!(
            simulate_json(&request(
                fixture(m),
                json!([{"instance_id":"v1","action_id":"set"}])
            ))
            .unwrap_err()
            .code,
            "CONSTRAINT_FAILED"
        );
        let e=simulate_json(&request(fixture(manifest()),json!([{"instance_id":"v1","action_id":"set","exact_input_refs":[{"record_id":"R".repeat(43),"revision":1}]}]))).unwrap_err();
        assert_eq!(e.code, "REFERENCE_NOT_FOUND");
        assert_eq!(e.step, Some(0));
    }
    #[test]
    fn strict_shape_digest_numbers_and_resource_bounds() {
        let mut f = fixture(manifest());
        f["objects"][0]["value"]["manifest"]["display_version"] = json!("tampered");
        assert_eq!(
            simulate_json(&request(f, json!([]))).unwrap_err().code,
            "SIMULATION_MANIFEST_INVALID"
        );
        assert!(simulate_json("{\"schema\":NaN}").is_err());
        assert!(simulate_json("{\"schema\":1,\"schema\":2}").is_err());
        let e = simulate_json(&request(
            fixture(manifest()),
            Value::Array(vec![json!({"instance_id":"v1","action_id":"set"}); 65]),
        ))
        .unwrap_err();
        assert_eq!(e.code, "SIMULATION_LIMIT");
        let e = simulate_json(&request(
            fixture(manifest()),
            json!([{"instance_id":"v1","action_id":"set","ignore_auth":true}]),
        ))
        .unwrap_err();
        assert_eq!(e.code, "SIMULATION_INPUT_INVALID");
    }
    #[test]
    fn utf16_payload_is_lossless() {
        let mut m = manifest();
        m["actions"][0]["variants"][0]["effects"][0]["value"] =
            json!({"from":"body","path":["value"]});
        let f = fixture(m);
        let q = request(
            f,
            json!([{"instance_id":"v1","action_id":"set","body":{"value":"PLACEHOLDER"}}]),
        )
        .replace("PLACEHOLDER", "\\ud800");
        let r = simulate_json(&q).unwrap();
        assert!(r.contains("\\ud800"));
    }
    #[test]
    fn two_versions_remain_independent() {
        let a = manifest();
        let mut b = a.clone();
        b["display_version"] = json!("2");
        b["actions"][0]["variants"][0]["effects"][0]["value"]["value"] = json!(2);
        let f:Value=serde_json::from_str(&build_fixture_json(&json!({"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"v1","manifest":a},{"instance_id":"v2","manifest":b}]}).to_string()).unwrap()).unwrap();
        let r:Value=serde_json::from_str(&simulate_json(&request(f,json!([{"instance_id":"v1","action_id":"set"},{"instance_id":"v2","action_id":"set"}]))).unwrap()).unwrap();
        assert_eq!(r["steps"][0]["output_state"]["count"], 1);
        assert_eq!(r["steps"][1]["output_state"]["count"], 2);
    }

    #[test]
    fn conversion_uses_exact_cross_instance_record_and_enforces_output_schema() {
        let mut a = manifest();
        a["record_schemas"] = json!({"ticket":{"type":"object","fields":{"title":"string"},"required":["title"],"max_bytes":4096}});
        a["actions"][0] = json!({"id":"create","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"append","schema":"ticket","value":{"from":"body","path":[]}}]}]});
        let mut b = a.clone();
        b["display_version"] = json!("2");
        b["record_schemas"]["ticket"]["fields"]["source"] = json!("json");
        b["record_schemas"]["ticket"]["required"] = json!(["title", "source"]);
        let reference = json!({"from":"ref","source":"body","path":["source"],"schema":"ticket","scope":"WORKSPACE"});
        b["actions"][0] = json!({"id":"import","reads":[],"writes":[],"revisionEffects":{"control":false,"contentEntities":[]},"variants":[{"when":[{"op":"exact_ref","ref":reference}],"effects":[{"op":"append","schema":"ticket","value":{"from":"object","fields":{"title":{"from":"resolved_payload","ref":reference,"path":["title"]},"source":{"from":"body","path":["source"]}}}}]}]});
        let f: Value = serde_json::from_str(&build_fixture_json(&json!({"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"old","manifest":a},{"instance_id":"new","manifest":b}]}).to_string()).unwrap()).unwrap();
        let source = json!({"record_id":"R".repeat(43),"revision":1});
        let steps = json!([
            {"instance_id":"old","action_id":"create","body":{"title":"Original"},"allocations":[{"record_id":"R".repeat(43),"entity_id":"E".repeat(43)}]},
            {"instance_id":"new","action_id":"import","body":{"source":source},"exact_input_refs":[source]}
        ]);
        let r: Value =
            serde_json::from_str(&simulate_json(&request(f.clone(), steps.clone())).unwrap())
                .unwrap();
        assert_eq!(
            r["steps"][1]["effects"][0]["value"]["payload"],
            json!({"title":"Original","source":source})
        );
        assert_ne!(
            r["steps"][0]["effects"][0]["id"],
            r["steps"][1]["effects"][0]["id"]
        );
        let mut missing = steps.clone();
        missing[1]["exact_input_refs"][0]["revision"] = json!(2);
        let e = simulate_json(&request(f.clone(), missing)).unwrap_err();
        assert_eq!(e.code, "REFERENCE_NOT_FOUND");
        assert_eq!(e.step, Some(1));
        let mut invalid = steps;
        invalid[0]["body"]["title"] = json!(7);
        assert_eq!(
            simulate_json(&request(f, invalid)).unwrap_err().code,
            "RECORD_SCHEMA_INVALID"
        );
    }

    #[test]
    fn revision_expiry_and_provenance_are_explicit() {
        let f = fixture(manifest());
        assert_eq!(
            simulate_json(&request(
                f.clone(),
                json!([{"instance_id":"v1","action_id":"set","expected_instance_revision":99}])
            ))
            .unwrap_err()
            .code,
            "STALE_REVISION"
        );
        let mut expired = f.clone();
        expired["policy"]["payload"]["members"][0]["scopes"][0]["expires_at"] = json!(5);
        assert_eq!(
            simulate_json(&request(
                expired,
                json!([{"instance_id":"v1","action_id":"set","time_ms":5}])
            ))
            .unwrap_err()
            .code,
            "AUTHOR_SCOPE_DENIED"
        );
        let mut exported = f;
        exported["provenance"] = json!({"kind":"verified-export","source_digest":"a".repeat(64)});
        let result: Value =
            serde_json::from_str(&simulate_json(&request(exported, json!([]))).unwrap()).unwrap();
        assert_eq!(result["authoritative"], false);
        assert_eq!(result["simulated"], true);
        assert!(result["assumptions"][0]
            .as_str()
            .unwrap()
            .contains("caller assertions"));
    }

    #[test]
    fn verified_export_projects_real_metadata_without_rewriting_source_or_authority() {
        let mut source: Value = serde_json::from_str(
            &build_fixture_json(
                &json!({
                    "schema":"peerwork.protocol-fixture.v1","protocols":[
                        {"instance_id":"selected","manifest":manifest()},
                        {"instance_id":"other","manifest":manifest()}
                    ]
                })
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        let selected = source["instances"][0]["instance_id"].clone();
        for object in source["objects"].as_array_mut().unwrap() {
            match object["kind"].as_str().unwrap() {
                "instances" => {
                    object["value"]["origin_entrypoint"] = json!("board");
                    object["value"]["created"] = json!(123);
                    object["value"]["semantics"] = json!("peerwork.kernel.v1");
                    object["value"]["package_source"] = Value::Null;
                }
                "protocols" => {
                    object["value"]["name"] = json!("Display metadata");
                    object["value"]["package_source"] = Value::Null;
                }
                _ => {}
            }
        }
        source["policy"]["signature"] = json!("caller-asserted-snapshot-signature");
        source["policy"]["payload"]["version"] = json!(12);
        source["policy"]["payload"]["structure_mode"] = json!("STRUCTURED");
        source["policy"]["payload"]["members"][0]["certificate"]["payload"]["encryption_key"] =
            json!({"kty":"EC"});
        source["policy"]["payload"]["members"][0]["scopes"].as_array_mut().unwrap().push(json!({
            "instance_id":null,"actions":["other.action"],"protocol_roles":["other.role"],"capabilities":["other.capability"]
        }));
        for index in 1..34 {
            let public = sha256(format!("export-member-{index}").as_bytes());
            source["policy"]["payload"]["members"].as_array_mut().unwrap().push(json!({
                "actor_id":actor_id(&public),"certificate":{"payload":{"signing_key":base64url(&public)}},"role":"MEMBER","scopes":[]
            }));
        }
        let q = json!({"schema":"peerwork.protocol-export.v1","workspace_id":source["workspace_id"],
            "policy":source["policy"],"objects":source["objects"],"instance_ids":[selected],
            "actor_id":source["actors"][0]["actor_id"],"source_digest":"a".repeat(64),"time_ms":9,"sequence":12});
        let before = q.to_string();
        let f: Value = serde_json::from_str(&project_fixture_json(&before).unwrap()).unwrap();
        assert_eq!(q.to_string(), before);
        assert_eq!(f["provenance"]["kind"], "verified-export");
        assert_eq!(f["instances"].as_array().unwrap().len(), 1);
        assert_eq!(
            f["policy"]["payload"]["members"][0]["scopes"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            f["policy"]["payload"]["members"].as_array().unwrap().len(),
            34
        );
        assert!(f["policy"].get("signature").is_none());
        assert!(
            f["policy"]["payload"]["members"][0]["certificate"]["payload"]
                .get("encryption_key")
                .is_none()
        );
        assert!(f["objects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["value"].get("origin_entrypoint").is_none()));
        let result: Value = serde_json::from_str(
            &simulate_json(&request(
                f,
                json!([{"instance_id":selected,"action_id":"set"}]),
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["simulated"], true);
        assert_eq!(result["authoritative"], false);
        assert_eq!(result["steps"][0]["time_ms"], 9);
        let mut composition = q.clone();
        composition["objects"][0]["value"]["composition"] = json!({"source_manifest":{}});
        assert_eq!(
            project_fixture_json(&composition.to_string())
                .unwrap_err()
                .code,
            "SIMULATION_UNSUPPORTED"
        );
        let mut unsupported = q;
        unsupported["objects"].as_array_mut().unwrap().push(json!({"kind":"protocol_status","id":"status","revision":1,"value":{"digest":source["instances"][0]["protocol_digest"],"state":"SUSPENDED"}}));
        assert_eq!(
            project_fixture_json(&unsupported.to_string())
                .unwrap_err()
                .code,
            "PROTOCOL_SUSPENDED"
        );
    }
}
