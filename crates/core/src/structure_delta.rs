//! Readable structure state transition checks for authenticated DELTA content.
//! This module has no authority constructor; full replay also needs migration,
//! recovery, and historical object binding before a verified read can escape.

use crate::{
    canonical::Path,
    secure_replay::validate_readable_field,
    wire_json::{canonical_wire_value, WireValue},
};
use std::collections::{HashMap, HashSet};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidStructureDelta;
type Result<T> = std::result::Result<T, InvalidStructureDelta>;

fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue> {
    value.get(name).ok_or(InvalidStructureDelta)
}
fn text(value: &WireValue) -> Result<String> {
    value.as_string().ok_or(InvalidStructureDelta)
}
fn number(value: &WireValue) -> Result<u64> {
    let n = value.as_number().ok_or(InvalidStructureDelta)?;
    if !n.is_finite() || n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(InvalidStructureDelta);
    }
    Ok(n as u64)
}
fn array(value: &WireValue) -> Result<&[WireValue]> {
    if let WireValue::Array(items) = value {
        Ok(items)
    } else {
        Err(InvalidStructureDelta)
    }
}
fn object(value: &WireValue) -> Result<&[(Vec<u16>, WireValue)]> {
    if let WireValue::Object(fields) = value {
        Ok(fields)
    } else {
        Err(InvalidStructureDelta)
    }
}
fn exact(value: &WireValue, required: &[&str]) -> Result<()> {
    let fields = object(value)?;
    if fields.len() != required.len() || required.iter().any(|k| value.get(k).is_none()) {
        Err(InvalidStructureDelta)
    } else {
        Ok(())
    }
}
fn token(value: &WireValue) -> Result<Vec<u16>> {
    let units = value.as_utf16().ok_or(InvalidStructureDelta)?;
    if units.len() != 43
        || !units.iter().all(|v| {
            (*v >= b'A' as u16 && *v <= b'Z' as u16)
                || (*v >= b'a' as u16 && *v <= b'z' as u16)
                || (*v >= b'0' as u16 && *v <= b'9' as u16)
                || *v == b'_' as u16
                || *v == b'-' as u16
        })
    {
        return Err(InvalidStructureDelta);
    }
    Ok(units.to_vec())
}
fn digest(value: &WireValue) -> Result<()> {
    let units = value.as_utf16().ok_or(InvalidStructureDelta)?;
    if units.len() != 64
        || !units.iter().all(|v| {
            (*v >= b'a' as u16 && *v <= b'f' as u16) || (*v >= b'0' as u16 && *v <= b'9' as u16)
        })
    {
        Err(InvalidStructureDelta)
    } else {
        Ok(())
    }
}
fn same(a: &WireValue, b: &WireValue) -> Result<bool> {
    Ok(
        canonical_wire_value(a, Path::SecureArtifact).map_err(|_| InvalidStructureDelta)?
            == canonical_wire_value(b, Path::SecureArtifact).map_err(|_| InvalidStructureDelta)?,
    )
}
fn eq_field(a: &WireValue, a_key: &str, b: &WireValue, b_key: &str) -> Result<bool> {
    same(field(a, a_key)?, field(b, b_key)?)
}
fn find<'a>(values: &'a [WireValue], name: &str, needle: &WireValue) -> Option<&'a WireValue> {
    values.iter().find(|v| v.get(name) == Some(needle))
}
fn scoped(
    scopes: &[WireValue],
    instance: &WireValue,
    now: u64,
    kind: &str,
    wanted: &WireValue,
) -> bool {
    scopes.iter().any(|scope| {
        let expires = scope.get("expires_at");
        let active = expires
            .is_none_or(|v| matches!(v, WireValue::Null) || number(v).is_ok_and(|n| n > now));
        let matches_instance = scope
            .get("instance_id")
            .is_some_and(|id| matches!(id, WireValue::Null) || id == instance);
        active
            && matches_instance
            && scope
                .get(kind)
                .and_then(|v| array(v).ok())
                .is_some_and(|items| items.contains(wanted))
    })
}
fn authorized(
    member: &WireValue,
    delegation: Option<&WireValue>,
    instance: &WireValue,
    now: u64,
    kind: &str,
    wanted: &WireValue,
) -> Result<bool> {
    let member_scopes = array(field(member, "scopes")?)?;
    if !scoped(member_scopes, instance, now, kind, wanted) {
        return Ok(false);
    }
    if let Some(delegation) = delegation {
        let scopes = array(field(field(delegation, "payload")?, "scope")?)?;
        if !scoped(scopes, instance, now, kind, wanted) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn action_granted(
    action: &WireValue,
    member: &WireValue,
    delegation: Option<&WireValue>,
    instance: &WireValue,
    now: u64,
) -> Result<bool> {
    for (kind, field_name) in [
        ("protocol_roles", "roles"),
        ("capabilities", "capabilities"),
    ] {
        for wanted in array(field(action, field_name)?)? {
            if !authorized(member, delegation, instance, now, kind, wanted)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
fn refs<'a>(value: &'a WireValue, kind: &str) -> Result<Vec<&'a WireValue>> {
    if matches!(value, WireValue::Null) {
        return Ok(vec![]);
    }
    if kind == "references" {
        return Ok(array(value)?.iter().collect());
    }
    Ok(vec![value])
}
fn validate_record_shape(record: &WireValue, contract: &WireValue) -> Result<()> {
    exact(
        record,
        &[
            "record_id",
            "entity_id",
            "revision",
            "instance_id",
            "protocol_digest",
            "schema_ref",
            "actor_id",
            "created",
            "fields",
        ],
    )?;
    for key in ["record_id", "entity_id", "instance_id", "actor_id"] {
        token(field(record, key)?)?;
    }
    digest(field(record, "protocol_digest")?)?;
    if number(field(record, "revision")?)? == 0 {
        return Err(InvalidStructureDelta);
    }
    number(field(record, "created")?)?;
    let fields = field(record, "fields")?;
    let instance = field(record, "instance_id")?;
    let protocol = field(record, "protocol_digest")?;
    if !array(field(contract, "instances")?)?.iter().any(|row| {
        row.get("instance_id") == Some(instance) && row.get("protocol_digest") == Some(protocol)
    }) {
        return Err(InvalidStructureDelta);
    }
    let declaration = array(field(contract, "protocols")?)?
        .iter()
        .find(|row| row.get("protocol_digest") == Some(protocol))
        .ok_or(InvalidStructureDelta)?;
    let schema = text(field(record, "schema_ref")?)?;
    let definition = field(declaration, "schemas")?
        .get(&schema)
        .ok_or(InvalidStructureDelta)?;
    let declared = field(definition, "fields")?;
    for (name, value) in object(fields)? {
        let name = String::from_utf16(name).map_err(|_| InvalidStructureDelta)?;
        let rule = declared.get(&name).ok_or(InvalidStructureDelta)?;
        if field(rule, "protection")?.as_string().as_deref() != Some("server_readable")
            || validate_readable_field(rule, value).is_err()
        {
            return Err(InvalidStructureDelta);
        }
        // Projected references use the canonical record_id spelling.
        if matches!(
            field(rule, "type")?.as_string().as_deref(),
            Some(
                "reference"
                    | "workspace_reference"
                    | "optional_reference"
                    | "optional_workspace_reference"
                    | "references"
            )
        ) {
            for reference in refs(value, &text(field(rule, "type")?)?)? {
                exact(reference, &["record_id", "revision"])?;
            }
        }
    }
    for required in array(field(definition, "required")?)? {
        let name = text(required)?;
        let rule = declared.get(&name).ok_or(InvalidStructureDelta)?;
        if field(rule, "protection")?.as_string().as_deref() == Some("server_readable")
            && fields.get(&name).is_none()
        {
            return Err(InvalidStructureDelta);
        }
    }
    Ok(())
}
fn validate_head_shape(head: &WireValue) -> Result<()> {
    exact(head, &["entity_id", "record_id", "revision", "instance_id"])?;
    for key in ["entity_id", "record_id", "instance_id"] {
        token(field(head, key)?)?;
    }
    if number(field(head, "revision")?)? == 0 {
        return Err(InvalidStructureDelta);
    }
    Ok(())
}

fn validate_projection(
    records: &[WireValue],
    heads: &[WireValue],
    contract: &WireValue,
    limit: usize,
) -> Result<()> {
    if records.len() > limit || heads.len() > limit {
        return Err(InvalidStructureDelta);
    }
    let mut record_ids = HashSet::new();
    for record in records {
        validate_record_shape(record, contract)?;
        if !record_ids.insert(token(field(record, "record_id")?)?) {
            return Err(InvalidStructureDelta);
        }
    }
    let mut head_ids = HashSet::new();
    for head in heads {
        validate_head_shape(head)?;
        if !head_ids.insert(token(field(head, "entity_id")?)?) {
            return Err(InvalidStructureDelta);
        }
    }
    Ok(())
}

pub(crate) fn validate_projection_page(
    records: &[WireValue],
    heads: &[WireValue],
    contract: &WireValue,
) -> Result<()> {
    validate_projection(records, heads, contract, 128)
}

fn workflow_readable<'a>(schema: &'a WireValue) -> Result<Option<&'a WireValue>> {
    let Some(rule) = schema.get("workflow") else {
        return Ok(None);
    };
    let fields = field(schema, "fields")?;
    let mut critical = vec![
        text(field(rule, "status_field")?)?,
        text(field(rule, "parent_field")?)?,
    ];
    if let Some(dependencies) = rule.get("dependencies") {
        critical.push(text(field(dependencies, "field")?)?);
    }
    if critical.iter().any(|name| {
        fields
            .get(name)
            .and_then(|r| r.get("protection"))
            .and_then(WireValue::as_string)
            .as_deref()
            != Some("server_readable")
    }) {
        return Ok(None);
    }
    Ok(Some(rule))
}
fn readable_workflow_field(
    schema: &WireValue,
    rule: &WireValue,
    name: &str,
) -> Result<Option<String>> {
    let Some(field_name) = rule.get(name) else {
        return Ok(None);
    };
    let field_name = text(field_name)?;
    if field(schema, "fields")?
        .get(&field_name)
        .and_then(|r| r.get("protection"))
        .and_then(WireValue::as_string)
        .as_deref()
        == Some("server_readable")
    {
        Ok(Some(field_name))
    } else {
        Ok(None)
    }
}
fn reference(value: &WireValue) -> Result<(Vec<u16>, u64)> {
    exact(value, &["record_id", "revision"])?;
    Ok((
        token(field(value, "record_id")?)?,
        number(field(value, "revision")?)?,
    ))
}
struct WorkflowValues {
    status: WireValue,
    parent: Option<(Vec<u16>, u64)>,
    assignee: Option<Vec<u16>>,
    dependencies: Vec<(Vec<u16>, u64)>,
}
fn workflow_values(
    schema: &WireValue,
    rule: &WireValue,
    record: &WireValue,
) -> Result<WorkflowValues> {
    let fields = field(record, "fields")?;
    let status_name = text(field(rule, "status_field")?)?;
    let status = field(fields, &status_name)?.clone();
    if !array(field(rule, "states")?)?.contains(&status) {
        return Err(InvalidStructureDelta);
    }
    let parent_name = text(field(rule, "parent_field")?)?;
    let parent = match field(fields, &parent_name)? {
        WireValue::Null => None,
        v => Some(reference(v)?),
    };
    let assignee = if let Some(name) = readable_workflow_field(schema, rule, "assignee_field")? {
        match field(fields, &name)? {
            WireValue::Null => None,
            v => Some(token(v)?),
        }
    } else {
        None
    };
    if let Some(deadline) = rule.get("deadline") {
        let name = text(field(deadline, "field")?)?;
        if field(schema, "fields")?
            .get(&name)
            .and_then(|r| r.get("protection"))
            .and_then(WireValue::as_string)
            .as_deref()
            == Some("server_readable")
        {
            let time = field(fields, &name)?;
            if !matches!(time, WireValue::Null) {
                number(time)?;
            }
        }
    }
    let dependencies = if let Some(dependency) = rule.get("dependencies") {
        let name = text(field(dependency, "field")?)?;
        let list = array(field(fields, &name)?)?;
        if list.len() > 32 {
            return Err(InvalidStructureDelta);
        }
        list.iter().map(reference).collect::<Result<Vec<_>>>()?
    } else {
        vec![]
    };
    Ok(WorkflowValues {
        status,
        parent,
        assignee,
        dependencies,
    })
}
fn belongs(record: &WireValue, schema: &[u16], instance: &WireValue, protocol: &WireValue) -> bool {
    record.get("schema_ref").and_then(WireValue::as_utf16) == Some(schema)
        && record.get("instance_id") == Some(instance)
        && record.get("protocol_digest") == Some(protocol)
}
fn record_map(rows: &[WireValue]) -> Result<HashMap<Vec<u16>, &WireValue>> {
    rows.iter()
        .map(|record| Ok((token(field(record, "record_id")?)?, record)))
        .collect()
}
fn head_map(rows: &[WireValue]) -> Result<HashMap<Vec<u16>, &WireValue>> {
    rows.iter()
        .map(|head| Ok((token(field(head, "entity_id")?)?, head)))
        .collect()
}
fn graph(
    rule: &WireValue,
    schema_definition: &WireValue,
    schema: &[u16],
    instance: &WireValue,
    protocol: &WireValue,
    records: &[WireValue],
    heads: &[WireValue],
) -> Result<()> {
    let all = record_map(records)?;
    let mut selected: HashMap<Vec<u16>, &WireValue> = HashMap::new();
    for head in heads {
        let id = token(field(head, "record_id")?)?;
        if let Some(record) = all
            .get(&id)
            .copied()
            .filter(|r| belongs(r, schema, instance, protocol))
        {
            if !eq_field(record, "entity_id", head, "entity_id")?
                || !eq_field(record, "revision", head, "revision")?
                || !same(field(head, "instance_id")?, instance)?
            {
                return Err(InvalidStructureDelta);
            }
            selected.insert(token(field(head, "entity_id")?)?, record);
        }
    }
    let mut edges: HashMap<Vec<u16>, Vec<Vec<u16>>> = HashMap::new();
    for (entity, record) in &selected {
        let own = workflow_values(schema_definition, rule, record)?;
        let mut dependencies = Vec::new();
        for (id, revision) in own.dependencies {
            let anchor = all.get(&id).copied().ok_or(InvalidStructureDelta)?;
            if number(field(anchor, "revision")?)? != revision
                || !belongs(anchor, schema, instance, protocol)
            {
                return Err(InvalidStructureDelta);
            }
            let target_entity = token(field(anchor, "entity_id")?)?;
            if &target_entity == entity || dependencies.contains(&target_entity) {
                return Err(InvalidStructureDelta);
            }
            let target = selected
                .get(&target_entity)
                .copied()
                .ok_or(InvalidStructureDelta)?;
            let target_values = workflow_values(schema_definition, rule, target)?;
            if let Some(spec) = rule.get("dependencies") {
                if array(field(spec, "gated_states")?)?.contains(&own.status)
                    && !array(field(spec, "satisfied_states")?)?.contains(&target_values.status)
                {
                    return Err(InvalidStructureDelta);
                }
            }
            dependencies.push(target_entity);
        }
        edges.insert(entity.clone(), dependencies);
    }
    // Iterative DFS, preserving the source's behavior on deep valid graphs.
    let mut done = HashSet::new();
    for start in edges.keys() {
        if done.contains(start) {
            continue;
        }
        let mut active = HashSet::new();
        let mut stack = vec![(start.clone(), 0usize)];
        active.insert(start.clone());
        while let Some((id, offset)) = stack.last_mut() {
            let next = edges
                .get(id)
                .ok_or(InvalidStructureDelta)?
                .get(*offset)
                .cloned();
            *offset += 1;
            if let Some(next) = next {
                if active.contains(&next) {
                    return Err(InvalidStructureDelta);
                }
                if !done.contains(&next) {
                    active.insert(next.clone());
                    stack.push((next, 0));
                }
            } else {
                let id = id.clone();
                stack.pop();
                active.remove(&id);
                done.insert(id);
            }
        }
    }
    Ok(())
}
fn workflow_change(
    rule: &WireValue,
    schema_definition: &WireValue,
    schema: &[u16],
    instance: &WireValue,
    protocol: &WireValue,
    action_id: &str,
    before_records: &[WireValue],
    before_heads: &[WireValue],
    after_records: &[WireValue],
    after_heads: &[WireValue],
    changed: &[WireValue],
    members: &HashSet<Vec<u16>>,
) -> Result<()> {
    let old = record_map(before_records)?;
    let after = record_map(after_records)?;
    let old_heads = head_map(before_heads)?;
    let new_heads = head_map(after_heads)?;
    for head in before_heads {
        let id = token(field(head, "record_id")?)?;
        let Some(record) = old
            .get(&id)
            .copied()
            .filter(|r| belongs(r, schema, instance, protocol))
        else {
            continue;
        };
        let entity = token(field(record, "entity_id")?)?;
        let target = new_heads
            .get(&entity)
            .and_then(|h| h.get("record_id"))
            .and_then(|id| token(id).ok())
            .and_then(|id| after.get(&id).copied())
            .ok_or(InvalidStructureDelta)?;
        if !belongs(target, schema, instance, protocol)
            || !eq_field(target, "entity_id", head, "entity_id")?
            || changed.iter().any(|r| {
                r.get("entity_id") == head.get("entity_id")
                    && !belongs(r, schema, instance, protocol)
            })
        {
            return Err(InvalidStructureDelta);
        }
    }
    for record in changed
        .iter()
        .filter(|r| belongs(r, schema, instance, protocol))
    {
        let next = workflow_values(schema_definition, rule, record)?;
        if next.assignee.as_ref().is_some_and(|a| !members.contains(a)) {
            return Err(InvalidStructureDelta);
        }
        let prior = next
            .parent
            .as_ref()
            .map(|(id, _)| old.get(id).copied().ok_or(InvalidStructureDelta))
            .transpose()?;
        let entity = token(field(record, "entity_id")?)?;
        if let Some(prior) = prior {
            if number(field(prior, "revision")?)? != next.parent.as_ref().unwrap().1
                || !eq_field(prior, "entity_id", record, "entity_id")?
                || !belongs(prior, schema, instance, protocol)
                || old_heads.get(&entity).and_then(|h| h.get("record_id")) != prior.get("record_id")
                || number(field(record, "revision")?)? != number(field(prior, "revision")?)? + 1
            {
                return Err(InvalidStructureDelta);
            }
        } else if number(field(record, "revision")?)? != 1 || old_heads.contains_key(&entity) {
            return Err(InvalidStructureDelta);
        }
        let previous = if let Some(prior) = prior {
            workflow_values(schema_definition, rule, prior)?.status
        } else {
            WireValue::Null
        };
        if !array(field(rule, "transitions")?)?.iter().any(|t| {
            t.get("action").and_then(WireValue::as_string).as_deref() == Some(action_id)
                && t.get("from") == Some(&previous)
                && t.get("to") == Some(&next.status)
        }) {
            return Err(InvalidStructureDelta);
        }
        if new_heads.get(&entity).and_then(|h| h.get("record_id")) != record.get("record_id") {
            return Err(InvalidStructureDelta);
        }
    }
    for head in after_heads {
        let id = token(field(head, "record_id")?)?;
        let Some(_record) = after
            .get(&id)
            .copied()
            .filter(|r| belongs(r, schema, instance, protocol))
        else {
            continue;
        };
        let entity = token(field(head, "entity_id")?)?;
        if old_heads.get(&entity).and_then(|h| h.get("record_id")) != head.get("record_id")
            && !changed
                .iter()
                .any(|r| r.get("record_id") == head.get("record_id"))
        {
            return Err(InvalidStructureDelta);
        }
    }
    graph(
        rule,
        schema_definition,
        schema,
        instance,
        protocol,
        after_records,
        after_heads,
    )
}

pub(crate) fn validate_snapshot_graph(
    contract: &WireValue,
    records: &[WireValue],
    heads: &[WireValue],
) -> Result<()> {
    validate_projection(records, heads, contract, 100_000)?;
    for head in heads {
        let record =
            find(records, "record_id", field(head, "record_id")?).ok_or(InvalidStructureDelta)?;
        if !eq_field(head, "entity_id", record, "entity_id")?
            || !eq_field(head, "revision", record, "revision")?
            || !eq_field(head, "instance_id", record, "instance_id")?
        {
            return Err(InvalidStructureDelta);
        }
    }
    for protocol in array(field(contract, "protocols")?)? {
        let protocol_id = field(protocol, "protocol_digest")?;
        for (schema, schema_definition) in object(field(protocol, "schemas")?)? {
            if let Some(rule) = workflow_readable(schema_definition)? {
                for instance in array(field(contract, "instances")?)?
                    .iter()
                    .filter(|i| i.get("protocol_digest") == Some(protocol_id))
                {
                    graph(
                        rule,
                        schema_definition,
                        schema,
                        field(instance, "instance_id")?,
                        protocol_id,
                        records,
                        heads,
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Apply a fully authenticated DELTA to the prior readable projection. The
/// caller must verify the signed envelope exactly matches operation objects.
pub(crate) fn apply_delta(
    records_delta: &[WireValue],
    heads_delta: &[WireValue],
    contract: &WireValue,
    before_records: &[WireValue],
    before_heads: &[WireValue],
    context: &WireValue,
    policy: &WireValue,
) -> Result<(Vec<WireValue>, Vec<WireValue>)> {
    if records_delta.len() > 128 || heads_delta.len() > 128 {
        return Err(InvalidStructureDelta);
    }
    let mut record_ids = HashSet::new();
    for record in records_delta {
        validate_record_shape(record, contract)?;
        if !record_ids.insert(token(field(record, "record_id")?)?) {
            return Err(InvalidStructureDelta);
        }
    }
    let mut head_ids = HashSet::new();
    for head in heads_delta {
        validate_head_shape(head)?;
        if !head_ids.insert(token(field(head, "entity_id")?)?) {
            return Err(InvalidStructureDelta);
        }
    }
    let payload = field(policy, "payload")?;
    let delegation = match context.get("delegation") {
        Some(WireValue::Null) | None => None,
        Some(value) => Some(value),
    };
    let principal = if let Some(d) = delegation {
        field(field(d, "payload")?, "actor_id")?
    } else {
        field(context, "actor_id")?
    };
    let member = array(field(payload, "members")?)?
        .iter()
        .find(|m| m.get("actor_id") == Some(principal))
        .ok_or(InvalidStructureDelta)?;
    let instance = field(context, "instance_id")?;
    let now = number(field(context, "issued_at")?)?;
    let action_id = text(field(context, "action_id")?)?;
    let mut records = before_records.to_vec();
    let mut heads = before_heads.to_vec();
    let mut index: HashMap<Vec<u16>, usize> = HashMap::new();
    for (i, record) in records.iter().enumerate() {
        index.insert(token(field(record, "record_id")?)?, i);
    }
    let mut head_index: HashMap<Vec<u16>, usize> = HashMap::new();
    for (i, head) in heads.iter().enumerate() {
        head_index.insert(token(field(head, "entity_id")?)?, i);
    }
    for record in records_delta {
        let id = token(field(record, "record_id")?)?;
        if index.contains_key(&id)
            || !eq_field(record, "instance_id", context, "instance_id")?
            || !same(field(record, "actor_id")?, principal)?
            || number(field(record, "created")?)? != now
        {
            return Err(InvalidStructureDelta);
        }
        let protocol = array(field(contract, "protocols")?)?
            .iter()
            .find(|p| p.get("protocol_digest") == record.get("protocol_digest"))
            .ok_or(InvalidStructureDelta)?;
        let action = field(protocol, "actions")?
            .get(&action_id)
            .ok_or(InvalidStructureDelta)?;
        if !array(field(action, "schemas")?)?.contains(field(record, "schema_ref")?)
            || !action_granted(action, member, delegation, instance, now)?
        {
            return Err(InvalidStructureDelta);
        }
        let fields = field(record, "fields")?;
        if let Some(author) = fields.get("author") {
            if !same(author, principal)? {
                return Err(InvalidStructureDelta);
            }
        }
        if let Some(assignee) = fields.get("assignee") {
            if !matches!(assignee, WireValue::Null)
                && find(array(field(payload, "members")?)?, "actor_id", assignee).is_none()
            {
                return Err(InvalidStructureDelta);
            }
        }
        let schema = text(field(record, "schema_ref")?)?;
        let definition = field(protocol, "schemas")?
            .get(&schema)
            .ok_or(InvalidStructureDelta)?;
        if let Some(workflow) = definition.get("workflow") {
            if let Some(name) = workflow
                .get("assignee_field")
                .and_then(WireValue::as_string)
            {
                if let Some(assignee) = fields.get(&name) {
                    if !matches!(assignee, WireValue::Null)
                        && find(array(field(payload, "members")?)?, "actor_id", assignee).is_none()
                    {
                        return Err(InvalidStructureDelta);
                    }
                }
            }
        }
        for (name, value) in object(fields)? {
            let name = String::from_utf16(name).map_err(|_| InvalidStructureDelta)?;
            let rule = field(definition, "fields")?
                .get(&name)
                .ok_or(InvalidStructureDelta)?;
            let kind = text(field(rule, "type")?)?;
            if matches!(
                kind.as_str(),
                "reference"
                    | "optional_reference"
                    | "references"
                    | "workspace_reference"
                    | "optional_workspace_reference"
            ) {
                for reference in refs(value, &kind)? {
                    let target_id = token(field(reference, "record_id")?)?;
                    let target = index
                        .get(&target_id)
                        .and_then(|i| records.get(*i))
                        .ok_or(InvalidStructureDelta)?;
                    if !eq_field(reference, "revision", target, "revision")?
                        || !matches!(
                            kind.as_str(),
                            "workspace_reference" | "optional_workspace_reference"
                        ) && !eq_field(record, "instance_id", target, "instance_id")?
                    {
                        return Err(InvalidStructureDelta);
                    }
                }
            }
        }
        // Fixed task transitions are checked before making this record visible.
        if let Some(transitions) = action.get("task_transition") {
            if schema == "task.revision" {
                let parent = fields.get("parent").unwrap_or(&WireValue::Null);
                let prior = if matches!(parent, WireValue::Null) {
                    None
                } else {
                    let id = token(field(parent, "record_id")?)?;
                    Some(
                        index
                            .get(&id)
                            .and_then(|i| records.get(*i))
                            .ok_or(InvalidStructureDelta)?,
                    )
                };
                if let Some(prior) = prior {
                    if !eq_field(prior, "entity_id", record, "entity_id")?
                        || !eq_field(prior, "schema_ref", record, "schema_ref")?
                        || number(field(prior, "revision")?)?.checked_add(1)
                            != Some(number(field(record, "revision")?)?)
                        || !head_index
                            .get(&token(field(record, "entity_id")?)?)
                            .and_then(|i| heads.get(*i))
                            .is_some_and(|h| h.get("record_id") == prior.get("record_id"))
                    {
                        return Err(InvalidStructureDelta);
                    }
                } else if number(field(record, "revision")?)? != 1
                    || head_index.contains_key(&token(field(record, "entity_id")?)?)
                {
                    return Err(InvalidStructureDelta);
                }
                let from = prior
                    .and_then(|p| p.get("fields"))
                    .and_then(|f| f.get("status"))
                    .unwrap_or(&WireValue::Null)
                    .clone();
                if !array(transitions)?.iter().any(|pair| {
                    pair.get("from") == Some(&from) && pair.get("to") == fields.get("status")
                }) {
                    return Err(InvalidStructureDelta);
                }
            }
        }
        index.insert(id, records.len());
        records.push(record.clone());
    }
    for head in heads_delta {
        let id = token(field(head, "record_id")?)?;
        let record = index
            .get(&id)
            .and_then(|i| records.get(*i))
            .ok_or(InvalidStructureDelta)?;
        if !eq_field(head, "entity_id", record, "entity_id")?
            || !eq_field(head, "revision", record, "revision")?
            || !eq_field(head, "instance_id", record, "instance_id")?
            || !eq_field(head, "instance_id", context, "instance_id")?
        {
            return Err(InvalidStructureDelta);
        }
        let protocol = array(field(contract, "protocols")?)?
            .iter()
            .find(|p| p.get("protocol_digest") == record.get("protocol_digest"))
            .ok_or(InvalidStructureDelta)?;
        let action = field(protocol, "actions")?
            .get(&action_id)
            .ok_or(InvalidStructureDelta)?;
        let head_mode = text(field(action, "heads")?)?;
        if !action_granted(action, member, delegation, instance, now)?
            || !(head_mode == "SELECT"
                || head_mode == "APPEND"
                    && records_delta
                        .iter()
                        .any(|r| r.get("record_id") == head.get("record_id")))
        {
            return Err(InvalidStructureDelta);
        }
        let entity = token(field(head, "entity_id")?)?;
        if let Some(i) = head_index.get(&entity) {
            heads[*i] = head.clone();
        } else {
            head_index.insert(entity, heads.len());
            heads.push(head.clone());
        }
    }
    let members: HashSet<Vec<u16>> = array(field(payload, "members")?)?
        .iter()
        .map(|member| token(field(member, "actor_id")?))
        .collect::<Result<_>>()?;
    for protocol in array(field(contract, "protocols")?)? {
        let protocol_id = field(protocol, "protocol_digest")?;
        for (schema, schema_definition) in object(field(protocol, "schemas")?)? {
            if let Some(rule) = workflow_readable(schema_definition)? {
                if !matches!(instance, WireValue::Null)
                    && array(field(contract, "instances")?)?.iter().any(|i| {
                        i.get("instance_id") == Some(instance)
                            && i.get("protocol_digest") == Some(protocol_id)
                    })
                {
                    workflow_change(
                        rule,
                        schema_definition,
                        schema,
                        instance,
                        protocol_id,
                        &action_id,
                        before_records,
                        before_heads,
                        &records,
                        &heads,
                        records_delta,
                        &members,
                    )?;
                }
            }
        }
    }
    Ok((records, heads))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::parse_wire_json_js_bounded;

    #[test]
    fn pinned_typescript_delta_auth_reference_and_head_cases() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/structure-delta-vectors.json"),
            64,
            1_000_000,
        )
        .unwrap();
        for case in array(&cases).unwrap() {
            let name = text(field(case, "name").unwrap()).unwrap();
            let expected = field(case, "ok").unwrap() == &WireValue::Bool(true);
            let records = array(field(case, "records").unwrap()).unwrap();
            let heads = array(field(case, "heads").unwrap()).unwrap();
            let contract = field(case, "contract").unwrap();
            let result = if case.get("kind").and_then(WireValue::as_string).as_deref()
                == Some("snapshot_graph")
            {
                validate_snapshot_graph(contract, records, heads).map(|_| (vec![], vec![]))
            } else {
                apply_delta(
                    records,
                    heads,
                    contract,
                    array(field(case, "priorRecords").unwrap()).unwrap(),
                    array(field(case, "priorHeads").unwrap()).unwrap(),
                    field(case, "context").unwrap(),
                    field(case, "policy").unwrap(),
                )
            };
            assert_eq!(result.is_ok(), expected, "{name}: {result:?}");
        }
    }

    #[test]
    fn completed_snapshot_can_contain_more_than_one_page() {
        let cases = parse_wire_json_js_bounded(
            include_bytes!("../../../conformance/structure-delta-vectors.json"),
            64,
            1_000_000,
        )
        .unwrap();
        let case = array(&cases)
            .unwrap()
            .iter()
            .find(|case| {
                case.get("name").and_then(WireValue::as_string).as_deref() == Some("append_head")
            })
            .unwrap();
        let template = array(field(case, "records").unwrap())
            .unwrap()
            .first()
            .unwrap();
        let template = canonical_wire_value(template, Path::SecureArtifact).unwrap();
        let records = (0..129)
            .map(|index| {
                let text = template.replace(&"r".repeat(43), &format!("{index:043}"));
                parse_wire_json_js_bounded(text.as_bytes(), 32, 4096).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(validate_snapshot_graph(field(case, "contract").unwrap(), &records, &[]).is_ok());
        assert!(validate_projection_page(&records, &[], field(case, "contract").unwrap()).is_err());
    }
}
