//! Lossless UTF-16 protocol interpreter port. This module remains private until
//! manifest validation and full secure-operation replay are complete.

use crate::{
    canonical::Path,
    wire_json::{canonical_wire_value, WireValue},
};
use std::collections::HashSet;
use thiserror::Error;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvalError {
    #[error("INVALID_PAYLOAD")]
    InvalidPayload,
    #[error("FORBIDDEN")]
    Forbidden,
    #[error("CONSTRAINT_FAILED")]
    ConstraintFailed,
    #[error("RESOURCE_EXHAUSTED")]
    ResourceExhausted,
}

#[derive(Debug, Clone)]
pub(crate) struct InterpreterAuth {
    pub actor_id: String,
    pub workspace_roles: Vec<Vec<u16>>,
    pub protocol_roles: Vec<Vec<u16>>,
    pub capabilities: Vec<Vec<u16>>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedInput {
    pub record_id: String,
    pub revision: u64,
    pub schema: Vec<u16>,
    pub payload: WireValue,
    pub scope: String,
    pub entity_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EvalResult {
    pub next_state: WireValue,
    pub records: Vec<WireValue>,
    pub head_selections: Vec<WireValue>,
    pub control_revision: bool,
    pub content_entities: Vec<Vec<u16>>,
    pub evaluated_at: Option<u64>,
}

fn shape(value: &WireValue, required: &[&str], optional: &[&str]) -> Result<(), EvalError> {
    let WireValue::Object(fields) = value else {
        return Err(EvalError::InvalidPayload);
    };
    if required.iter().any(|key| value.get(key).is_none()) {
        return Err(EvalError::InvalidPayload);
    }
    for (key, _) in fields {
        if !required
            .iter()
            .chain(optional)
            .any(|allowed| key.iter().copied().eq(allowed.encode_utf16()))
        {
            return Err(EvalError::InvalidPayload);
        }
    }
    Ok(())
}

fn validate_manifest(manifest: &WireValue) -> Result<(), EvalError> {
    walk_manifest(manifest, 0, &mut 0)?;
    shape(manifest, &["actions"], &[])?;
    let actions = array(field(manifest, "actions")?)?;
    if actions.len() >= 64 {
        return Err(EvalError::InvalidPayload);
    }
    let mut ids = HashSet::new();
    for action in actions {
        shape(
            action,
            &["id", "reads", "writes", "revisionEffects", "variants"],
            &["inputs"],
        )?;
        let id = units(field(action, "id")?)?;
        if id.is_empty() || id.len() > 120 || !ids.insert(id.to_vec()) {
            return Err(EvalError::InvalidPayload);
        }
        let reads = paths(field(action, "reads")?)?;
        let writes = paths(field(action, "writes")?)?;
        if reads.len() > 64 || writes.len() > 64 || writes.iter().any(Vec::is_empty) {
            return Err(EvalError::InvalidPayload);
        }
        let revision = field(action, "revisionEffects")?;
        shape(revision, &["control", "contentEntities"], &[])?;
        let control = boolean(field(revision, "control")?)?;
        let content = segments(field(revision, "contentEntities")?, 8)?;
        if !unique(&content) {
            return Err(EvalError::InvalidPayload);
        }
        if let Some(inputs) = action.get("inputs") {
            validate_input_contract(inputs)?;
        }
        let variants = array(field(action, "variants")?)?;
        if variants.is_empty() || variants.len() > 32 {
            return Err(EvalError::InvalidPayload);
        }
        for variant in variants {
            shape(variant, &["when", "effects"], &[])?;
            let when = array(field(variant, "when")?)?;
            let effects = array(field(variant, "effects")?)?;
            if when.len() > 32 || effects.len() > 16 {
                return Err(EvalError::InvalidPayload);
            }
            for guard in when {
                validate_guard(guard, 0, &reads)?;
            }
            let mut record_slots = Vec::new();
            let mut entity_slots = Vec::new();
            for effect in effects {
                if ascii(field(effect, "op")?)? == "append" {
                    if let Some(slot) = effect.get("recordSlot") {
                        record_slots.push(segment_value(slot)?);
                    }
                    if let Some(slot) = effect.get("entitySlot") {
                        entity_slots.push(segment_value(slot)?);
                    }
                    if let Some(entity) = effect.get("entity") {
                        entity_slots.push(segment_value(field(entity, "slot")?)?);
                    }
                }
            }
            if !unique(&record_slots)
                || !unique(&entity_slots)
                || entity_slots.iter().any(|slot| !content.contains(slot))
            {
                return Err(EvalError::InvalidPayload);
            }
            for effect in effects {
                validate_effect(effect, &reads, &writes, &record_slots, &entity_slots)?;
            }
            if !control
                && content.is_empty()
                && effects.iter().any(|effect| {
                    matches!(
                        ascii(field(effect, "op").unwrap_or(&WireValue::Null)).as_deref(),
                        Ok("set" | "select_head")
                    ) || effect.get("entity").is_some()
                })
            {
                return Err(EvalError::InvalidPayload);
            }
        }
    }
    Ok(())
}

fn walk_manifest(value: &WireValue, depth: usize, nodes: &mut usize) -> Result<(), EvalError> {
    *nodes += 1;
    if *nodes > 2048 || depth > 32 {
        return Err(EvalError::InvalidPayload);
    }
    match value {
        WireValue::Array(items) => {
            for item in items {
                walk_manifest(item, depth + 1, nodes)?;
            }
        }
        WireValue::Object(fields) => {
            for (key, item) in fields {
                if ["__proto__", "prototype", "constructor"]
                    .iter()
                    .any(|bad| key.iter().copied().eq(bad.encode_utf16()))
                {
                    return Err(EvalError::InvalidPayload);
                }
                walk_manifest(item, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unique(items: &[Vec<u16>]) -> bool {
    let mut seen = HashSet::new();
    items.iter().all(|item| seen.insert(item))
}
fn segment_value(value: &WireValue) -> Result<Vec<u16>, EvalError> {
    let text = units(value)?;
    if !segment(text) {
        return Err(EvalError::InvalidPayload);
    }
    Ok(text.to_vec())
}
fn segments(value: &WireValue, max: usize) -> Result<Vec<Vec<u16>>, EvalError> {
    let values = array(value)?;
    if values.len() > max {
        return Err(EvalError::InvalidPayload);
    }
    values.iter().map(segment_value).collect()
}

fn validate_selector(
    selector: &WireValue,
    depth: usize,
    reads: &[Vec<Vec<u16>>],
    produced: bool,
    record_slots: &[Vec<u16>],
    entity_slots: &[Vec<u16>],
) -> Result<(), EvalError> {
    if depth > 32 {
        return Err(EvalError::InvalidPayload);
    }
    match ascii(field(selector, "from")?)?.as_str() {
        "literal" => {
            shape(selector, &["from", "value"], &[])?;
            safe_value(field(selector, "value")?, 0, &mut 0)?;
        }
        "body" | "state" => {
            shape(selector, &["from", "path"], &[])?;
            path(field(selector, "path")?)?;
        }
        "time" => shape(selector, &["from"], &[])?,
        "time_add" => {
            shape(selector, &["from", "timestamp", "milliseconds"], &[])?;
            for key in ["timestamp", "milliseconds"] {
                validate_selector(
                    field(selector, key)?,
                    depth + 1,
                    reads,
                    produced,
                    record_slots,
                    entity_slots,
                )?;
            }
        }
        "auth" => {
            shape(selector, &["from", "field"], &[])?;
            if !matches!(
                ascii(field(selector, "field")?)?.as_str(),
                "actorId" | "workspaceRoles" | "protocolRoles" | "capabilities"
            ) {
                return Err(EvalError::InvalidPayload);
            }
        }
        "ref" => validate_ref_selector(selector)?,
        "resolved_entity" => {
            shape(selector, &["from", "ref"], &[])?;
            validate_ref_selector(field(selector, "ref")?)?;
        }
        "resolved_payload" => {
            shape(selector, &["from", "ref", "path"], &[])?;
            validate_ref_selector(field(selector, "ref")?)?;
            path(field(selector, "path")?)?;
        }
        "produced_ref" | "produced_entity" => {
            shape(selector, &["from", "slot"], &[])?;
            let slot = segment_value(field(selector, "slot")?)?;
            let slots = if ascii(field(selector, "from")?)? == "produced_ref" {
                record_slots
            } else {
                entity_slots
            };
            if !produced || !slots.contains(&slot) {
                return Err(EvalError::InvalidPayload);
            }
        }
        "object" => {
            shape(selector, &["from", "fields"], &[])?;
            let WireValue::Object(fields) = field(selector, "fields")? else {
                return Err(EvalError::InvalidPayload);
            };
            for (name, value) in fields {
                if !segment(name) {
                    return Err(EvalError::InvalidPayload);
                }
                validate_selector(
                    value,
                    depth + 1,
                    reads,
                    produced,
                    record_slots,
                    entity_slots,
                )?;
            }
        }
        "array" => {
            shape(selector, &["from", "items"], &[])?;
            let items = array(field(selector, "items")?)?;
            if items.len() > 128 {
                return Err(EvalError::InvalidPayload);
            }
            for item in items {
                validate_selector(item, depth + 1, reads, produced, record_slots, entity_slots)?;
            }
        }
        _ => return Err(EvalError::InvalidPayload),
    }
    let _ = reads;
    Ok(())
}

fn validate_ref_selector(value: &WireValue) -> Result<(), EvalError> {
    shape(value, &["from", "source", "path", "scope"], &["schema"])?;
    if ascii(field(value, "from")?)? != "ref"
        || !matches!(ascii(field(value, "source")?)?.as_str(), "body" | "state")
        || !matches!(
            ascii(field(value, "scope")?)?.as_str(),
            "INSTANCE" | "WORKSPACE"
        )
    {
        return Err(EvalError::InvalidPayload);
    }
    path(field(value, "path")?)?;
    if let Some(schema) = value.get("schema") {
        segment_value(schema)?;
    }
    Ok(())
}

fn validate_guard(
    guard: &WireValue,
    depth: usize,
    reads: &[Vec<Vec<u16>>],
) -> Result<(), EvalError> {
    if depth > 32 {
        return Err(EvalError::InvalidPayload);
    }
    let select = |key| validate_selector(field(guard, key)?, depth + 1, reads, false, &[], &[]);
    match ascii(field(guard, "op")?)?.as_str() {
        "eq" | "lt" | "lte" | "gt" | "gte" => {
            shape(guard, &["op", "left", "right"], &[])?;
            select("left")?;
            select("right")?;
        }
        "in" => {
            shape(guard, &["op", "value", "set"], &[])?;
            select("value")?;
            let set = array(field(guard, "set")?)?;
            if set.len() > 128 {
                return Err(EvalError::InvalidPayload);
            }
            for item in set {
                validate_selector(item, depth + 1, reads, false, &[], &[])?;
            }
        }
        "has_role" | "has_protocol_role" => {
            shape(guard, &["op", "role"], &[])?;
            segment_value(field(guard, "role")?)?;
        }
        "has_capability" => {
            shape(guard, &["op", "capability"], &[])?;
            let value = units(field(guard, "capability")?)?;
            if value.is_empty() || value.len() > 120 {
                return Err(EvalError::InvalidPayload);
            }
        }
        "exact_ref" => {
            shape(guard, &["op", "ref"], &[])?;
            validate_ref_selector(field(guard, "ref")?)?;
        }
        "exact_ref_list" => {
            shape(
                guard,
                &["op", "source", "path", "scope", "max"],
                &["schema"],
            )?;
            if !matches!(ascii(field(guard, "source")?)?.as_str(), "body" | "state")
                || !matches!(
                    ascii(field(guard, "scope")?)?.as_str(),
                    "INSTANCE" | "WORKSPACE" | "INSTANCE_OR_WORKSPACE"
                )
            {
                return Err(EvalError::InvalidPayload);
            }
            path(field(guard, "path")?)?;
            let max = number(field(guard, "max")?)?;
            if !(1.0..=32.0).contains(&max) {
                return Err(EvalError::InvalidPayload);
            }
            if let Some(schema) = guard.get("schema") {
                segment_value(schema)?;
            }
        }
        "and" | "or" => {
            shape(guard, &["op", "rules"], &[])?;
            let rules = array(field(guard, "rules")?)?;
            if rules.is_empty() || rules.len() > 32 {
                return Err(EvalError::InvalidPayload);
            }
            for rule in rules {
                validate_guard(rule, depth + 1, reads)?;
            }
        }
        "not" => {
            shape(guard, &["op", "rule"], &[])?;
            validate_guard(field(guard, "rule")?, depth + 1, reads)?;
        }
        _ => return Err(EvalError::InvalidPayload),
    }
    Ok(())
}

fn validate_effect(
    effect: &WireValue,
    reads: &[Vec<Vec<u16>>],
    writes: &[Vec<Vec<u16>>],
    record_slots: &[Vec<u16>],
    entity_slots: &[Vec<u16>],
) -> Result<(), EvalError> {
    let select = |value| validate_selector(value, 0, reads, true, record_slots, entity_slots);
    match ascii(field(effect, "op")?)?.as_str() {
        "set" => {
            shape(effect, &["op", "path", "value"], &[])?;
            let target = path(field(effect, "path")?)?;
            if target.is_empty() || !owns(writes, &target) {
                return Err(EvalError::InvalidPayload);
            }
            select(field(effect, "value")?)?;
        }
        "select_head" => {
            shape(effect, &["op", "expected", "target"], &[])?;
            for key in ["expected", "target"] {
                validate_ref_selector(field(effect, key)?)?;
            }
        }
        "append" => {
            shape(
                effect,
                &["op", "schema", "value"],
                &[
                    "recordSlot",
                    "entitySlot",
                    "entity",
                    "selectHead",
                    "relations",
                ],
            )?;
            segment_value(field(effect, "schema")?)?;
            if let Some(slot) = effect.get("recordSlot") {
                segment_value(slot)?;
            }
            if let Some(slot) = effect.get("entitySlot") {
                segment_value(slot)?;
            }
            if effect.get("entitySlot").is_some() && effect.get("entity").is_some() {
                return Err(EvalError::InvalidPayload);
            }
            if let Some(value) = effect.get("selectHead") {
                boolean(value)?;
            }
            if let Some(entity) = effect.get("entity") {
                match ascii(field(entity, "mode")?)?.as_str() {
                    "new" => shape(entity, &["mode", "slot"], &[])?,
                    "revise" => {
                        shape(entity, &["mode", "slot", "parent"], &[])?;
                        validate_ref_selector(field(entity, "parent")?)?;
                    }
                    _ => return Err(EvalError::InvalidPayload),
                }
                segment_value(field(entity, "slot")?)?;
            }
            select(field(effect, "value")?)?;
            if let Some(relations) = effect.get("relations") {
                let relations = array(relations)?;
                if relations.len() > 32 {
                    return Err(EvalError::InvalidPayload);
                }
                for relation in relations {
                    shape(relation, &["kind", "target"], &[])?;
                    segment_value(field(relation, "kind")?)?;
                    let target = field(relation, "target")?;
                    match ascii(field(target, "from")?)?.as_str() {
                        "ref" => validate_ref_selector(target)?,
                        "produced_ref" => select(target)?,
                        _ => return Err(EvalError::InvalidPayload),
                    }
                }
            }
        }
        _ => return Err(EvalError::InvalidPayload),
    }
    Ok(())
}

fn validate_input_contract(contract: &WireValue) -> Result<(), EvalError> {
    shape(
        contract,
        &["fields", "required", "additionalProperties"],
        &[],
    )?;
    let WireValue::Object(fields) = field(contract, "fields")? else {
        return Err(EvalError::InvalidPayload);
    };
    if fields.len() > 32 {
        return Err(EvalError::InvalidPayload);
    }
    let required = segments(field(contract, "required")?, 32)?;
    if !unique(&required)
        || required
            .iter()
            .any(|name| !fields.iter().any(|(key, _)| key == name))
    {
        return Err(EvalError::InvalidPayload);
    }
    boolean(field(contract, "additionalProperties")?)?;
    for (name, spec) in fields {
        if !segment(name) {
            return Err(EvalError::InvalidPayload);
        }
        match ascii(field(spec, "type")?)?.as_str() {
            "string" => {
                shape(spec, &["type"], &["maxBytes", "nullable"])?;
                if let Some(max) = spec.get("maxBytes") {
                    if !(1.0..=8192.0).contains(&number(max)?) {
                        return Err(EvalError::InvalidPayload);
                    }
                }
                if let Some(nullable) = spec.get("nullable") {
                    boolean(nullable)?;
                }
            }
            "integer" => {
                shape(spec, &["type"], &["minimum", "maximum", "nullable"])?;
                let min = spec.get("minimum").map(number).transpose()?;
                let max = spec.get("maximum").map(number).transpose()?;
                if min.zip(max).is_some_and(|(min, max)| min > max) {
                    return Err(EvalError::InvalidPayload);
                }
                if let Some(nullable) = spec.get("nullable") {
                    boolean(nullable)?;
                }
            }
            "boolean" => {
                shape(spec, &["type"], &["nullable"])?;
                if let Some(nullable) = spec.get("nullable") {
                    boolean(nullable)?;
                }
            }
            "enum" => {
                shape(spec, &["type", "values"], &["nullable"])?;
                let values = array(field(spec, "values")?)?;
                if values.is_empty() || values.len() > 64 {
                    return Err(EvalError::InvalidPayload);
                }
                for value in values {
                    let text = units(value)?;
                    if text.is_empty() || text.len() > 8192 {
                        return Err(EvalError::InvalidPayload);
                    }
                }
                if let Some(nullable) = spec.get("nullable") {
                    boolean(nullable)?;
                }
            }
            "actor_id" => shape(spec, &["type"], &[])?,
            "exact_ref" => {
                shape(spec, &["type", "schema", "scope"], &[])?;
                segment_value(field(spec, "schema")?)?;
                if !matches!(
                    ascii(field(spec, "scope")?)?.as_str(),
                    "INSTANCE" | "WORKSPACE"
                ) {
                    return Err(EvalError::InvalidPayload);
                }
            }
            _ => return Err(EvalError::InvalidPayload),
        }
    }
    Ok(())
}

fn validate_action_inputs(
    contract: Option<&WireValue>,
    body: &WireValue,
    exact: &[ResolvedInput],
) -> Result<(), EvalError> {
    let Some(contract) = contract else {
        return Ok(());
    };
    let WireValue::Object(values) = body else {
        return Err(EvalError::InvalidPayload);
    };
    let fields = field(contract, "fields")?;
    let required = segments(field(contract, "required")?, 32)?;
    if required
        .iter()
        .any(|name| !values.iter().any(|(key, _)| key == name))
    {
        return Err(EvalError::InvalidPayload);
    }
    let additional = boolean(field(contract, "additionalProperties")?)?;
    for (name, value) in values {
        let Some(spec) = ({
            let WireValue::Object(defs) = fields else {
                return Err(EvalError::InvalidPayload);
            };
            defs.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
        }) else {
            if additional {
                continue;
            } else {
                return Err(EvalError::InvalidPayload);
            }
        };
        if matches!(value, WireValue::Null)
            && spec.get("nullable").is_some_and(|v| boolean(v) == Ok(true))
        {
            continue;
        }
        match ascii(field(spec, "type")?)?.as_str() {
            "string" => {
                let text = units(value)?;
                let max = spec
                    .get("maxBytes")
                    .map(number)
                    .transpose()?
                    .unwrap_or(8192.0);
                if String::from_utf16_lossy(text).len() as f64 > max {
                    return Err(EvalError::InvalidPayload);
                }
            }
            "integer" => {
                let current = number(value)?;
                if spec
                    .get("minimum")
                    .is_some_and(|v| number(v).is_ok_and(|min| current < min))
                    || spec
                        .get("maximum")
                        .is_some_and(|v| number(v).is_ok_and(|max| current > max))
                {
                    return Err(EvalError::InvalidPayload);
                }
            }
            "boolean" => {
                boolean(value)?;
            }
            "enum" => {
                let current = units(value)?;
                if !array(field(spec, "values")?)?
                    .iter()
                    .any(|item| units(item).is_ok_and(|text| text == current))
                {
                    return Err(EvalError::InvalidPayload);
                }
            }
            "actor_id" => {
                if !token(&ascii(value)?) {
                    return Err(EvalError::InvalidPayload);
                }
            }
            "exact_ref" => {
                let (id, revision) = parse_ref(value)?;
                let scope = ascii(field(spec, "scope")?)?;
                let schema = units(field(spec, "schema")?)?;
                if !exact.iter().any(|item| {
                    item.record_id == id
                        && item.revision == revision
                        && item.scope == scope
                        && (schema == "*".encode_utf16().collect::<Vec<_>>()
                            || item.schema == schema)
                }) {
                    return Err(EvalError::InvalidPayload);
                }
            }
            _ => return Err(EvalError::InvalidPayload),
        }
    }
    Ok(())
}

pub(crate) fn evaluate_action(
    manifest: &WireValue,
    action_id: &[u16],
    state: &WireValue,
    body: &WireValue,
    auth: &InterpreterAuth,
    exact_inputs: &[ResolvedInput],
    execution_time_ms: Option<u64>,
) -> Result<EvalResult, EvalError> {
    validate_manifest(manifest)?;
    let actions = array(field(manifest, "actions")?)?;
    let action = actions
        .iter()
        .find(|action| {
            units(field(action, "id").unwrap_or(&WireValue::Null)).is_ok_and(|id| id == action_id)
        })
        .ok_or(EvalError::Forbidden)?;
    validate_auth(auth)?;
    let mut exact = HashSet::new();
    for input in exact_inputs {
        if !token(&input.record_id)
            || input.revision == 0
            || input.revision as f64 > MAX_SAFE
            || !segment(&input.schema)
            || !matches!(input.scope.as_str(), "INSTANCE" | "WORKSPACE")
            || input.entity_id.as_ref().is_some_and(|id| !token(id))
            || !exact.insert((input.record_id.clone(), input.revision))
        {
            return Err(EvalError::InvalidPayload);
        }
        safe_value(&input.payload, 0, &mut 0)?;
    }
    validate_action_inputs(action.get("inputs"), body, exact_inputs)?;
    let reads = paths(field(action, "reads")?)?;
    let writes = paths(field(action, "writes")?)?;
    let revision = field(action, "revisionEffects")?;
    let control_revision = boolean(field(revision, "control")?)?;
    let _declared_entities = array(field(revision, "contentEntities")?)?;
    let variants = array(field(action, "variants")?)?;
    let mut ctx = EvalContext {
        state,
        body,
        auth,
        exact_inputs,
        reads,
        execution_time_ms,
        used_time: false,
    };
    let mut matches = Vec::new();
    for variant in variants {
        let mut passed = true;
        for guard in array(field(variant, "when")?)? {
            if !eval_guard(guard, &mut ctx)? {
                passed = false;
                break;
            }
        }
        if passed {
            matches.push(variant);
        }
    }
    if matches.len() != 1 {
        return Err(EvalError::ConstraintFailed);
    }
    let mut next_state = safe_value(state, 0, &mut 0)?;
    let mut records = Vec::new();
    let mut heads = Vec::new();
    let mut content_entities = Vec::new();
    for effect in array(field(matches[0], "effects")?)? {
        match ascii(field(effect, "op")?)?.as_str() {
            "set" => {
                let path = path(field(effect, "path")?)?;
                if path.is_empty() || !owns(&writes, &path) {
                    return Err(EvalError::InvalidPayload);
                }
                let value = select(field(effect, "value")?, &mut ctx, true)?;
                put(&mut next_state, &path, value)?;
                next_state = safe_value(&next_state, 0, &mut 0)?;
            }
            "select_head" => {
                let expected = select(field(effect, "expected")?, &mut ctx, false)?;
                let target = select(field(effect, "target")?, &mut ctx, false)?;
                heads.push(object(vec![
                    ("expected", ref_output(&expected)?),
                    ("target", ref_output(&target)?),
                ]));
            }
            "append" => {
                let schema = units(field(effect, "schema")?)?.to_vec();
                let mut record = vec![("schema", WireValue::String(schema))];
                if let Some(slot) = effect.get("recordSlot") {
                    record.push(("recordSlot", slot.clone()));
                }
                if let Some(slot) = effect.get("entitySlot") {
                    content_entities.push(units(slot)?.to_vec());
                    record.push(("entitySlot", slot.clone()));
                }
                if let Some(entity) = effect.get("entity") {
                    content_entities.push(units(field(entity, "slot")?)?.to_vec());
                    let mode = ascii(field(entity, "mode")?)?;
                    let entity_output = if mode == "new" {
                        object(vec![
                            ("mode", string("new")),
                            ("slot", field(entity, "slot")?.clone()),
                        ])
                    } else if mode == "revise" {
                        let parent = select(field(entity, "parent")?, &mut ctx, false)?;
                        object(vec![
                            ("mode", string("revise")),
                            ("slot", field(entity, "slot")?.clone()),
                            ("parent", ref_output(&parent)?),
                        ])
                    } else {
                        return Err(EvalError::InvalidPayload);
                    };
                    record.push(("entity", entity_output));
                }
                let select_head = effect
                    .get("selectHead")
                    .map(boolean)
                    .transpose()?
                    .unwrap_or(false);
                if effect.get("entity").is_some() || select_head {
                    record.push(("selectHead", WireValue::Bool(select_head)));
                }
                let payload = select(field(effect, "value")?, &mut ctx, true)?;
                let payload = safe_value(&payload, 0, &mut 0)?;
                if canonical_wire_value(&payload, Path::KERNEL)
                    .map_err(|_| EvalError::InvalidPayload)?
                    .len()
                    > 16_384
                {
                    return Err(EvalError::ResourceExhausted);
                }
                record.push(("payload", payload));
                let mut relations = Vec::new();
                if let Some(items) = effect.get("relations") {
                    for relation in array(items)? {
                        let target = select(field(relation, "target")?, &mut ctx, true)?;
                        let target = if target.get("$produced").is_some() {
                            target
                        } else {
                            ref_output(&target)?
                        };
                        relations.push(object(vec![
                            ("kind", field(relation, "kind")?.clone()),
                            ("target", target),
                        ]));
                    }
                }
                record.push(("relations", WireValue::Array(relations)));
                records.push(object(record));
                if records.len() > 8 {
                    return Err(EvalError::ResourceExhausted);
                }
            }
            _ => return Err(EvalError::InvalidPayload),
        }
    }
    let evaluated_at = if ctx.used_time {
        Some(execution_time_ms.ok_or(EvalError::InvalidPayload)?)
    } else {
        None
    };
    Ok(EvalResult {
        next_state,
        records,
        head_selections: heads,
        control_revision,
        content_entities,
        evaluated_at,
    })
}

struct EvalContext<'a> {
    state: &'a WireValue,
    body: &'a WireValue,
    auth: &'a InterpreterAuth,
    exact_inputs: &'a [ResolvedInput],
    reads: Vec<Vec<Vec<u16>>>,
    execution_time_ms: Option<u64>,
    used_time: bool,
}

fn select(
    selector: &WireValue,
    ctx: &mut EvalContext<'_>,
    produced: bool,
) -> Result<WireValue, EvalError> {
    match ascii(field(selector, "from")?)?.as_str() {
        "literal" => safe_value(field(selector, "value")?, 0, &mut 0),
        "time" => {
            ctx.used_time = true;
            let value = ctx.execution_time_ms.ok_or(EvalError::InvalidPayload)?;
            if value as f64 > MAX_SAFE {
                return Err(EvalError::InvalidPayload);
            }
            Ok(WireValue::Number(value as f64))
        }
        "time_add" => {
            let timestamp = number(&select(field(selector, "timestamp")?, ctx, produced)?)?;
            let milliseconds = number(&select(field(selector, "milliseconds")?, ctx, produced)?)?;
            if timestamp < 0.0 || milliseconds < 0.0 || timestamp > MAX_SAFE - milliseconds {
                return Err(EvalError::InvalidPayload);
            }
            Ok(WireValue::Number(timestamp + milliseconds))
        }
        "auth" => match ascii(field(selector, "field")?)?.as_str() {
            "actorId" => Ok(string(&ctx.auth.actor_id)),
            "workspaceRoles" => Ok(strings(&ctx.auth.workspace_roles)),
            "protocolRoles" => Ok(strings(&ctx.auth.protocol_roles)),
            "capabilities" => Ok(strings(&ctx.auth.capabilities)),
            _ => Err(EvalError::InvalidPayload),
        },
        "body" | "state" => {
            let from = ascii(field(selector, "from")?)?;
            let path = path(field(selector, "path")?)?;
            if from == "state" && !owns(&ctx.reads, &path) {
                return Err(EvalError::InvalidPayload);
            }
            safe_value(
                at(if from == "state" { ctx.state } else { ctx.body }, &path)?,
                0,
                &mut 0,
            )
        }
        "object" => {
            let WireValue::Object(fields) = field(selector, "fields")? else {
                return Err(EvalError::InvalidPayload);
            };
            let mut out = Vec::new();
            for (key, value) in fields {
                out.push((key.clone(), select(value, ctx, produced)?));
            }
            safe_value(&WireValue::Object(out), 0, &mut 0)
        }
        "array" => {
            let mut out = Vec::new();
            for value in array(field(selector, "items")?)? {
                out.push(select(value, ctx, produced)?);
            }
            safe_value(&WireValue::Array(out), 0, &mut 0)
        }
        "produced_ref" | "produced_entity" => {
            if !produced {
                return Err(EvalError::InvalidPayload);
            }
            let kind = if ascii(field(selector, "from")?)? == "produced_ref" {
                "record"
            } else {
                "entity"
            };
            Ok(object(vec![
                ("$produced", string(kind)),
                ("slot", field(selector, "slot")?.clone()),
            ]))
        }
        "ref" | "resolved_entity" | "resolved_payload" => {
            let from = ascii(field(selector, "from")?)?;
            let reference = if from == "ref" {
                selector
            } else {
                field(selector, "ref")?
            };
            let source = ascii(field(reference, "source")?)?;
            let ref_path = path(field(reference, "path")?)?;
            if source == "state" && !owns(&ctx.reads, &ref_path) {
                return Err(EvalError::InvalidPayload);
            }
            let reference_value = at(
                if source == "state" {
                    ctx.state
                } else {
                    ctx.body
                },
                &ref_path,
            )?;
            let (record_id, revision) = parse_ref(reference_value)?;
            let input = ctx
                .exact_inputs
                .iter()
                .find(|item| item.record_id == record_id && item.revision == revision)
                .ok_or(EvalError::InvalidPayload)?;
            if input.scope != ascii(field(reference, "scope")?)?
                || reference
                    .get("schema")
                    .is_some_and(|schema| units(schema).map_or(true, |value| value != input.schema))
            {
                return Err(EvalError::InvalidPayload);
            }
            match from.as_str() {
                "ref" => Ok(reference_value.clone()),
                "resolved_entity" => Ok(string(
                    input.entity_id.as_ref().ok_or(EvalError::InvalidPayload)?,
                )),
                _ => safe_value(
                    at(&input.payload, &path(field(selector, "path")?)?)?,
                    0,
                    &mut 0,
                ),
            }
        }
        _ => Err(EvalError::InvalidPayload),
    }
}

fn eval_guard(guard: &WireValue, ctx: &mut EvalContext<'_>) -> Result<bool, EvalError> {
    match ascii(field(guard, "op")?)?.as_str() {
        "eq" => Ok(equal(
            &select(field(guard, "left")?, ctx, false)?,
            &select(field(guard, "right")?, ctx, false)?,
        )?),
        "in" => {
            let value = select(field(guard, "value")?, ctx, false)?;
            for item in array(field(guard, "set")?)? {
                if equal(&value, &select(item, ctx, false)?)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "lt" | "lte" | "gt" | "gte" => {
            let op = ascii(field(guard, "op")?)?;
            let left = number(&select(field(guard, "left")?, ctx, false)?)?;
            let right = number(&select(field(guard, "right")?, ctx, false)?)?;
            Ok(match op.as_str() {
                "lt" => left < right,
                "lte" => left <= right,
                "gt" => left > right,
                _ => left >= right,
            })
        }
        "has_role" => {
            let role = units(field(guard, "role")?)?;
            Ok(ctx
                .auth
                .workspace_roles
                .iter()
                .any(|item| item.as_slice() == role))
        }
        "has_protocol_role" => {
            let role = units(field(guard, "role")?)?;
            Ok(ctx
                .auth
                .protocol_roles
                .iter()
                .any(|item| item.as_slice() == role))
        }
        "has_capability" => {
            let capability = units(field(guard, "capability")?)?;
            Ok(ctx
                .auth
                .capabilities
                .iter()
                .any(|item| item.as_slice() == capability))
        }
        "exact_ref" => {
            select(field(guard, "ref")?, ctx, false)?;
            Ok(true)
        }
        "exact_ref_list" => {
            let source = ascii(field(guard, "source")?)?;
            let path = path(field(guard, "path")?)?;
            if source == "state" && !owns(&ctx.reads, &path) {
                return Err(EvalError::InvalidPayload);
            }
            let values = array(at(
                if source == "state" {
                    ctx.state
                } else {
                    ctx.body
                },
                &path,
            )?)?;
            let max = number(field(guard, "max")?)?;
            if values.len() as f64 > max {
                return Err(EvalError::InvalidPayload);
            }
            let scope = ascii(field(guard, "scope")?)?;
            for value in values {
                let (id, revision) = parse_ref(value)?;
                let input = ctx
                    .exact_inputs
                    .iter()
                    .find(|item| item.record_id == id && item.revision == revision)
                    .ok_or(EvalError::InvalidPayload)?;
                if !(scope == "INSTANCE_OR_WORKSPACE"
                    && matches!(input.scope.as_str(), "INSTANCE" | "WORKSPACE")
                    || input.scope == scope)
                    || guard.get("schema").is_some_and(|schema| {
                        units(schema).map_or(true, |value| value != input.schema)
                    })
                {
                    return Err(EvalError::InvalidPayload);
                }
            }
            Ok(true)
        }
        "and" => {
            for rule in array(field(guard, "rules")?)? {
                if !eval_guard(rule, ctx)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "or" => {
            for rule in array(field(guard, "rules")?)? {
                if eval_guard(rule, ctx)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "not" => Ok(!eval_guard(field(guard, "rule")?, ctx)?),
        _ => Err(EvalError::InvalidPayload),
    }
}

fn equal(left: &WireValue, right: &WireValue) -> Result<bool, EvalError> {
    let left = safe_value(left, 0, &mut 0)?;
    let right = safe_value(right, 0, &mut 0)?;
    Ok(
        canonical_wire_value(&left, Path::KERNEL).map_err(|_| EvalError::InvalidPayload)?
            == canonical_wire_value(&right, Path::KERNEL).map_err(|_| EvalError::InvalidPayload)?,
    )
}

fn safe_value(value: &WireValue, depth: usize, nodes: &mut usize) -> Result<WireValue, EvalError> {
    *nodes += 1;
    if *nodes > 2048 || depth > 12 {
        return Err(EvalError::InvalidPayload);
    }
    match value {
        WireValue::Null | WireValue::Bool(_) => Ok(value.clone()),
        WireValue::Number(_) => {
            number(value)?;
            Ok(value.clone())
        }
        WireValue::String(text) => {
            if String::from_utf16_lossy(text).len() > 8192 {
                return Err(EvalError::InvalidPayload);
            }
            Ok(value.clone())
        }
        WireValue::Array(items) => {
            if items.len() > 128 {
                return Err(EvalError::InvalidPayload);
            }
            Ok(WireValue::Array(
                items
                    .iter()
                    .map(|item| safe_value(item, depth + 1, nodes))
                    .collect::<Result<_, _>>()?,
            ))
        }
        WireValue::Object(fields) => {
            let mut out = Vec::with_capacity(fields.len());
            for (name, item) in fields {
                if !segment(name) {
                    return Err(EvalError::InvalidPayload);
                }
                out.push((name.clone(), safe_value(item, depth + 1, nodes)?));
            }
            Ok(WireValue::Object(out))
        }
    }
}

fn validate_auth(auth: &InterpreterAuth) -> Result<(), EvalError> {
    if !token(&auth.actor_id) {
        return Err(EvalError::InvalidPayload);
    }
    for values in [
        &auth.workspace_roles,
        &auth.protocol_roles,
        &auth.capabilities,
    ] {
        if values.len() > 64
            || values
                .iter()
                .any(|value| value.is_empty() || String::from_utf16_lossy(value).len() > 120)
        {
            return Err(EvalError::InvalidPayload);
        }
        let mut unique = HashSet::new();
        if !values.iter().all(|value| unique.insert(value)) {
            return Err(EvalError::InvalidPayload);
        }
    }
    Ok(())
}

fn parse_ref(value: &WireValue) -> Result<(String, u64), EvalError> {
    let WireValue::Object(fields) = value else {
        return Err(EvalError::InvalidPayload);
    };
    if fields.len() != 2 {
        return Err(EvalError::InvalidPayload);
    }
    let id = ascii(field(value, "record_id")?)?;
    let revision = number(field(value, "revision")?)?;
    if !token(&id) || revision <= 0.0 {
        return Err(EvalError::InvalidPayload);
    }
    Ok((id, revision as u64))
}

fn ref_output(value: &WireValue) -> Result<WireValue, EvalError> {
    let (record_id, revision) = parse_ref(value)?;
    Ok(object(vec![
        ("recordId", string(&record_id)),
        ("revision", WireValue::Number(revision as f64)),
    ]))
}

fn put(root: &mut WireValue, path: &[Vec<u16>], value: WireValue) -> Result<(), EvalError> {
    if path.len() == 1 {
        let WireValue::Object(fields) = root else {
            return Err(EvalError::InvalidPayload);
        };
        if let Some((_, existing)) = fields.iter_mut().find(|(name, _)| name == &path[0]) {
            *existing = value;
        } else {
            fields.push((path[0].clone(), value));
        }
        return Ok(());
    }
    let WireValue::Object(fields) = root else {
        return Err(EvalError::InvalidPayload);
    };
    let next = fields
        .iter_mut()
        .find(|(name, _)| name == &path[0])
        .map(|(_, value)| value)
        .ok_or(EvalError::InvalidPayload)?;
    put(next, &path[1..], value)
}

fn at<'a>(root: &'a WireValue, path: &[Vec<u16>]) -> Result<&'a WireValue, EvalError> {
    let mut current = root;
    for key in path {
        let WireValue::Object(fields) = current else {
            return Err(EvalError::InvalidPayload);
        };
        current = fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .ok_or(EvalError::InvalidPayload)?;
    }
    Ok(current)
}

fn owns(declared: &[Vec<Vec<u16>>], path: &[Vec<u16>]) -> bool {
    declared.iter().any(|candidate| {
        candidate.len() <= path.len() && candidate.iter().zip(path).all(|(a, b)| a == b)
    })
}

fn paths(value: &WireValue) -> Result<Vec<Vec<Vec<u16>>>, EvalError> {
    array(value)?.iter().map(path).collect()
}
fn path(value: &WireValue) -> Result<Vec<Vec<u16>>, EvalError> {
    let elements = array(value)?;
    if elements.len() > 12 {
        return Err(EvalError::InvalidPayload);
    }
    let mut out = Vec::with_capacity(elements.len());
    for element in elements {
        let value = units(element)?;
        if !segment(value) {
            return Err(EvalError::InvalidPayload);
        }
        out.push(value.to_vec())
    }
    Ok(out)
}
fn segment(value: &[u16]) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && !["__proto__", "prototype", "constructor"]
            .iter()
            .any(|bad| value.iter().copied().eq(bad.encode_utf16()))
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn number(value: &WireValue) -> Result<f64, EvalError> {
    let value = value.as_number().ok_or(EvalError::InvalidPayload)?;
    if !value.is_finite() || value.fract() != 0.0 || value.abs() > MAX_SAFE {
        return Err(EvalError::InvalidPayload);
    }
    Ok(value)
}
fn boolean(value: &WireValue) -> Result<bool, EvalError> {
    if let WireValue::Bool(value) = value {
        Ok(*value)
    } else {
        Err(EvalError::InvalidPayload)
    }
}
fn array(value: &WireValue) -> Result<&[WireValue], EvalError> {
    if let WireValue::Array(value) = value {
        Ok(value)
    } else {
        Err(EvalError::InvalidPayload)
    }
}
fn units(value: &WireValue) -> Result<&[u16], EvalError> {
    value.as_utf16().ok_or(EvalError::InvalidPayload)
}
fn ascii(value: &WireValue) -> Result<String, EvalError> {
    value
        .as_string()
        .filter(|value| value.is_ascii())
        .ok_or(EvalError::InvalidPayload)
}
fn field<'a>(value: &'a WireValue, name: &str) -> Result<&'a WireValue, EvalError> {
    value.get(name).ok_or(EvalError::InvalidPayload)
}
fn string(value: &str) -> WireValue {
    WireValue::String(value.encode_utf16().collect())
}
fn strings(values: &[Vec<u16>]) -> WireValue {
    WireValue::Array(values.iter().cloned().map(WireValue::String).collect())
}
fn object(fields: Vec<(&str, WireValue)>) -> WireValue {
    WireValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_json::parse_wire_json_js_bounded;

    fn canonical(value: &WireValue) -> String {
        canonical_wire_value(value, Path::KERNEL).unwrap()
    }
    fn text(value: &WireValue) -> String {
        value.as_string().unwrap()
    }
    fn list_strings(value: Option<&WireValue>) -> Vec<Vec<u16>> {
        value
            .map(|value| {
                array(value)
                    .unwrap()
                    .iter()
                    .map(|item| units(item).unwrap().to_vec())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[test]
    fn pinned_typescript_interpreter_vectors() {
        let cases = parse_wire_json_js_bounded(
            include_str!("../../../conformance/interpreter-vectors.json").as_bytes(),
            64,
            2_000_000,
        )
        .unwrap();
        for case in array(&cases).unwrap() {
            let name = text(field(case, "name").unwrap());
            let auth_value = case.get("auth");
            let actor = auth_value
                .and_then(|value| value.get("actorId"))
                .map(text)
                .unwrap_or_else(|| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
            let capabilities = list_strings(auth_value.and_then(|value| value.get("capabilities")));
            let workspace_roles =
                list_strings(auth_value.and_then(|value| value.get("workspaceRoles")));
            let protocol_roles =
                list_strings(auth_value.and_then(|value| value.get("protocolRoles")));
            let auth = InterpreterAuth {
                actor_id: actor,
                workspace_roles,
                protocol_roles,
                capabilities,
            };
            let exact = case
                .get("exactInputs")
                .map(|values| {
                    array(values)
                        .unwrap()
                        .iter()
                        .map(|value| ResolvedInput {
                            record_id: text(field(value, "recordId").unwrap()),
                            revision: number(field(value, "revision").unwrap()).unwrap() as u64,
                            schema: units(field(value, "schema").unwrap()).unwrap().to_vec(),
                            payload: field(value, "payload").unwrap().clone(),
                            scope: text(field(value, "scope").unwrap()),
                            entity_id: value.get("entityId").map(text),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let result = evaluate_action(
                field(case, "manifest").unwrap(),
                &"test.set".encode_utf16().collect::<Vec<_>>(),
                field(case, "state").unwrap(),
                field(case, "body").unwrap(),
                &auth,
                &exact,
                case.get("executionTimeMs")
                    .map(|value| number(value).unwrap() as u64),
            );
            if let Some(error) = case.get("error") {
                assert_eq!(result.unwrap_err().to_string(), text(error), "{name}");
            } else {
                let result = result.unwrap_or_else(|err| panic!("{name}: {err}"));
                let mut fields = vec![
                    ("nextState", result.next_state),
                    ("records", WireValue::Array(result.records)),
                    ("headSelections", WireValue::Array(result.head_selections)),
                    (
                        "revisionEffects",
                        object(vec![
                            ("control", WireValue::Bool(result.control_revision)),
                            ("contentEntities", strings(&result.content_entities)),
                        ]),
                    ),
                ];
                if let Some(time) = result.evaluated_at {
                    fields.push(("evaluatedAt", WireValue::Number(time as f64)));
                }
                assert_eq!(
                    canonical(&object(fields)),
                    canonical(field(case, "result").unwrap()),
                    "{name}"
                );
            }
        }
    }
}
