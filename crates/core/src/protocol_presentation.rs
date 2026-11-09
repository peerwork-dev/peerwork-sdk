//! Bounded, optional display bindings in an authored protocol resource.
//! This describes existing readable fields and actions; it grants no authority.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const RESOURCE_PATH: &str = "peerwork/presentation.json";
pub const FORMAT: &str = "peerwork.protocol-presentation.v1";
#[derive(Debug, thiserror::Error)]
#[error("PROTOCOL_PRESENTATION_INVALID")]
pub struct PresentationError;
type Result<T> = std::result::Result<T, PresentationError>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub format: String,
    pub default_view: String,
    pub views: Vec<View>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub id: String,
    pub title: String,
    pub schema: String,
    pub layout: String,
    pub fields: Vec<Field>,
    pub actions: Vec<Action>,
    #[serde(default, deserialize_with = "optional_text", skip_serializing_if = "Option::is_none")]
    pub title_field: Option<String>,
    #[serde(default, deserialize_with = "optional_text", skip_serializing_if = "Option::is_none")]
    pub group_field: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub field: String,
    pub label: String,
    pub format: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub action_id: String,
    pub label: String,
}
fn optional_text<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn text(value: &str, max: usize) -> bool {
    let visible = value.chars().any(|c| !matches!(c,
        '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' |
        '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' |
        '\u{205f}' | '\u{3000}' | '\u{feff}'));
    visible && value.encode_utf16().count() <= max
        && !value.chars().any(|c| c <= '\u{1f}')
}
fn safe(value: &str) -> bool {
    !matches!(value, "__proto__" | "prototype" | "constructor" | "sealed_content" | "$content")
}
fn field_kind<'a>(schema: &'a Value, field: &str) -> Result<&'a str> {
    if !text(field, 80) || !safe(field)
        || schema["protection"]["fields"][field]["protection"] == "e2ee" {
        return Err(PresentationError);
    }
    schema["fields"].get(field).and_then(Value::as_str).ok_or(PresentationError)
}
fn compatible(kind: &str, format: &str) -> bool {
    match format {
        "TEXT" | "JSON" => true,
        "NUMBER" => kind == "integer",
        "BOOLEAN" => kind == "boolean",
        "TIME" => matches!(kind, "integer" | "string" | "source_timestamp"),
        "ACTOR" => kind == "string",
        "REFERENCE" => kind == "json",
        _ => false,
    }
}
pub fn parse_resource(content: &str, manifest: &Value) -> Result<Presentation> {
    if content.len() > 8192 { return Err(PresentationError); }
    let parsed: Presentation = serde_json::from_str(content).map_err(|_| PresentationError)?;
    if parsed.format != FORMAT || !text(&parsed.default_view, 80)
        || parsed.views.is_empty() || parsed.views.len() > 16 {
        return Err(PresentationError);
    }
    let mut views = BTreeSet::new();
    for view in &parsed.views {
        let valid_id = text(&view.id, 80) && safe(&view.id)
            && view.id.as_bytes()[0].is_ascii_alphabetic()
            && view.id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !valid_id || !views.insert(&view.id) || !text(&view.title, 120)
            || !text(&view.schema, 80) || view.fields.len() > 16 || view.actions.len() > 16
            || !matches!(view.layout.as_str(), "LIST" | "TABLE" | "TIMELINE" | "BOARD") {
            return Err(PresentationError);
        }
        let schema = manifest["record_schemas"].get(&view.schema).ok_or(PresentationError)?;
        let mut fields = BTreeSet::new();
        for field in &view.fields {
            if !fields.insert(&field.field) || !text(&field.label, 120)
                || !compatible(field_kind(schema, &field.field)?, &field.format) {
                return Err(PresentationError);
            }
        }
        let mut actions = BTreeSet::new();
        for action in &view.actions {
            if !text(&action.action_id, 120) || !text(&action.label, 120)
                || !actions.insert(&action.action_id)
                || !manifest["actions"].as_array().is_some_and(|items|
                    items.iter().any(|item| item["id"].as_str() == Some(&action.action_id))) {
                return Err(PresentationError);
            }
        }
        if let Some(field) = &view.title_field {
            if !matches!(field_kind(schema, field)?, "string" | "integer" | "source_text") {
                return Err(PresentationError);
            }
        }
        if let Some(field) = &view.group_field {
            if !matches!(field_kind(schema, field)?, "string" | "integer" | "boolean") {
                return Err(PresentationError);
            }
        }
        if view.layout == "BOARD" && view.group_field.is_none() { return Err(PresentationError); }
    }
    if !views.contains(&parsed.default_view) { return Err(PresentationError); }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn declaration() -> Value {
        json!({"format":FORMAT,"default_view":"claims","views":[{
            "id":"claims","title":"Claims","schema":"claim","layout":"BOARD",
            "fields":[{"field":"status","label":"State","format":"TEXT"}],
            "actions":[{"action_id":"claim","label":"Claim work"}],
            "title_field":"status","group_field":"status"
        }]})
    }
    #[test]
    fn authored_resource_is_optional_and_changes_only_the_package_identity() {
        let f: Value = serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
        let original = crate::protocol_bundle::inspect(&f["bundle"]).unwrap();
        let mut bundle = f["bundle"].clone();
        let resource = declaration();
        parse_resource(&resource.to_string(), &bundle["manifest"]).unwrap();
        bundle["resources"][RESOURCE_PATH] = json!({"media_type":"application/json","text":resource.to_string()});
        let presented = crate::protocol_bundle::inspect(&bundle).unwrap();
        assert_eq!(presented["protocol_digest"], original["protocol_digest"]);
        assert_ne!(presented["package_digest"], original["package_digest"]);
        bundle["resources"][RESOURCE_PATH]["media_type"] = json!("text/plain");
        assert!(crate::protocol_bundle::inspect(&bundle).is_err());
    }
    #[test]
    fn declarations_cannot_select_undeclared_actions_private_fields_or_executable_behavior() {
        let f: Value = serde_json::from_str(include_str!("../../../tests/fixtures/protocol-role-bundle-v1.json")).unwrap();
        let manifest = &f["bundle"]["manifest"];
        for (path, value) in [
            (vec!["script"], json!("fetch('https://example.invalid')")),
            (vec!["views", "0", "schema"], json!("missing")),
            (vec!["views", "0", "title_field"], Value::Null),
            (vec!["views", "0", "fields", "0", "format"], json!("NUMBER")),
            (vec!["views", "0", "actions", "0", "action_id"], json!("missing")),
        ] {
            let mut changed = declaration();
            let mut current = &mut changed;
            for part in &path[..path.len()-1] {
                current = if let Ok(index) = part.parse::<usize>() { &mut current[index] } else { &mut current[*part] };
            }
            current[*path.last().unwrap()] = value;
            assert!(parse_resource(&changed.to_string(), manifest).is_err());
        }
        let mut private = manifest.clone();
        private["record_schemas"]["claim"]["protection"] = json!({"v":1,"fields":{"status":{"protection":"e2ee","type":"string"}}});
        assert!(parse_resource(&declaration().to_string(), &private).is_err());
        let duplicate = format!("{{\"format\":\"wrong\",{}", &declaration().to_string()[1..]);
        assert!(parse_resource(&duplicate, manifest).is_err());
    }
    #[test]
    fn display_labels_match_javascript_utf16_and_whitespace_bounds() {
        // Frozen Unicode compatibility data; all authored labels remain English.
        assert!(!text("\u{feff}", 120));
        assert!(text("\u{0085}", 120));
        assert!(text(&"\u{1f642}".repeat(60), 120));
        assert!(!text(&"\u{1f642}".repeat(61), 120));
    }
}
