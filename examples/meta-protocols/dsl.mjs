// SPDX-License-Identifier: Apache-2.0
export const literal = (value) => ({ from: "literal", value });
export const body = (...path) => ({ from: "body", path });
export const state = (...path) => ({ from: "state", path });
export const actor = { from: "auth", field: "actorId" },
  time = { from: "time" };
export const object = (fields) => ({ from: "object", fields });
export const ref = (name, schema, scope = "INSTANCE") => ({
  from: "ref",
  source: "body",
  path: [name],
  schema,
  scope,
});
export const payload = (reference, ...path) => ({
  from: "resolved_payload",
  ref: reference,
  path,
});
export const eq = (left, right) => ({ op: "eq", left, right });
export const not = (rule) => ({ op: "not", rule });
export const set = (name, value) => ({ op: "set", path: [name], value });
export const produced = (slot) => ({ from: "produced_ref", slot });
export const permission = (role, capability) => [
  { op: "has_protocol_role", role },
  { op: "has_capability", capability },
];
export const schema = (fields) => ({
  type: "object",
  fields,
  required: Object.keys(fields),
  max_bytes: 4096,
});
export const exact = (schema, scope = "INSTANCE") => ({
  type: "exact_ref",
  schema,
  scope,
});
export function append(name, fields, { slot, entity, relations = [] } = {}) {
  return {
    op: "append",
    schema: name,
    value: object(fields),
    relations,
    ...(slot ? { recordSlot: slot } : {}),
    ...(entity ? { entity, selectHead: true } : {}),
  };
}
export function action(
  id,
  fields,
  guards,
  effects,
  { reads = [], writes = [], entities = [], variants } = {},
) {
  return {
    id,
    reads: reads.map((name) => [name]),
    writes: writes.map((name) => [name]),
    revisionEffects: { control: writes.length > 0, contentEntities: entities },
    inputs: {
      fields,
      required: Object.keys(fields),
      additionalProperties: false,
    },
    variants: variants ?? [{ when: guards, effects }],
  };
}
