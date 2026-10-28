'use strict';
// SPDX-License-Identifier: Apache-2.0

class ProtocolSessionError extends Error {
  constructor(code) { super(code); this.name = 'ProtocolSessionError'; this.code = code; }
}
const fail = code => { throw new ProtocolSessionError(code); };
const token = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const accepted = out => ['ACCEPTED', 'COMPLETED'].includes(out?.state);
const origin = value => {
  try { const u = new URL(value); if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.search || u.hash) fail('PROTOCOL_BINDING_INVALID'); return u.href.replace(/\/$/, ''); }
  catch { return fail('PROTOCOL_BINDING_INVALID'); }
};

/** The native kernel verifies transport/evidence. This facade only pins selection
 * and marshals declared actions; it never evaluates rules or drives an Agent. */
function createProtocolSession(kernel, selection, {snapshot, protocols}) {
  const binding = snapshot(selection), keys = ['expected_origin', 'expected_actor', 'workspace_id', 'instance_id', 'protocol_digest', 'package_digest', 'role'];
  if (!binding || typeof binding !== "object" || Array.isArray(binding) || Object.keys(binding).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(binding, k)) ||
      !['expected_actor', 'workspace_id', 'instance_id', 'role'].every(k => token(binding[k])) ||
      !digest(binding.protocol_digest) || !digest(binding.package_digest)) fail('PROTOCOL_BINDING_INVALID');
  if (kernel.actor_id !== binding.expected_actor || origin(kernel.origin) !== origin(binding.expected_origin)) fail('PROTOCOL_BINDING_MISMATCH');
  Object.freeze(binding);
  const scope = {workspace_id: binding.workspace_id, instance_id: binding.instance_id, protocol_digest: binding.protocol_digest};
  let tools = null;
  const assertActor = () => {
    if (kernel.actor_id !== binding.expected_actor || origin(kernel.origin) !== origin(binding.expected_origin)) fail('PROTOCOL_BINDING_MISMATCH');
  };
  const read = async (action, body, options) => {
    assertActor();
    const out = await kernel.executeStructureIntent({action, ...scope, body}, options);
    if (accepted(out)) {
      const r = out.result;
      if (r.workspace_id !== scope.workspace_id || r.instance_id !== scope.instance_id || r.protocol_digest !== scope.protocol_digest) fail('PROTOCOL_BINDING_MISMATCH');
    }
    return out;
  };
  const page = (options = {}, events = false) => {
    const q = snapshot(options), allowed = events ? ['limit', 'cursor', 'after_sequence'] : ['limit', 'cursor', 'schema', 'consistency'];
    if (Object.keys(q).some(k => !allowed.includes(k))) fail('PROTOCOL_PAGE_INVALID');
    if (!Number.isSafeInteger(q.limit ?? 16) || (q.limit ?? 16) < 1 || (q.limit ?? 16) > 32) fail('PROTOCOL_PAGE_INVALID');
    if (q.cursor !== undefined && (typeof q.cursor !== 'string' || !q.cursor || q.cursor.length > 16384)) fail('PROTOCOL_PAGE_INVALID');
    if (q.after_sequence !== undefined && (!Number.isSafeInteger(q.after_sequence) || q.after_sequence < 0 || q.cursor !== undefined)) fail('PROTOCOL_PAGE_INVALID');
    return {...q, limit: q.limit ?? 16};
  };
  const prepareAction = request => {
    assertActor();
    if (tools === null) fail('PROTOCOL_CONTEXT_REQUIRED');
    const r = snapshot(request);
    if (Object.keys(r).some(k => !['tool', 'action_id', 'values', 'expected_revision', 'operation_id', 'plaintext_contents'].includes(k)) ||
        Boolean(r.tool) === Boolean(r.action_id) || !Number.isSafeInteger(r.expected_revision) || r.expected_revision < 1 ||
        typeof r.operation_id !== 'string' || !r.operation_id || r.operation_id.length > 128 ||
        !r.values || typeof r.values !== 'object' || Array.isArray(r.values)) fail('PROTOCOL_ACTION_INVALID');
    const tool = tools.find(t => r.tool ? t.name === r.tool : t.action === r.action_id);
    if (!tool) fail('PROTOCOL_ACTION_NOT_GRANTED');
    const refs = [];
    for (const [name, field] of Object.entries(tool.input_schema?.fields ?? {})) {
      if (field.type !== 'exact_ref' || r.values[name] === undefined) continue;
      const value = r.values[name];
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'record_id,revision' ||
          !token(value.record_id) || !Number.isSafeInteger(value.revision) || value.revision < 1) fail('PROTOCOL_REFERENCE_INVALID');
      if (!refs.some(v => v.record_id === value.record_id && v.revision === value.revision)) refs.push(value);
    }
    return snapshot({format: 'peerwork.protocol-action.v1', binding, intent: {
      action: 'structure.action', ...scope, expected_instance_revision: r.expected_revision,
      idempotency_key: r.operation_id, exact_input_refs: refs, body: {action_id: tool.action, structure: r.values},
      ...(r.plaintext_contents === undefined ? {} : {plaintext_contents: r.plaintext_contents}),
    }});
  };
  const submit = async (prepared, options = {}) => {
    assertActor();
    const p = snapshot(prepared), i = p.intent;
    if (p.format !== 'peerwork.protocol-action.v1' || Object.keys(p).sort().join(',') !== 'binding,format,intent' ||
        !p.binding || keys.some(k => p.binding[k] !== binding[k]) || Object.keys(p.binding).length !== keys.length ||
        !i || i.action !== 'structure.action' || Object.keys(scope).some(k => i[k] !== scope[k]) ||
        typeof i.idempotency_key !== 'string' || !i.idempotency_key || i.idempotency_key.length > 128 ||
        !Number.isSafeInteger(i.expected_instance_revision) || i.expected_instance_revision < 1 ||
        Object.keys(i).some(k => !['action', ...Object.keys(scope), 'expected_instance_revision', 'idempotency_key', 'exact_input_refs', 'body', 'plaintext_contents'].includes(k))) fail('PROTOCOL_BINDING_MISMATCH');
    const out = await kernel.executeStructureIntent(i, options);
    if (accepted(out) && (out.result.workspace_id !== scope.workspace_id || out.result.instance_id !== scope.instance_id || out.result.protocol_digest !== scope.protocol_digest)) fail('PROTOCOL_BINDING_MISMATCH');
    return out;
  };
  return Object.freeze({
    get binding() { return snapshot(binding); },
    describe: async (options = {}) => {
      assertActor(); tools = null;
      const outcome = await protocols(kernel).role({...scope, role: binding.role}, options);
      if (!accepted(outcome)) return {outcome, context: null};
      const v = outcome.result.structure;
      if (v?.workspace_id !== scope.workspace_id || v.protocol_digest !== scope.protocol_digest || v.package_digest !== binding.package_digest ||
          v.runtime?.actor_id !== binding.expected_actor || v.runtime?.role !== binding.role ||
          v.evidence?.binding?.instance_id !== scope.instance_id) fail('PROTOCOL_BINDING_MISMATCH');
      const resource = v.resources?.[v.runtime.instructions_resource];
      if (typeof resource?.content !== 'string' || !Array.isArray(v.runtime.tools)) fail('PROTOCOL_CONTEXT_INVALID');
      tools = snapshot(v.runtime.tools);
      return {outcome, context: snapshot({binding, instructions: resource.content, tools, context_sources: v.runtime.context, assurance: 'BACKEND_CURRENT_STATE'})};
    },
    state: (options = {}) => read('structure.instance.get', {}, options),
    records: (selection = {}, options = {}) => read('structure.records.read', page(selection), options),
    updates: (selection = {}, options = {}) => read('structure.events.read', page(selection, true), options),
    record: (reference, options = {}) => {
      const r = snapshot(reference);
      if (!token(r.record_id) || !Number.isSafeInteger(r.revision) || r.revision < 1 || Object.keys(r).sort().join(',') !== 'record_id,revision') fail('PROTOCOL_REFERENCE_INVALID');
      return read('structure.record.get', r, options);
    },
    prepareAction,
    submit,
    resume: submit,
    action: (request, options = {}) => submit(prepareAction(request), options),
  });
}
module.exports = {createProtocolSession, ProtocolSessionError};
