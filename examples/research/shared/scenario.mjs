// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import {
  compileStructureProtocol,
  executeStructureAction,
} from "../vendor/backend-evaluator.mjs";
export const token = (label) =>
  createHash("sha256").update(label).digest("base64url");
/** Deterministic fixture adapter. NO receipts, encryption, transport or DB claims. */
export class Scenario {
  constructor(manifest, { now = 1000, seed = "scenario" } = {}) {
    this.protocol = compileStructureProtocol(manifest);
    this.manifest = manifest;
    this.state = structuredClone(manifest.initial_state);
    this.revision = 1;
    this.now = now;
    this.seed = seed;
    this.records = new Map();
    this.heads = new Map();
    this.counter = 0;
    this.steps = [];
  }
  execute(
    actorId,
    actionId,
    body = {},
    refs = [],
    {
      roles = this.manifest.protocol_roles,
      capabilities = this.manifest.capabilities,
      revision = this.revision,
      time = this.now,
    } = {},
  ) {
    if (revision !== this.revision)
      throw Object.assign(Error("STALE_REVISION"), { code: "STALE_REVISION" });
    const exact = refs.map((r) => {
      const found = this.records.get(r.record_id);
      if (!found || found.revision !== r.revision)
        throw Object.assign(Error("REFERENCE_NOT_FOUND"), {
          code: "REFERENCE_NOT_FOUND",
        });
      return {
        recordId: r.record_id,
        revision: r.revision,
        schema: found.schema,
        payload: found.structure,
        entityId: found.entity_id,
        scope: "INSTANCE",
      };
    });
    const result = executeStructureAction({
      protocol: this.protocol,
      actionId,
      state: this.state,
      structure: body,
      auth: { actorId, workspaceRoles: [], protocolRoles: roles, capabilities },
      exactInputs: exact,
      admittedAtMs: time,
    });
    const records = [],
      produced = new Map(),
      entities = new Map();
    for (let index = 0; index < result.records.length; index++) {
      const r = result.records[index],
        id = token(`${this.seed}:${this.counter}:${index}`);
      let entity = token(id + ":entity"),
        revision = 1;
      if (r.entity?.mode === "revise") {
        const parent = this.records.get(r.entity.parent.recordId);
        if (!parent || parent.revision !== r.entity.parent.revision)
          throw Error("REFERENCE_NOT_FOUND");
        entity = parent.entity_id;
        if (r.selectHead && this.heads.get(entity) !== parent.record_id)
          throw Object.assign(Error("STALE_REVISION"), {
            code: "STALE_REVISION",
          });
        revision = parent.revision + 1;
      }
      if (r.recordSlot) produced.set(r.recordSlot, { record_id: id, revision });
      if (r.entity) entities.set(r.entity.slot, entity);
      records.push({
        record_id: id,
        entity_id: entity,
        revision,
        schema: r.schema,
        structure: r.payload,
        selectHead: r.selectHead,
        relations: r.relations,
      });
    }
    const substitute = (v) => {
      if (Array.isArray(v)) return v.map(substitute);
      if (v && typeof v === "object") {
        if (v.$produced === "record") return produced.get(v.slot);
        if (v.$produced === "entity") return entities.get(v.slot);
        return Object.fromEntries(
          Object.entries(v).map(([k, x]) => [k, substitute(x)]),
        );
      }
      return v;
    };
    this.state = substitute(result.nextState);
    this.counter++;
    if (result.revisionEffects.control) this.revision++;
    for (const r of records) {
      r.structure = substitute(r.structure);
      this.records.set(r.record_id, r);
      if (r.selectHead) this.heads.set(r.entity_id, r.record_id);
    }
    const out = {
      simulated: true,
      authoritative: false,
      revision: this.revision,
      state: structuredClone(this.state),
      produced_record_ids: records.map((r) => r.record_id),
      records,
    };
    this.steps.push({
      actor_id: actorId,
      action_id: actionId,
      revision: this.revision,
    });
    return out;
  }
  ref(id) {
    const row = this.records.get(id);
    if (!row) throw Error("REFERENCE_NOT_FOUND");
    return { record_id: id, revision: row.revision };
  }
}
