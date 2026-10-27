// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
export const digest = (value) =>
  createHash("sha256").update(value).digest("hex");
export function accepted(outcome) {
  if (!["ACCEPTED", "COMPLETED"].includes(outcome.state))
    throw Object.assign(
      Error(
        outcome.result?.structure?.error?.code ??
          outcome.code ??
          "OPERATION_NOT_ACCEPTED",
      ),
      { outcome },
    );
  return outcome.result;
}
function summary(outcome) {
  const r = outcome.result?.structure;
  return {
    state: outcome.state,
    command_id: outcome.command_id ?? outcome.result?.command_id ?? null,
    code: outcome.code ?? r?.error?.code ?? null,
    retryable: outcome.retryable ?? r?.error?.retryable ?? false,
    effect_certainty: outcome.effect_certainty ?? r?.effect_certainty ?? null,
    revision: r?.revision ?? null,
    produced_record_ids: r?.produced_record_ids ?? [],
    state_snapshot: r?.state ?? null,
  };
}
/** Calls the installed native SDK; owns durable business selection, never signatures. */
export class WorkClient {
  constructor(kernel, scope, store) {
    this.kernel = kernel;
    this.scope = scope;
    this.store = store;
    this.actor = kernel.actor_id;
  }
  async read() {
    return accepted(
      await this.kernel.executeStructureIntent({
        action: "structure.instance.get",
        ...this.scope,
        body: {},
      }),
    ).structure;
  }
  async record(reference) {
    return accepted(
      await this.kernel.executeStructureIntent({
        action: "structure.record.get",
        ...this.scope,
        body: reference,
      }),
    );
  }
  async act(action_id, structure, key, { refs = [], revision, artifact } = {}) {
    if (revision === undefined) revision = (await this.read()).revision;
    const request = {
      action: "structure.action",
      ...this.scope,
      expected_instance_revision: revision,
      idempotency_key: "research-" + digest(key),
      exact_input_refs: refs,
      body: { action_id, structure },
    };
    const selected = { request, ...(artifact ? { artifact } : {}) },
      saved = this.store.saveDecision(key, selected);
    return this.resume(key, saved);
  }
  async resume(key, saved = this.store.decision(key)) {
    if (!saved) throw Error("DECISION_NOT_FOUND");
    if (saved.result && saved.result.state !== "PENDING") return saved.result;
    let outcome;
    if (saved.result?.command_id)
      outcome = await this.kernel.resumeStructureIntent(
        saved.result.command_id,
      );
    else {
      const { request, artifact } = saved.intent;
      let plaintext_contents;
      if (artifact) {
        const bytes = readFileSync(artifact.path);
        if (digest(bytes) !== artifact.sha256)
          throw Error("BODY_ARTIFACT_CHANGED");
        plaintext_contents = [
          {
            record_index: 0,
            text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
          },
        ];
      }
      outcome = await this.kernel.executeStructureIntent({
        ...request,
        ...(plaintext_contents ? { plaintext_contents } : {}),
      });
    }
    const result = summary(outcome);
    this.store.result(key, result);
    return result;
  }
}
