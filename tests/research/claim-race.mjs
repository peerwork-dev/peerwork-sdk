// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { loadSDK } from "../../examples/research/shared/sdk.mjs";
import { accepted } from "../../examples/research/shared/client.mjs";
import { cooperationProtocol } from "../../examples/meta-protocols/index.mjs";
export async function claimRace(config, binding) {
  const sdk = loadSDK(),
    owner = await sdk.openKernel({
      origin: config.origin,
      identityPath: config.owner.identityPath,
      journalPath: join(config.directory, "race-owner.sqlite"),
      allowLoopbackHttp: true,
    });
  const manifest = cooperationProtocol({ minLeaseMs: 25, maxLeaseMs: 1000 });
  const adopted = accepted(
    await owner.executeStructureIntent({
      action: "structure.adopt",
      workspace_id: config.workspace_id,
      idempotency_key: "race-adopt",
      body: {
        manifest,
        bootstrap_grant: {
          actions: manifest.actions.map((x) => x.id),
          protocol_roles: manifest.protocol_roles,
          capabilities: manifest.capabilities,
        },
      },
    }),
  ).structure;
  const scope = {
      workspace_id: config.workspace_id,
      instance_id: adopted.instance_id,
      protocol_digest: adopted.protocol_digest,
    },
    workers = [];
  for (const file of binding.workers) {
    const cfg = JSON.parse(readFileSync(file, "utf8")),
      worker = await sdk.openKernel({
        origin: cfg.origin,
        identityPath: cfg.identityPath,
        journalPath: cfg.journalPath,
        allowLoopbackHttp: true,
      });
    const metadata = accepted(
      await worker.executeStructureIntent({
        action: "structure.workspace.get",
        workspace_id: config.workspace_id,
        body: {},
      }),
    ).structure;
    accepted(
      await owner.executeStructureIntent({
        action: "structure.grant.set",
        ...scope,
        idempotency_key: "race-grant-" + worker.actor_id,
        body: {
          actor_id: worker.actor_id,
          membership_id: metadata.membership.membership_id,
          expected_grant_revision: null,
          actions: manifest.actions.map((x) => x.id),
          protocol_roles: manifest.protocol_roles,
          capabilities: manifest.capabilities,
        },
      }),
    );
    workers.push(worker);
  }
  const act = (worker, id, structure, revision, key, refs = []) =>
    worker.executeStructureIntent({
      action: "structure.action",
      ...scope,
      expected_instance_revision: revision,
      idempotency_key: key,
      exact_input_refs: refs,
      body: { action_id: id, structure },
    });
  const attempts = await Promise.all(
    workers.map((w, i) =>
      act(w, "work.claim", { ttl_ms: 25 }, 1, "race-claim-" + i),
    ),
  );
  const winner = attempts.findIndex((x) => x.state === "ACCEPTED");
  assert(winner >= 0);
  assert.equal(attempts.filter((x) => x.state === "ACCEPTED").length, 1);
  assert.equal(attempts[1 - winner].state, "REJECTED");
  const old = attempts[winner].result.structure.state.lease_ref;
  await delay(75);
  const fresh = accepted(
    await act(
      workers[1 - winner],
      "work.reclaim",
      { ttl_ms: 1000 },
      2,
      "race-reclaim",
    ),
  ).structure.state.lease_ref;
  const stale = await act(
    workers[winner],
    "work.submit",
    { claim_ref: old, artifact_digest: "0".repeat(64) },
    3,
    "race-stale-submit",
    [old],
  );
  assert.equal(stale.state, "REJECTED");
  assert.equal(stale.result.structure.error.code, "CONSTRAINT_FAILED");
  accepted(
    await act(
      workers[1 - winner],
      "work.submit",
      { claim_ref: fresh, artifact_digest: "0".repeat(64) },
      3,
      "race-fresh-submit",
      [fresh],
    ),
  );
  return { concurrent_claim_exclusive: true, expired_holder_fenced: true };
}
