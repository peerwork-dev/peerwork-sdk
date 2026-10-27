#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  lstatSync,
} from "node:fs";
import { resolve, join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { loadSDK } from "./shared/sdk.mjs";
import { accepted } from "./shared/client.mjs";
import {
  cooperationProtocol,
  composeProtocol,
  sharedFindings,
} from "../meta-protocols/index.mjs";
export async function setup(config, directory) {
  directory = resolve(directory);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (lstatSync(directory).mode & 0o077)
    throw Error("PRIVATE_DIRECTORY_REQUIRED");
  const sdk = loadSDK(),
    path = join(directory, "setup-state.json"),
    selection = createHash("sha256")
      .update(JSON.stringify(config))
      .digest("hex");
  let saved = existsSync(path)
    ? JSON.parse(readFileSync(path, "utf8"))
    : {
        selection,
        run_id: randomUUID(),
        workers: [],
        intents: {},
        instances: [],
      };
  if (saved.selection !== selection) throw Error("SETUP_SELECTION_CHANGED");
  const persist = () =>
    writeFileSync(path, JSON.stringify(saved, null, 2) + "\n", { mode: 0o600 });
  persist();
  const ownerIdentity =
    config.owner?.identityPath ?? join(directory, "owner.state");
  if (!config.owner?.identityPath && !existsSync(ownerIdentity))
    await sdk.createIdentity(ownerIdentity);
  const owner = await sdk.openKernel({
    origin: config.origin,
    identityPath: ownerIdentity,
    journalPath: config.owner?.journalPath ?? join(directory, "owner.sqlite"),
    authority: config.authority,
    allowLoopbackHttp: config.allowLoopbackHttp ?? false,
  });
  if (
    config.owner?.expectedActor &&
    owner.actor_id !== config.owner.expectedActor
  )
    throw Error("OWNER_IDENTITY_MISMATCH");
  const execute = async (key, intent) => {
    if (!saved.intents[key]) {
      saved.intents[key] = {
        ...intent,
        idempotency_key: "research-setup-" + saved.run_id + "-" + key,
      };
      persist();
    }
    return accepted(await owner.executeStructureIntent(saved.intents[key]))
      .structure;
  };
  if (!saved.workspace_id) {
    saved.workspace_id =
      config.workspace_id ??
      (
        await execute("workspace", {
          action: "structure.workspace.create",
          body: { name: "Research protocol demo" },
        })
      ).workspace_id;
    persist();
  }
  for (let i = 0; i < 2; i++) {
    const stateDir = join(directory, "worker-" + i);
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const identity = join(stateDir, "identity.state");
    if (!existsSync(identity)) await sdk.createIdentity(identity);
    const worker = await sdk.openKernel({
      origin: config.origin,
      identityPath: identity,
      journalPath: join(stateDir, "operations.sqlite"),
      authority: config.authority,
      allowLoopbackHttp: config.allowLoopbackHttp ?? false,
    });
    let row = saved.workers[i];
    if (!row) {
      row = {
        actor_id: worker.actor_id,
        stateDir,
        identityPath: identity,
        journalPath: join(stateDir, "operations.sqlite"),
      };
      saved.workers[i] = row;
      persist();
    }
    if (row.actor_id !== worker.actor_id)
      throw Error("WORKER_IDENTITY_CHANGED");
    if (!row.membership_id) {
      if (!row.request) {
        row.request = await worker.requestAccess({
          workspace_id: saved.workspace_id,
          label: "Research demo worker " + i,
        });
        persist();
      }
      accepted(
        await owner.authorizeAccess({
          workspace_id: saved.workspace_id,
          request_jws: row.request.request_jws,
          ttl_ms: 86400000,
          follow_current_key: true,
        }),
      );
      const meta = accepted(
        await worker.executeStructureIntent({
          action: "structure.workspace.get",
          workspace_id: saved.workspace_id,
          body: {},
        }),
      ).structure;
      row.membership_id = meta.membership.membership_id;
      persist();
    }
    const metadata = accepted(
      await worker.executeStructureIntent({
        action: "structure.workspace.get",
        workspace_id: saved.workspace_id,
        body: {},
      }),
    ).structure;
    if (metadata.content_key_head?.key_id)
      await worker.acceptContentKeys({
        workspace_id: saved.workspace_id,
        owner_id: owner.actor_id,
        key_ids: [metadata.content_key_head.key_id],
        current_key_id: metadata.content_key_head.key_id,
      });
  }
  const sources = [
    composeProtocol([sharedFindings()], { name: "peerwork.research.findings" }),
    cooperationProtocol(),
    cooperationProtocol(),
  ];
  for (let i = 0; i < sources.length; i++) {
    const m = sources[i];
    if (!saved.instances[i]) {
      const r = await execute("adopt-" + i, {
        action: "structure.adopt",
        workspace_id: saved.workspace_id,
        body: {
          manifest: m,
          bootstrap_grant: {
            actions: m.actions.map((a) => a.id),
            protocol_roles: m.protocol_roles,
            capabilities: m.capabilities,
          },
        },
      });
      saved.instances[i] = {
        instance_id: r.instance_id,
        protocol_digest: r.protocol_digest,
      };
      persist();
    }
    const scope = { workspace_id: saved.workspace_id, ...saved.instances[i] };
    for (const row of saved.workers) {
      const key = "grant-" + i + "-" + row.actor_id;
      await execute(key, {
        action: "structure.grant.set",
        ...scope,
        body: {
          actor_id: row.actor_id,
          membership_id: row.membership_id,
          expected_grant_revision: null,
          actions: m.actions.map((a) => a.id),
          protocol_roles: m.protocol_roles,
          capabilities: m.capabilities,
        },
      });
    }
  }
  const base = {
    origin: config.origin,
    authority: config.authority ?? null,
    allowLoopbackHttp: config.allowLoopbackHttp ?? false,
    workspace_id: saved.workspace_id,
    run_id: saved.run_id,
    board: saved.instances[0],
    work: saved.instances.slice(1),
    agentCommand: config.agentCommand ?? null,
    timeoutMs: config.timeoutMs ?? 120000,
    agentTimeoutMs: config.agentTimeoutMs ?? 60000,
  };
  const workers = [];
  for (const row of saved.workers) {
    const workerFile = join(row.stateDir, "worker.json");
    writeFileSync(
      workerFile,
      JSON.stringify({
        ...base,
        actor_id: row.actor_id,
        identityPath: row.identityPath,
        journalPath: row.journalPath,
        stateDir: row.stateDir,
      }),
      { mode: 0o600 },
    );
    workers.push(workerFile);
  }
  const binding = {
    schema: "peerwork.research-demo.v1",
    directory,
    workspace_id: saved.workspace_id,
    run_id: saved.run_id,
    workers,
    work: base.work,
    board: base.board,
  };
  const bindingPath = join(directory, "binding.json");
  writeFileSync(bindingPath, JSON.stringify(binding, null, 2) + "\n", {
    mode: 0o600,
  });
  return { bindingPath, ...binding };
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === new URL(import.meta.url).pathname
) {
  if (!process.argv[2] || !process.argv[3])
    throw Error(
      "Usage: node examples/research/setup.mjs CONFIG_JSON PRIVATE_DEMO_DIRECTORY",
    );
  console.log(
    JSON.stringify(
      await setup(
        JSON.parse(readFileSync(process.argv[2], "utf8")),
        process.argv[3],
      ),
    ),
  );
}
