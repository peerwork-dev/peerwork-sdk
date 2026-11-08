// SPDX-License-Identifier: Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { once } from "node:events";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const product = process.env.PEERWORK_RESEARCH_BACKEND;
test(
  "installed SDK: two processes, claims, independent E2EE review, reply loss, Git merge and restart",
  {
    skip:
      !product ||
      !process.env.PEERWORK_POSTGRES_TEST_URL ||
      !process.env.PEERWORK_RESEARCH_SDK,
    timeout: 180000,
  },
  async () => {
    const { postgresFixture } = await import(
      pathToFileURL(
        join(
          product,
          "dist-workspace/tests/fixtures/workspace-postgres-fixture.js",
        ),
      )
    );
    const { createPostgresControlApp } = await import(
      pathToFileURL(
        join(product, "dist-workspace/src/workspace-postgres-http.js"),
      )
    );
    const { serve } = createRequire(join(product, "package.json"))(
      "@hono/node-server",
    );
    const f = await postgresFixture(),
      directory = mkdtempSync(join(tmpdir(), "peerwork-research-http-"));
    f.clock.now = Date.now();
    const ticker = setInterval(() => {
      f.clock.now = Date.now();
    }, 20);
    const app = createPostgresControlApp(f.kernel, {
        source: () => "127.0.0.1",
      }),
      paths = new Map(),
      submissions = new Map();
    let lostReplies = 0;
    const server = serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: async (request) => {
        const path = new URL(request.url).pathname;
        paths.set(path, (paths.get(path) ?? 0) + 1);
        let action, command;
        if (path.endsWith("/commands")) {
          const wire = await request.clone().json();
          const payload = wire.jws?.split(".")[1];
          if (payload) {
            command = JSON.parse(Buffer.from(payload, "base64url"));
            action = command.action_id;
          }
        }
        const response = await app.fetch(request);
        if (command && action === "structure.action" && response.ok) {
          const selected = command.body.action_id;
          submissions.set(command.command_id, {
            selected,
            key: command.command_id,
            probe:
              String(command.body?.structure?.artifact_digest ?? "") ===
              "0".repeat(64),
            count: (submissions.get(command.command_id)?.count ?? 0) + 1,
          });
          if (!lostReplies && selected === "work.submit") {
            lostReplies++;
            return Response.json(
              { error: { code: "TEST_REPLY_LOST", retryable: true } },
              { status: 503 },
            );
          }
        }
        return response;
      },
    });
    await once(server, "listening");
    try {
      const identity = join(directory, "owner.state");
      writeFileSync(
        identity,
        "PEERWORK-NATIVE-SECURE-STATE\n1\n" +
          JSON.stringify({
            kind: "peerwork.native-identity.v1",
            seed: f.owner.key.export({ format: "jwk" }).d,
          }),
        { mode: 0o600 },
      );
      const cfg = join(directory, "fixture.json");
      writeFileSync(
        cfg,
        JSON.stringify({
          origin: "http://127.0.0.1:" + server.address().port,
          workspace_id: f.workspace,
          directory,
          owner: { identityPath: identity, expectedActor: f.owner.actor },
          allowLoopbackHttp: true,
          timeoutMs: 60000,
        }),
        { mode: 0o600 },
      );
      let result;
      try {
        result = await promisify(execFile)(
          process.execPath,
          [new URL("./live-driver.mjs", import.meta.url).pathname, cfg],
          { timeout: 150000, maxBuffer: 131072, env: process.env },
        );
      } catch (error) {
        error.message +=
          "\nSTDOUT: " + error.stdout + "\nSTDERR: " + error.stderr;
        throw error;
      }
      const output = JSON.parse(result.stdout.trim().split("\n").at(-1));
      assert.equal(output.status, "PASS");
      assert.equal(output.concurrent_claim_exclusive, true);
      assert.equal(output.expired_holder_fenced, true);
      assert.equal(lostReplies, 1);
      assert.equal(
        [...paths].filter(([path]) => /journal|legacy|\/secure\//.test(path))
          .length,
        0,
      );
      const submits = [...submissions.values()].filter(
        (x) => x.selected === "work.submit" && !x.probe,
      );
      assert.equal(
        submits.length,
        4,
        "two accepted work submissions in each recipe, even after reply loss and restart",
      );
      console.log(
        JSON.stringify({
          status: "PASS",
          recipes: 2,
          independent_workers: 2,
          reply_loss_recovered: true,
          unique_submissions: submits.length,
          history_http_requests: 0,
        }),
      );
    } finally {
      clearInterval(ticker);
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await f.close();
      rmSync(directory, { recursive: true, force: true });
    }
  },
);
