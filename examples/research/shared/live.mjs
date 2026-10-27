// SPDX-License-Identifier: Apache-2.0
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { initializeRepository } from "./git.mjs";
export async function runLive(recipe, path) {
  const binding = JSON.parse(readFileSync(path, "utf8"));
  if (
    binding.schema !== "peerwork.research-demo.v1" ||
    binding.workers.length !== 2
  )
    throw Error("BINDING_INVALID");
  const children = [];
  if (recipe === "agensh") {
    const bare = await initializeRepository(binding.directory);
    for (const file of binding.workers) {
      const cfg = JSON.parse(readFileSync(file, "utf8"));
      cfg.bareRepository = bare;
      writeFileSync(file, JSON.stringify(cfg), { mode: 0o600 });
    }
  }
  try {
    const peers = await Promise.all(
      binding.workers.map(
        (file) =>
          new Promise((resolve, reject) => {
            const child = spawn(
              process.execPath,
              [new URL("./worker.mjs", import.meta.url).pathname, file, recipe],
              { stdio: ["ignore", "pipe", "pipe"] },
            );
            children.push(child);
            let output = "",
              stderr = "";
            child.stdout.on("data", (x) => {
              output += x;
              if (output.length > 65536) child.kill();
            });
            child.stderr.on("data", (x) => {
              if (stderr.length < 65536) stderr += x;
            });
            child.on("error", reject);
            child.on("close", (code) => {
              if (code !== 0) {
                writeFileSync(
                  join(binding.directory, "worker-failure.log"),
                  stderr,
                  { mode: 0o600 },
                );
                return reject(Error("WORKER_INCOMPLETE: " + output.trim()));
              }
              try {
                resolve(JSON.parse(output.trim()));
              } catch {
                reject(Error("WORKER_RESULT_INVALID"));
              }
            });
          }),
      ),
    );
    if (peers.some((x) => x.status !== "PASS" || x.candidate_total !== 17))
      throw Error("REFERENCE_RESULT_INVALID");
    const result = {
      status: "PASS",
      recipe,
      mode: peers.some((x) => x.mode === "external_harness")
        ? "external_harness"
        : "scripted_protocol_fixture",
      simulated: false,
      worker_count: 2,
      candidates: peers.length,
      total: 17,
      independent_processes: true,
      peers,
      model_quality_measured: false,
    };
    writeFileSync(
      join(binding.directory, recipe + "-result.json"),
      JSON.stringify(result, null, 2) + "\n",
      { mode: 0o600 },
    );
    console.log(JSON.stringify(result));
    return result;
  } finally {
    for (const child of children)
      if (child.exitCode === null) child.kill("SIGTERM");
  }
}
