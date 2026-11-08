import assert from "node:assert/strict";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { setup } from "../../examples/research/setup.mjs";
import { runLive } from "../../examples/research/shared/live.mjs";
import { claimRace } from "./claim-race.mjs";
let probes;
const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
for (const recipe of ["delm", "agensh"]) {
  const directory = join(config.directory, recipe);
  mkdirSync(directory, { mode: 0o700 });
  // Exercise both an existing Owner/workspace and the documented fresh default.
  const recipeConfig =
    recipe === "agensh"
      ? {
          origin: config.origin,
          allowLoopbackHttp: true,
          timeoutMs: config.timeoutMs,
        }
      : config;
  const binding = await setup(recipeConfig, directory);
  const result = await runLive(recipe, binding.bindingPath);
  assert.equal(result.total, 17);
  assert.equal(result.independent_processes, true);
  const resumed = await runLive(recipe, binding.bindingPath);
  assert.equal(resumed.total, 17);
  if (recipe === "delm") probes = await claimRace(config, binding);
  if (recipe === "agensh") {
    for (const task of ["left", "right"]) {
      const artifact = JSON.parse(
        execFileSync(
          "git",
          [
            "--git-dir",
            join(directory, "shared.git"),
            "show",
            "main:" + task + ".json",
          ],
          { encoding: "utf8" },
        ),
      );
      assert.equal(artifact.artifact.value, task === "left" ? 5 : 12);
    }
  }
}
console.log(
  JSON.stringify({
    status: "PASS",
    ...probes,
    live_recipes: 2,
    restart_completed_binding: true,
    git_artifacts_verified: true,
  }),
);
