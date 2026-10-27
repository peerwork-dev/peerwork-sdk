// SPDX-License-Identifier: Apache-2.0
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const exec = promisify(execFile);
async function git(cwd, ...args) {
  return (
    await exec("git", args, {
      cwd,
      timeout: 15000,
      maxBuffer: 65536,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
    })
  ).stdout.trim();
}
export async function initializeRepository(directory) {
  const bare = join(directory, "shared.git");
  if (existsSync(bare)) return bare;
  await git(directory, "init", "--bare", "--initial-branch=main", bare);
  const seed = join(directory, "git-seed");
  mkdirSync(seed, { mode: 0o700 });
  await git(seed, "init", "--initial-branch=main");
  await git(seed, "config", "user.name", "Peerwork demo");
  await git(seed, "config", "user.email", "demo@localhost");
  writeFileSync(
    join(seed, "README.md"),
    "Private synthetic Agensh reference artifacts.\n",
  );
  await git(seed, "add", "README.md");
  await git(seed, "commit", "-m", "Initialize synthetic shared workspace");
  await git(seed, "remote", "add", "origin", bare);
  await git(seed, "push", "origin", "main");
  return bare;
}
export async function gitIntegrator(directory, bare, actor) {
  const checkout = join(directory, "checkout");
  if (!existsSync(join(checkout, ".git"))) {
    await git(directory, "clone", bare, checkout);
    await git(
      checkout,
      "config",
      "user.name",
      "Peerwork demo " + actor.slice(0, 8),
    );
    await git(checkout, "config", "user.email", "demo@localhost");
  }
  return async ({ task, text, result_ref, review_ref }) => {
    if (!["left", "right"].includes(task.id))
      throw Error("INTEGRATION_TARGET_INVALID");
    const filename = task.id + ".json",
      content =
        JSON.stringify(
          { artifact: JSON.parse(text), result_ref, review_ref },
          null,
          2,
        ) + "\n";
    for (let attempt = 0; attempt < 3; attempt++) {
      await git(checkout, "fetch", "origin", "main");
      await git(checkout, "rebase", "origin/main");
      writeFileSync(join(checkout, filename), content, { mode: 0o600 });
      await git(checkout, "add", filename);
      const staged = await git(checkout, "diff", "--cached", "--name-only");
      if (staged)
        await git(
          checkout,
          "commit",
          "-m",
          "Integrate independently reviewed " + task.id,
        );
      try {
        await git(checkout, "push", "origin", "HEAD:main");
        return;
      } catch {
        if (attempt === 2) throw Error("GIT_HANDOFF_REQUIRED");
      }
    }
  };
}
