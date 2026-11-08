// SPDX-License-Identifier: Apache-2.0
import { spawn } from "node:child_process";
/** Harness-neutral JSON stdin/stdout adapter. No shell interpolation or identity files. */
export function runAgentCommand(
  argv,
  input,
  { signal, timeoutMs = 60000, maxBytes = 65536, cwd } = {},
) {
  if (
    !Array.isArray(argv) ||
    !argv.length ||
    argv.some((s) => typeof s !== "string" || !s)
  )
    throw Error("AGENT_COMMAND_REQUIRED");
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      signal,
    });
    let output = [],
      bytes = 0,
      settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      }, 1000).unref();
      finish(Error("AGENT_COMMAND_TIMEOUT"));
    }, timeoutMs);
    child.stdout.on("data", (b) => {
      bytes += b.length;
      if (bytes > maxBytes) {
        child.kill("SIGKILL");
        finish(Error("AGENT_OUTPUT_LIMIT"));
      } else output.push(b);
    });
    child.stderr.resume();
    child.on("error", () => finish(Error("AGENT_COMMAND_FAILED")));
    child.on("close", (code) => {
      if (code !== 0) return finish(Error("AGENT_COMMAND_FAILED"));
      try {
        const value = JSON.parse(Buffer.concat(output).toString("utf8"));
        if (
          !value ||
          typeof value.text !== "string" ||
          Buffer.byteLength(value.text) > maxBytes
        )
          throw Error();
        finish(null, value);
      } catch {
        finish(Error("AGENT_OUTPUT_INVALID"));
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(input) + "\n");
  });
}
