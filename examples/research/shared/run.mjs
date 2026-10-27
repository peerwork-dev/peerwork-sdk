// SPDX-License-Identifier: Apache-2.0
import { runOffline } from "./offline.mjs";
export async function run(recipe) {
  if (process.argv.includes("--offline")) {
    console.log(JSON.stringify(await runOffline(recipe)));
    return;
  }
  const index = process.argv.indexOf("--binding");
  if (index < 0)
    throw Error(
      "Use --offline, or --binding PRIVATE_BINDING_FILE. See examples/research/README.md.",
    );
  const { runLive } = await import("./live.mjs");
  await runLive(recipe, process.argv[index + 1]);
}
