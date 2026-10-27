// SPDX-License-Identifier: Apache-2.0
// Maintainer-only: bundle the actual Backend evaluator, never a second interpreter.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { resolve, join, relative } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
const product = resolve(process.argv[2] ?? ""),
  out = new URL("../../examples/research/vendor/", import.meta.url),
  require = createRequire(join(product, "package.json")),
  esbuild = require("esbuild");
const result = await esbuild.build({
  stdin: {
    contents: `export {compileStructureProtocol,executeStructureAction} from ${JSON.stringify(join(product, "src/workspace-structure-execution.ts"))};`,
    resolveDir: product,
  },
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node24",
  minify: true,
  legalComments: "inline",
  outfile: new URL("backend-evaluator.mjs", out).pathname,
  metafile: true,
  banner: {
    js: "// Generated from the Peerwork Backend evaluator. See backend-evaluator.source.json and LICENSE files.",
  },
});
const files = Object.keys(result.metafile.inputs)
  .filter((f) => !f.startsWith("<"))
  .sort()
  .map((f) => ({
    path: relative(product, resolve(product, f)).replaceAll("\\", "/"),
    sha256: createHash("sha256")
      .update(readFileSync(resolve(product, f)))
      .digest("hex"),
  }));
const manifest = {
  profile: "backend-structure-v1",
  product_commit: execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: product,
    encoding: "utf8",
  }).trim(),
  files,
  bundle_sha256: createHash("sha256")
    .update(readFileSync(new URL("backend-evaluator.mjs", out)))
    .digest("hex"),
};
writeFileSync(
  new URL("backend-evaluator.source.json", out),
  JSON.stringify(manifest, null, 2) + "\n",
);
copyFileSync(
  join(product, "protocols/LICENSE-APACHE-2.0"),
  new URL("LICENSE-Peerwork", out),
);
copyFileSync(
  join(product, "node_modules/zod/LICENSE"),
  new URL("LICENSE-Zod", out),
);
copyFileSync(
  join(product, "node_modules/@noble/hashes/LICENSE"),
  new URL("LICENSE-Noble-Hashes", out),
);
console.log(
  JSON.stringify({
    status: "EXPORTED_ACTUAL_BACKEND",
    files: files.length,
    bundle_bytes: readFileSync(new URL("backend-evaluator.mjs", out)).length,
  }),
);

copyFileSync(
  join(product, "node_modules/hpke/LICENSE.md"),
  new URL("LICENSE-HPKE", out),
);
