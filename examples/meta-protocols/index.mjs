// SPDX-License-Identifier: Apache-2.0
export { sharedFindings } from "./findings.mjs";
export { workClaim } from "./work-claim.mjs";
export { reviewAdopt } from "./review-adopt.mjs";
import { sharedFindings } from "./findings.mjs";
import { workClaim } from "./work-claim.mjs";
import { reviewAdopt } from "./review-adopt.mjs";
/** Source-level composition, yielding an ordinary fully resolved backend manifest. */
export function composeProtocol(
  modules,
  { name = "peerwork.research.cooperation", version = "1.0.0" } = {},
) {
  const ids = new Set(),
    schemas = {},
    initial = {};
  const actions = [];
  for (const m of modules) {
    if (ids.has(m.id)) throw Error("DUPLICATE_MODULE");
    ids.add(m.id);
  }
  for (const m of modules) {
    for (const dependency of m.requires ?? [])
      if (!ids.has(dependency)) throw Error("MISSING_MODULE_" + dependency);
    for (const [k, v] of Object.entries(m.schemas)) {
      if (k in schemas) throw Error("SCHEMA_COLLISION");
      schemas[k] = v;
    }
    for (const [k, v] of Object.entries(m.initial_state)) {
      if (k in initial) throw Error("STATE_COLLISION");
      initial[k] = v;
    }
    actions.push(...m.actions);
  }
  if (new Set(actions.map((a) => a.id)).size !== actions.length)
    throw Error("ACTION_COLLISION");
  return {
    name,
    display_version: version,
    semantics: "peerwork.kernel.v1",
    dependencies: [],
    initial_state: initial,
    protocol_roles: [...new Set(modules.flatMap((m) => m.roles))],
    capabilities: [...new Set(modules.flatMap((m) => m.capabilities))],
    record_schemas: schemas,
    actions,
  };
}
export const cooperationProtocol = (options) =>
  composeProtocol([sharedFindings(), workClaim(options), reviewAdopt()]);
