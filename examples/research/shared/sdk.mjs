// SPDX-License-Identifier: Apache-2.0
import { createRequire } from "node:module";
import { resolve } from "node:path";
export function loadSDK() {
  const sdk = createRequire(resolve(process.cwd(), "package.json"))(
    process.env.PEERWORK_RESEARCH_SDK ?? "@peerwork/agent-sdk",
  );
  const version = sdk.version().split(".").map(Number);
  if (
    version[0] === 0 &&
    (version[1] < 2 || (version[1] === 2 && version[2] < 4))
  )
    throw Error("SDK_0_2_4_OR_LATER_REQUIRED");
  return sdk;
}
