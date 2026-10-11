/**
 * `@forestrie/mcp-register` — the browser-safe core.
 *
 * This is the `"."` export. Everything reachable from here is pure over
 * bytes: no `node:*`, no `fetch`, no filesystem, no MCP SDK, no key
 * material. `"./net"` is the only place `fetch` is called, and `"./server"`
 * is where the MCP adapter, the signer backend and the key file live.
 * `pnpm run check:browser-safe` bundles this file for `platform: "browser"`
 * and fails on any edge to a node builtin.
 *
 * Currently: version constants only. Tools arrive in the next change.
 */

export {
  PACKAGE_VERSION,
  VERIFIER_VERSION,
  RESOLVE_VERSION,
} from "./version.js";
