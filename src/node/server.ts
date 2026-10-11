/**
 * `createServer(deps?)` — the MCP adapter. No transport: the caller connects
 * one (stdio from `cli.ts`, `InMemoryTransport` from the smoke test), which
 * is also what lets an embedder mount tools on their own transport without
 * the CLI.
 *
 * Registers no tools yet: the skeleton exists so the gates, the packaging
 * and the `initialize` round trip are green before any tool is added. Tools
 * register from `TOOL_NAMES` (`text.ts`).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PACKAGE_VERSION } from "../core/index.js";
import { INSTRUCTIONS } from "./text.js";

export const SERVER_NAME = "forestrie-mcp-register";

/** Every field optional; defaults to `process.env` / `globalThis.fetch` /
 *  `() => new Date()` so tests can inject fakes without touching the real
 *  network or the real environment. */
export type Deps = {
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  now?: () => Date;
};

export function createServer(_deps?: Deps): McpServer {
  return new McpServer(
    { name: SERVER_NAME, version: PACKAGE_VERSION },
    { instructions: INSTRUCTIONS },
  );
}
