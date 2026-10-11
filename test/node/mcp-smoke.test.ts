/**
 * The MCP surface, over the SDK's in-memory transport pair.
 *
 * In-memory rather than a spawned process: it is faster and it exercises the
 * same `Server`/`Client` protocol code. The one thing it CANNOT catch is a
 * stray `console.log` corrupting the stdio framing — that needs a real
 * process, and it lives in `pnpm run check:stdio-clean`.
 *
 * Runs under the forbidden-fetch global: the server is built with
 * `createServer({ fetchImpl, env: {} })`, never the real `globalThis.fetch`.
 *
 * The skeleton registers no tools, so this is the initialize round trip and
 * the version assertions. Per-tool tests arrive with the tools.
 */
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PACKAGE_VERSION } from "../../src/core/index.js";
import { SERVER_NAME, createServer } from "../../src/node/server.js";
import { INSTRUCTIONS, TOOL_NAMES } from "../../src/node/text.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(`${repoRoot}package.json`, "utf8")) as {
  version: string;
};

let client: Client;

beforeAll(async () => {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const fetchImpl = (() => {
    throw new Error("network forbidden in the smoke test");
  }) as unknown as typeof fetch;
  const server = createServer({ fetchImpl, env: {} });
  await server.connect(serverTransport);
  client = new Client({ name: "mcp-register-test", version: "0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
});

describe("initialize", () => {
  /**
   * The version is read from package.json here so that a forgotten bump
   * fails as a red test rather than as a lie in `initialize`'s serverInfo.
   */
  it("reports the package version", () => {
    expect(client.getServerVersion()).toMatchObject({
      name: "forestrie-mcp-register",
      version: pkg.version,
    });
    expect(SERVER_NAME).toBe("forestrie-mcp-register");
  });

  it("PACKAGE_VERSION agrees with package.json#version", () => {
    expect(PACKAGE_VERSION).toBe(pkg.version);
  });

  it("carries the instructions", () => {
    expect(client.getInstructions()).toBe(INSTRUCTIONS);
  });
});

describe("tools/list", () => {
  it("is exactly TOOL_NAMES (none yet), each with a non-empty description", async () => {
    const { tools } = await client.listTools().catch(() => ({ tools: [] }));
    expect(tools.map((t) => t.name).sort()).toEqual([...TOOL_NAMES].sort());
    for (const tool of tools) {
      expect((tool.description ?? "").length).toBeGreaterThan(0);
    }
  });
});
