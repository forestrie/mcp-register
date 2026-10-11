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
 * The surface only: names, annotations, prompts, and the no-signature-input
 * rule. What each tool does is tested in test/node/tools.test.ts.
 */
import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PACKAGE_VERSION } from "../../src/core/index.js";
import { SERVER_NAME, createServer } from "../../src/node/server.js";
import {
  INSTRUCTIONS,
  PROMPT_NAMES,
  TOOL_NAMES,
} from "../../src/node/text.js";

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
  it("is exactly TOOL_NAMES, in order, each with a non-empty description", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([...TOOL_NAMES]);
    for (const tool of tools) {
      expect((tool.description ?? "").length).toBeGreaterThan(0);
    }
  });

  it("annotates only verify_registration as read-only, and nothing as destructive", async () => {
    const { tools } = await client.listTools();
    for (const tool of tools) {
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(
        tool.name === "verify_registration",
      );
      expect(tool.annotations?.destructiveHint, tool.name).toBe(false);
    }
  });

  it("takes no signature and no private key as input (the model never handles signature bytes)", async () => {
    const { tools } = await client.listTools();
    for (const tool of tools) {
      const schema = JSON.stringify(tool.inputSchema).toLowerCase();
      expect(schema, tool.name).not.toMatch(
        /"(signature|sig|privatekey|private_key|d|jwk)"\s*:/,
      );
    }
  });
});

describe("prompts", () => {
  it("prompts/list is exactly PROMPT_NAMES, in order", async () => {
    const { prompts } = await client.listPrompts();
    expect(prompts.map((p) => p.name)).toEqual([...PROMPT_NAMES]);
  });

  it("register walks the loop in tool order", async () => {
    const { messages } = await client.getPrompt({
      name: "register",
      arguments: { what: "a build manifest" },
    });
    const text = (messages[0]?.content as { text: string }).text;
    expect(text).toContain("a build manifest");
    const order = [
      "get_log_key",
      "delegate_sealing",
      "register_statement",
      "check_registration",
      "verify_registration",
    ].map((name) => text.indexOf(`Call ${name}`));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it("audit names all four questions and never ranks the roots", async () => {
    const { messages } = await client.getPrompt({
      name: "audit",
      arguments: {},
    });
    const text = (messages[0]?.content as { text: string }).text;
    for (const q of [
      "sealing",
      "split-view",
      "append-authority",
      "attribution",
      "not_answered_by_this_root",
    ])
      expect(text).toContain(q);
    expect(text).toContain("not ranked");
  });
});

describe("missing configuration", () => {
  it("register_statement without a base URL is a missing_input problem, not a throw or a request", async () => {
    const result = await client.callTool({
      name: "register_statement",
      arguments: { payload: { b64: "aGk=" }, contentType: "text/plain" },
    });
    expect(result.isError).toBe(false);
    expect(
      (result.structuredContent as { problem: { code: string } }).problem.code,
    ).toBe("missing_input");
  });
});
