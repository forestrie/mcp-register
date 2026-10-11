/**
 * `--help` names exactly the tools `tools/list` returns. The help text was
 * a hand-written block that listed six tools for a release in which the
 * server registered seven (`fetch_checkpoint_history` was missing), and
 * nothing tested it. Now the block is generated from `TOOL_NAMES`
 * (`src/node/text.ts`), the server registers from the same list, and this
 * test spawns the real bin — `dist/`, built by `beforeAll` when absent, as
 * `stdio-clean.test.ts` does — and compares.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../../src/node/server.js";
import { TOOL_NAMES } from "../../src/node/text.js";

const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const BIN = path.join(REPO_ROOT, "bin", "mcp-register.mjs");
const DIST_CLI = path.join(REPO_ROOT, "dist", "node", "cli.js");
const TSC_BIN = path.join(
  REPO_ROOT,
  "node_modules",
  "typescript",
  "bin",
  "tsc",
);

let buildFailure: string | undefined;

beforeAll(() => {
  if (existsSync(DIST_CLI)) return;
  const build = spawnSync(
    process.execPath,
    [TSC_BIN, "-p", "tsconfig.build.json"],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  if (build.status !== 0 || !existsSync(DIST_CLI)) {
    buildFailure = `dist/ was absent and tsc did not produce ${DIST_CLI}:\n${build.stdout}\n${build.stderr}`;
  }
}, 60_000);

async function listedToolNames(): Promise<string[]> {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const server = createServer({ fetchImpl: globalThis.fetch, env: {} });
  await server.connect(serverTransport);
  const client = new Client({ name: "help-test", version: "0" });
  await client.connect(clientTransport);
  try {
    // A server with no tools registered does not advertise the tools
    // capability, so tools/list is "method not found": that is an empty list.
    const { tools } = await client.listTools().catch(() => ({ tools: [] }));
    return tools.map((t) => t.name);
  } finally {
    await client.close();
  }
}

/** The tool names `--help` prints: every whitespace-separated token in
 *  the TOOLS block that is a registered name — order preserved. */
function helpToolNames(help: string): string[] {
  const block = help.split(/^TOOLS\n/m)[1]?.split(/\n\n/)[0] ?? "";
  return block
    .split(/\s+/)
    .filter((token) => (TOOL_NAMES as readonly string[]).includes(token));
}

describe("--help", () => {
  it("names exactly the tools tools/list returns, in registration order", async () => {
    if (buildFailure !== undefined) throw new Error(buildFailure);
    const result = spawnSync(process.execPath, [BIN, "--help"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const listed = await listedToolNames();
    expect(helpToolNames(result.stdout)).toEqual(listed);
    expect(listed).toEqual([...TOOL_NAMES]);
    // (Zero tools today: the block says so. The loop below is vacuous until
    // tools land, and then checks every tool's title.)
    // Every tool's title is on the line that names it.
    for (const name of TOOL_NAMES) {
      expect(result.stdout).toMatch(new RegExp(`^  ${name}\\s+\\S`, "m"));
    }
  });
});
