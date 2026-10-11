/**
 * The stdio-clean gate, made part of `vitest run --project unit` rather than only its
 * own separately-invoked `check:stdio-clean` package script: spawns the
 * real bin (`scripts/check-stdio-clean.mjs` unaltered — mirroring it, not
 * duplicating its logic) and asserts it exits 0.
 *
 * The script spawns `bin/mcp-register.mjs`, which imports `../dist/node/cli.js`
 * — a real build, not the in-memory transport `test/node/mcp-smoke.test.ts`
 * and `test/node/tools.test.ts` use. `dist/` is therefore a precondition
 * this test cannot skip past silently: `beforeAll` builds it (via the
 * project's own pinned `typescript` binary, `tsc -p tsconfig.build.json`)
 * whenever it is absent, so a clean checkout still gets a real answer
 * instead of a false green.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const REPO_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const DIST_CLI = path.join(REPO_ROOT, "dist", "node", "cli.js");
const TSC_BIN = path.join(
  REPO_ROOT,
  "node_modules",
  "typescript",
  "bin",
  "tsc",
);
const CHECK_SCRIPT = path.join(REPO_ROOT, "scripts", "check-stdio-clean.mjs");

let buildFailure: string | undefined;

// Always rebuild: these tests spawn dist/, and a dist/ left over from an
// earlier checkout would test old code.
beforeAll(() => {
  const build = spawnSync(
    process.execPath,
    [TSC_BIN, "-p", "tsconfig.build.json"],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  if (build.status !== 0 || !existsSync(DIST_CLI)) {
    buildFailure =
      `dist/ was absent and \`tsc -p tsconfig.build.json\` did not produce ` +
      `${DIST_CLI} (exit ${String(build.status)}):\n` +
      `${build.stdout}\n${build.stderr}`;
  }
}, 60_000);

describe("check:stdio-clean", () => {
  it("the real bin writes only well-formed replies to stdout, through initialize, the lists and a tool call", () => {
    if (buildFailure !== undefined) {
      throw new Error(buildFailure);
    }
    const result = spawnSync(process.execPath, [CHECK_SCRIPT], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 30_000,
    });
    expect(
      result.status,
      `check:stdio-clean exited ${String(result.status)} (signal ${String(
        result.signal,
      )})\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    ).toBe(0);
  });
});

describe("signals", () => {
  it("exits 0 on SIGTERM even while the client keeps stdin open", async () => {
    if (buildFailure !== undefined) throw new Error(buildFailure);
    const child = spawn(
      process.execPath,
      [path.join(REPO_ROOT, "bin", "mcp-register.mjs")],
      { cwd: REPO_ROOT, stdio: ["pipe", "pipe", "pipe"] },
    );
    const initialized = new Promise<void>((resolve) => {
      child.stdout.on("data", (chunk: Buffer) => {
        if (chunk.toString().includes('"id":1')) resolve();
      });
    });
    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "signal-test", version: "0" },
        },
      }) + "\n",
    );
    await initialized;
    const exited = new Promise<number | null>((resolve) =>
      child.on("exit", (code) => resolve(code)),
    );
    child.kill("SIGTERM");
    const code = await Promise.race([
      exited,
      new Promise<"timeout">((r) => setTimeout(() => r("timeout"), 3000)),
    ]);
    if (code === "timeout") child.kill("SIGKILL");
    expect(code).toBe(0);
  }, 20_000);
});
