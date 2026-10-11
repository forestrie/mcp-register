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
import { spawnSync } from "node:child_process";
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

beforeAll(() => {
  if (existsSync(DIST_CLI)) return;
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
  it("the real bin writes exactly one well-formed initialize response to stdout, nothing else", () => {
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
