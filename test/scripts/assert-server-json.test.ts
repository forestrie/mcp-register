/**
 * scripts/assert-server-json.mjs's pure `checkServerJson` check:
 * server.json must agree with package.json AND validate against the
 * vendored registry schema, not just the two hand-picked caps. No network
 * — the schema is read from the committed vendor file, exactly as the CLI
 * itself reads it.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { checkServerJson } from "../../scripts/assert-server-json.mjs";

const repoRoot = new URL("../../", import.meta.url).pathname;

function readJson(relPath: string): Record<string, unknown> {
  return JSON.parse(readFileSync(`${repoRoot}${relPath}`, "utf8"));
}

const pkg = readJson("package.json");
const server = readJson("server.json");
const schema = readJson("tools/registry-schema/2025-12-11.json");

describe("checkServerJson", () => {
  it("passes for the real package.json and server.json", () => {
    expect(checkServerJson(pkg, server, schema)).toEqual([]);
  });

  it("fails a 101-character description", () => {
    const bad = { ...server, description: "x".repeat(101) };
    const failures = checkServerJson(pkg, bad, schema);
    expect(failures.length).toBeGreaterThan(0);
    expect(failures.some((f) => f.includes("description"))).toBe(true);
  });

  it("fails a missing name", () => {
    const bad = { ...server };
    delete (bad as { name?: unknown }).name;
    const failures = checkServerJson(pkg, bad, schema);
    expect(failures.length).toBeGreaterThan(0);
    expect(
      failures.some((f) => f.includes("name") || f.includes("required")),
    ).toBe(true);
  });

  it("fails an unvendored $schema", () => {
    const bad = {
      ...server,
      $schema:
        "https://static.modelcontextprotocol.io/schemas/2099-01-01/server.schema.json",
    };
    const failures = checkServerJson(pkg, bad, schema);
    expect(
      failures.some((f) => f.includes("$schema") && f.includes("vendor")),
    ).toBe(true);
  });

  it("the vendored schema's sha256 matches the fetched fact (2026-09-14)", () => {
    const bytes = readFileSync(
      `${repoRoot}tools/registry-schema/2025-12-11.json`,
    );
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    expect(sha256).toBe(
      "3fba09590c99f61735d234822279f4223fab9e300c0a81e81c91ab62a4114de0",
    );
  });
});
