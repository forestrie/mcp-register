/**
 * Every `*_VERSION` constant in src/core/version.ts must equal the matching
 * exact pin in package.json#dependencies. A forgotten bump on either side
 * is a red test here rather than a silent lie in `--help`.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  PACKAGE_VERSION,
  RESOLVE_VERSION,
  VERIFIER_VERSION,
} from "../../src/core/index.js";

const repoRoot = new URL("../../", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(`${repoRoot}package.json`, "utf8")) as {
  version: string;
  dependencies: Record<string, string>;
};

function pinnedVersion(name: string): string {
  return pkg.dependencies[name] as string;
}

describe("version constants agree with package.json", () => {
  it("PACKAGE_VERSION === package.json#version", () => {
    expect(PACKAGE_VERSION).toBe(pkg.version);
  });

  it("VERIFIER_VERSION === the @forestrie/mcp-verify pin", () => {
    expect(VERIFIER_VERSION).toBe(pinnedVersion("@forestrie/mcp-verify"));
  });

  it("RESOLVE_VERSION === the @forestrie/mcp-resolve pin, and the installed package", () => {
    expect(RESOLVE_VERSION).toBe(pinnedVersion("@forestrie/mcp-resolve"));
    const installed = JSON.parse(
      readFileSync(
        `${repoRoot}node_modules/@forestrie/mcp-resolve/package.json`,
        "utf8",
      ),
    ) as { version: string };
    expect(installed.version).toBe(RESOLVE_VERSION);
  });
});
