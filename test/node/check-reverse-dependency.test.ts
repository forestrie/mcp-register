/**
 * Negative test: `findMcpRegisterCopies`
 * (scripts/check-reverse-dependency.mjs) must find a nested
 * @forestrie/mcp-register wherever it is planted — plain nested
 * node_modules, and pnpm's `.pnpm/<key>/node_modules/<scope>/<name>` store
 * layout — and must find nothing in a clean tree. Pure filesystem walk,
 * synthetic fixtures only: no network, no real install.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  HOSTS,
  findMcpRegisterCopies,
  scanInstalledTree,
} from "../../scripts/check-reverse-dependency.mjs";

let scratchDir: string | undefined;

function writePkg(dir: string, name: string, version = "0.0.0-test") {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name, version }),
    "utf8",
  );
}

afterEach(() => {
  if (scratchDir !== undefined) {
    rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

describe("check:reverse-dependency — findMcpRegisterCopies", () => {
  it("checks both mcp-verify and mcp-resolve", () => {
    expect(HOSTS).toEqual(["@forestrie/mcp-verify", "@forestrie/mcp-resolve"]);
  });

  it("finds @forestrie/mcp-register inside a nested mcp-resolve too", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-resolve-"));
    const resolveDir = join(
      scratchDir,
      "node_modules",
      "@forestrie",
      "mcp-resolve",
    );
    writePkg(resolveDir, "@forestrie/mcp-resolve");
    const planted = join(
      resolveDir,
      "node_modules",
      "@forestrie",
      "mcp-register",
    );
    writePkg(planted, "@forestrie/mcp-register");
    expect(findMcpRegisterCopies(scratchDir)).toEqual([planted]);
  });

  it("finds a plain nested @forestrie/mcp-register", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-nested-"));
    writePkg(
      join(scratchDir, "node_modules", "@forestrie", "mcp-verify"),
      "@forestrie/mcp-verify",
    );
    const planted = join(
      scratchDir,
      "node_modules",
      "@forestrie",
      "mcp-verify",
      "node_modules",
      "@forestrie",
      "mcp-register",
    );
    writePkg(planted, "@forestrie/mcp-register");

    expect(findMcpRegisterCopies(scratchDir)).toEqual([planted]);
  });

  it("finds @forestrie/mcp-register under pnpm's .pnpm store layout", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-pnpm-"));
    writePkg(
      join(scratchDir, "node_modules", "@forestrie", "mcp-verify"),
      "@forestrie/mcp-verify",
    );
    const planted = join(
      scratchDir,
      "node_modules",
      ".pnpm",
      "@forestrie+mcp-register@1.0.0",
      "node_modules",
      "@forestrie",
      "mcp-register",
    );
    writePkg(planted, "@forestrie/mcp-register");

    expect(findMcpRegisterCopies(scratchDir)).toEqual([planted]);
  });

  it("finds both at once, and only those, alongside unrelated packages", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-both-"));
    writePkg(
      join(scratchDir, "node_modules", "@forestrie", "mcp-verify"),
      "@forestrie/mcp-verify",
    );
    writePkg(join(scratchDir, "node_modules", "left-pad"), "left-pad");
    const nested = join(
      scratchDir,
      "node_modules",
      "@forestrie",
      "mcp-verify",
      "node_modules",
      "@forestrie",
      "mcp-register",
    );
    writePkg(nested, "@forestrie/mcp-register");
    const pnpmStyle = join(
      scratchDir,
      "node_modules",
      ".pnpm",
      "@forestrie+mcp-register@1.0.0",
      "node_modules",
      "@forestrie",
      "mcp-register",
    );
    writePkg(pnpmStyle, "@forestrie/mcp-register");

    const hits = findMcpRegisterCopies(scratchDir);
    expect(hits.sort()).toEqual([nested, pnpmStyle].sort());
  });

  it("finds nothing in a clean tree", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-clean-"));
    writePkg(
      join(scratchDir, "node_modules", "@forestrie", "mcp-verify"),
      "@forestrie/mcp-verify",
    );
    writePkg(
      join(
        scratchDir,
        "node_modules",
        "@forestrie",
        "mcp-verify",
        "node_modules",
        "@forestrie",
        "receipt-verify",
      ),
      "@forestrie/receipt-verify",
    );
    writePkg(join(scratchDir, "node_modules", "left-pad"), "left-pad");

    expect(findMcpRegisterCopies(scratchDir)).toEqual([]);
  });

  it("does not false-positive on a directory named mcp-register with a different package.json name", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-namecheck-"));
    // Folder name matches; package.json name does not. Must not count.
    writePkg(
      join(scratchDir, "node_modules", "@forestrie", "mcp-register"),
      "@someone-else/mcp-register",
    );

    expect(findMcpRegisterCopies(scratchDir)).toEqual([]);
  });
});

describe("check:reverse-dependency — scanInstalledTree", () => {
  it("reports every package name it walked past, so main() can prove coverage", () => {
    scratchDir = mkdtempSync(join(tmpdir(), "reverse-dependency-seen-"));
    const store = join(scratchDir, "node_modules", ".pnpm");
    writePkg(
      join(
        store,
        "@forestrie+mcp-verify@0.5.0",
        "node_modules",
        "@forestrie",
        "mcp-verify",
      ),
      "@forestrie/mcp-verify",
    );
    writePkg(
      join(
        store,
        "@forestrie+mcp-resolve@0.3.0",
        "node_modules",
        "@forestrie",
        "mcp-resolve",
      ),
      "@forestrie/mcp-resolve",
    );
    const { hits, seen } = scanInstalledTree(scratchDir);
    expect(hits).toEqual([]);
    expect([...seen].sort()).toEqual(HOSTS.slice().sort());
  });
});
