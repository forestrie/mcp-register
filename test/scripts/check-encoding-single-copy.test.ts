/**
 * `findCopies` (scripts/check-encoding-single-copy.mjs) must see every copy
 * of a tracked package, including one nested inside another tracked
 * package's own node_modules — npm's fallback when hoisting would conflict,
 * and exactly the skew this gate exists to catch. Synthetic trees only.
 */
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findCopies } from "../../scripts/check-encoding-single-copy.mjs";

let dir: string | undefined;

function pkg(at: string, name: string, version: string) {
  mkdirSync(at, { recursive: true });
  writeFileSync(join(at, "package.json"), JSON.stringify({ name, version }));
}

afterEach(() => {
  if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

const NAMES = ["@forestrie/encoding", "@forestrie/mcp-verify"];

describe("check:encoding-single-copy — findCopies", () => {
  it("finds a second copy nested inside a tracked package (npm layout)", () => {
    dir = mkdtempSync(join(tmpdir(), "single-copy-nested-"));
    const nm = join(dir, "node_modules", "@forestrie");
    pkg(join(nm, "encoding"), "@forestrie/encoding", "0.8.0");
    pkg(join(nm, "mcp-verify"), "@forestrie/mcp-verify", "0.5.0");
    pkg(
      join(nm, "mcp-verify", "node_modules", "@forestrie", "encoding"),
      "@forestrie/encoding",
      "0.9.0",
    );
    const found = findCopies(dir, NAMES);
    expect([...found.get("@forestrie/encoding")!.keys()].sort()).toEqual([
      "0.8.0",
      "0.9.0",
    ]);
  });

  it("finds one version in a clean tree", () => {
    dir = mkdtempSync(join(tmpdir(), "single-copy-clean-"));
    const nm = join(dir, "node_modules", "@forestrie");
    pkg(join(nm, "encoding"), "@forestrie/encoding", "0.8.0");
    pkg(join(nm, "mcp-verify"), "@forestrie/mcp-verify", "0.5.0");
    const found = findCopies(dir, NAMES);
    expect([...found.get("@forestrie/encoding")!.keys()]).toEqual(["0.8.0"]);
  });

  it("terminates on a symlink cycle", () => {
    dir = mkdtempSync(join(tmpdir(), "single-copy-cycle-"));
    const nm = join(dir, "node_modules");
    pkg(join(nm, "@forestrie", "encoding"), "@forestrie/encoding", "0.8.0");
    for (const n of ["a", "b", "c", "d"]) symlinkSync(".", join(nm, n));
    const started = Date.now();
    findCopies(dir, NAMES);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
