/**
 * The frozen fixtures stay frozen: every file in each fixture directory is
 * in its manifest.json and hashes to the recorded sha256. The synthetic
 * write-path directory is also regenerated into a temp dir to prove the
 * generator reproduces everything that carries no ECDSA signature.
 */
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { generate as generatePaidGrant } from "../fixtures/synthetic/paid-grant/generate.mjs";
import { generate } from "../fixtures/synthetic/write-path/generate.mjs";
import { PAID_GRANT_DIR } from "../net/paid-grant-fixture.js";
import { LANE_A_DIR, WRITE_PATH_DIR } from "../net/write-path-fixture.js";

function sha256Hex(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function checkManifest(dir: string): void {
  const manifest = JSON.parse(
    readFileSync(path.join(dir, "manifest.json"), "utf8"),
  ) as { files: Record<string, string> };
  const onDisk = readdirSync(dir)
    .filter(
      (f) =>
        f !== "manifest.json" && !f.endsWith(".d.mts") && f !== "generate.mjs",
    )
    .sort();
  const listed = Object.keys(manifest.files)
    .filter((f) => f !== "generate.mjs" && !f.endsWith(".d.mts"))
    .sort();
  expect(listed).toEqual(onDisk);
  for (const [name, digest] of Object.entries(manifest.files)) {
    if (name === "generate.mjs" || name.endsWith(".d.mts")) continue;
    expect(sha256Hex(path.join(dir, name)), name).toBe(digest);
  }
}

describe("fixture manifests", () => {
  it("lane-a-0.5.0 matches its manifest", () => checkManifest(LANE_A_DIR));
  it("synthetic/write-path matches its manifest", () =>
    checkManifest(WRITE_PATH_DIR));
  it("synthetic/paid-grant matches its manifest", () =>
    checkManifest(PAID_GRANT_DIR));
});

describe("synthetic/paid-grant generator", () => {
  it("reproduces every unsigned file from the committed keys", async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "paid-grant-"));
    try {
      for (const f of readdirSync(PAID_GRANT_DIR).filter((n) =>
        n.endsWith(".jwk.json"),
      ))
        cpSync(path.join(PAID_GRANT_DIR, f), path.join(tmp, f));
      const result = await generatePaidGrant(tmp);
      const signed = new Set([
        "authority-grant.cose",
        "authority-grant-free.cose",
        "manifest.json",
      ]);
      for (const name of result.files) {
        if (signed.has(name)) continue;
        expect(sha256Hex(path.join(tmp, name)), name).toBe(
          sha256Hex(path.join(PAID_GRANT_DIR, name)),
        );
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("commits only test-only keys, each with the loud warning", () => {
    for (const f of readdirSync(PAID_GRANT_DIR).filter((n) =>
      n.endsWith(".jwk.json"),
    )) {
      const jwk = JSON.parse(
        readFileSync(path.join(PAID_GRANT_DIR, f), "utf8"),
      );
      expect(jwk.warning, f).toMatch(/^TEST ONLY\./);
    }
  });
});

describe("synthetic/write-path generator", () => {
  it("reproduces every unsigned file from the committed keys", async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "write-path-"));
    try {
      for (const f of readdirSync(WRITE_PATH_DIR).filter((n) =>
        n.endsWith(".jwk.json"),
      ))
        cpSync(path.join(WRITE_PATH_DIR, f), path.join(tmp, f));
      const result = await generate(tmp);
      const signed = new Set([
        "grant.cose",
        "grant-other-key.cose",
        "voucher.cose",
        "voucher-bad.cose",
        "standing-entry.json",
        "pending-standing.body",
        "pending-standing.meta.json",
        "pending-standing-bad-voucher.body",
        "pending-standing-bad-voucher.meta.json",
        "manifest.json",
      ]);
      for (const name of result.files) {
        if (signed.has(name)) continue;
        expect(sha256Hex(path.join(tmp, name)), name).toBe(
          sha256Hex(path.join(WRITE_PATH_DIR, name)),
        );
      }
      expect(
        readdirSync(tmp)
          .filter((n) => n !== "manifest.json")
          .sort(),
      ).toEqual(
        readdirSync(WRITE_PATH_DIR)
          .filter(
            (n) =>
              n !== "manifest.json" &&
              n !== "generate.mjs" &&
              !n.endsWith(".d.mts"),
          )
          .sort(),
      );
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("commits only test-only keys, each with the loud warning", () => {
    for (const f of readdirSync(WRITE_PATH_DIR).filter((n) =>
      n.endsWith(".jwk.json"),
    )) {
      const jwk = JSON.parse(
        readFileSync(path.join(WRITE_PATH_DIR, f), "utf8"),
      );
      expect(jwk.warning, f).toMatch(/^TEST ONLY\./);
    }
  });
});
