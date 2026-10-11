/**
 * Child-grant construction, the parent check, the register-grant body and
 * completion, over bytes.
 */
import { decodeCborDeterministic } from "@forestrie/encoding";
import { describe, expect, it } from "vitest";
import { GrantError, inspectGrant } from "../../src/core/grant.js";
import {
  completeGrant,
  grantContent,
  issueChildGrant,
  parentGrantProblems,
  registerGrantBody,
} from "../../src/core/issue.js";
import { toHex } from "../../src/core/hex.js";
import {
  authorityGrantPath,
  freeAuthorityGrantPath,
  pg,
  pgSigner,
} from "../net/paid-grant-fixture.js";
import { grantPath, logKeyXY, wp } from "../net/write-path-fixture.js";
import { readFileSync } from "node:fs";

const read = (p: string) => new Uint8Array(readFileSync(p));

describe("issueChildGrant", () => {
  const base = {
    logId: pg.childLogId,
    ownerLogId: pg.authorityLogId,
    grantData: logKeyXY,
    maxHeight: 8,
  };

  it.each([
    ["a non-UUID log id", { logId: "nope" }],
    ["a self-owned log", { logId: pg.authorityLogId }],
    ["a 20-byte key", { grantData: new Uint8Array(20) }],
    ["maxHeight 0", { maxHeight: 0 }],
    ["a fractional maxHeight", { maxHeight: 1.5 }],
  ])("refuses %s", async (_what, over) => {
    await expect(
      issueChildGrant({ ...base, ...over }, await pgSigner()),
    ).rejects.toBeInstanceOf(GrantError);
  });

  it("refuses a signer that does not return r‖s", async () => {
    const signer = {
      ...(await pgSigner()),
      sign: async () => new Uint8Array(70),
    };
    await expect(issueChildGrant(base, signer)).rejects.toThrow(/64-byte r‖s/);
  });
});

describe("parentGrantProblems", () => {
  it("accepts the requester's authority grant for its own key", async () => {
    const xy = await (await pgSigner()).publicKeyXY();
    const view = inspectGrant(read(authorityGrantPath));
    expect(view).toMatchObject({ authLog: true, requiresChildPayment: true });
    expect(parentGrantProblems(view, xy)).toEqual([]);
    expect(
      inspectGrant(read(freeAuthorityGrantPath)).requiresChildPayment,
    ).toBe(false);
  });

  it("refuses another key and a data-log grant", async () => {
    const view = inspectGrant(read(authorityGrantPath));
    expect(parentGrantProblems(view, logKeyXY).join()).toMatch(
      /different key/,
    );
    const xy = await (await pgSigner()).publicKeyXY();
    expect(
      parentGrantProblems(inspectGrant(read(grantPath)), xy).join(),
    ).toMatch(/not an authority-log grant/);
  });
});

describe("grantContent", () => {
  it("is the same for two signatures of one grant", async () => {
    const input = {
      logId: pg.childLogId,
      ownerLogId: pg.authorityLogId,
      grantData: logKeyXY,
      maxHeight: 8,
    };
    const a = await issueChildGrant(input, await pgSigner());
    const b = await issueChildGrant(input, await pgSigner());
    expect(toHex(a.grant)).not.toBe(toHex(b.grant));
    expect(toHex(grantContent(a.grant))).toBe(toHex(grantContent(b.grant)));
    expect(toHex(grantContent(a.grant))).toBe(toHex(a.grantPayload));
  });

  it("refuses bytes that are not a grant", () => {
    expect(() => grantContent(new Uint8Array([1, 2, 3]))).toThrow(GrantError);
  });
});

describe("registerGrantBody and completeGrant", () => {
  it("puts the parent in a canonical CBOR map under parentGrant", () => {
    const parent = read(authorityGrantPath);
    const body = decodeCborDeterministic(registerGrantBody(parent)) as Map<
      string,
      Uint8Array
    >;
    expect([...body.keys()]).toEqual(["parentGrant"]);
    expect(toHex(body.get("parentGrant")!)).toBe(toHex(parent));
  });

  it("refuses an entry id that is not 32 hex", () => {
    expect(() =>
      completeGrant(wp("grant.cose"), new Uint8Array(1), "xyz"),
    ).toThrow(GrantError);
  });
});
