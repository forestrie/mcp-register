import { describe, expect, it } from "vitest";
import {
  GrantError,
  inspectGrant,
  prepareGrantProblems,
  statementGrantProblems,
  type GrantView,
} from "../../src/core/grant.js";
import { toHex } from "../../src/core/hex.js";
import {
  coordinates,
  logKeyXY,
  otherLogKeyXY,
  wp,
} from "../net/write-path-fixture.js";

describe("inspectGrant", () => {
  it("reads the data-log creation grant", () => {
    const view = inspectGrant(wp("grant.cose"));
    expect(view.logId).toBe(coordinates.dataLogId);
    expect(view.ownerLogId).toBe(coordinates.ownerLogId);
    expect(view.flagsHex).toBe("0000000300000002");
    expect(view.grantData).toEqual(logKeyXY);
    expect(view.dataLogStatementGrant).toBe(true);
    expect(view.createAndExtend).toBe(true);
    expect(toHex(view.grantData)).toHaveLength(128);
  });

  it("names the other key in grant-other-key.cose", () => {
    const view = inspectGrant(wp("grant-other-key.cose"));
    expect(view.grantData).toEqual(otherLogKeyXY);
    expect(view.logId).toBe(coordinates.dataLogId);
  });

  it("throws GrantError on garbage", () => {
    for (const bytes of [
      new Uint8Array([1, 2, 3]),
      new Uint8Array(0),
      new TextEncoder().encode("not a grant"),
      wp("voucher.cose"), // a COSE Sign1, but not a grant
    ])
      expect(() => inspectGrant(bytes)).toThrow(GrantError);
  });
});

describe("statementGrantProblems", () => {
  const grant = inspectGrant(wp("grant.cose"));

  it("is empty for the log key the grant names", () => {
    expect(statementGrantProblems(grant, logKeyXY)).toEqual([]);
  });

  it("names a different key", () => {
    const problems = statementGrantProblems(grant, otherLogKeyXY);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/different key/);
  });

  it("refuses flags that authorise no statements, and non-ES256 grantData", () => {
    const bad: GrantView = {
      ...grant,
      flagsHex: "0000000000000002",
      dataLogStatementGrant: false,
      statementRegistrationGrant: false,
      grantData: new Uint8Array(20),
    };
    const problems = statementGrantProblems(bad, logKeyXY);
    expect(problems.join("\n")).toMatch(
      /do not authorise statement registration/,
    );
    expect(problems.join("\n")).toMatch(/20 bytes/);
    expect(problems).toHaveLength(2);
  });

  it("refuses a data-log grant whose log is its own owner", () => {
    const problems = statementGrantProblems(
      { ...grant, logId: grant.ownerLogId },
      logKeyXY,
    );
    expect(problems).toEqual([
      expect.stringMatching(/logId equals ownerLogId/),
    ]);
  });

  it("accepts an auth-log bootstrap grant, as canopy's isStatementRegistrationGrant does", () => {
    const authBootstrap: GrantView = {
      ...grant,
      flagsHex: "0000000300000001",
      dataLogStatementGrant: false,
      statementRegistrationGrant: true,
      logId: grant.ownerLogId,
    };
    expect(statementGrantProblems(authBootstrap, logKeyXY)).toEqual([]);
  });
});

describe("prepareGrantProblems", () => {
  const grant = inspectGrant(wp("grant.cose"));

  it("is empty for the creation grant", () => {
    expect(prepareGrantProblems(grant)).toEqual([]);
  });

  it("refuses a grant lacking GF_CREATE, a root-log grant and a non-64-byte root", () => {
    const problems = prepareGrantProblems({
      ...grant,
      createAndExtend: false,
      logId: grant.ownerLogId,
      grantData: new Uint8Array(33),
    });
    expect(problems).toHaveLength(3);
  });
});
