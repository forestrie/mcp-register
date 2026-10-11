import { describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "../../src/core/base64.js";
import { inspectGrant } from "../../src/core/grant.js";
import { delegateSealing } from "../../src/net/delegate.js";
import { createReplay, type Exchange } from "./replay.js";
import {
  coordinates as c,
  ex,
  jwkSigner,
  otherLogKeyXY,
  registrarKeyXY,
  wp,
} from "./write-path-fixture.js";

const pendingUrl = `${c.coordinatorUrl}/api/logs/${c.dataLogId}/pending-delegation`;
const prepareUrl = `${c.baseUrl}/api/forest/${c.dataLogId}/prepare`;
const certUrl = `${c.coordinatorUrl}/api/delegations/certificate`;

const grantBytes = wp("grant.cose");
const grantB64 = bytesToBase64(grantBytes);
const grant = inspectGrant(grantBytes);

function input(extra: Record<string, unknown> = {}) {
  const sleeps: number[] = [];
  return {
    sleeps,
    args: {
      baseUrl: c.baseUrl,
      coordinatorUrl: c.coordinatorUrl,
      knownSealerKeyXY: registrarKeyXY,
      grantB64,
      grant,
      sleep: async (ms: number) => {
        sleeps.push(ms);
      },
      ...extra,
    },
  };
}

async function run(
  exchanges: Exchange[],
  extra: Record<string, unknown> = {},
  knownSealerKeyXY = registrarKeyXY,
) {
  const replay = createReplay(exchanges);
  const { args, sleeps } = input({ knownSealerKeyXY, ...extra });
  const outcome = await delegateSealing(args, await jwkSigner(), {
    fetchImpl: replay.fetch,
  });
  return { outcome, replay, sleeps };
}

describe("delegateSealing", () => {
  it("(a) uses a standing entry as found: one GET, one certificate POST, no prepare", async () => {
    const { outcome, replay, sleeps } = await run([
      ex("pending-standing"),
      ex("certificate-200"),
    ]);
    expect(outcome).toMatchObject({
      kind: "delegated",
      logId: c.dataLogId,
      sealerId: c.sealerId,
      epoch: c.epoch,
      prepared: false,
      certificateKey: expect.stringContaining(c.dataLogId),
    });
    expect(replay.calls.map((x) => `${x.method} ${x.url}`)).toEqual([
      `GET ${pendingUrl}`,
      `POST ${certUrl}`,
    ]);
    expect(sleeps).toEqual([]);
    const post = replay.callsTo("POST", certUrl)[0]!;
    expect(post.headers["content-type"]).toBe("application/json");
    const body = JSON.parse(new TextDecoder().decode(post.body));
    expect(body.logId).toBe(c.dataLogId);
    expect(body.mmrStart).toBe(0);
    expect(Object.keys(body).sort()).toEqual(
      [
        "certificate",
        "delegatedPublicKey",
        "expiresAt",
        "issuedAt",
        "logId",
        "mmrEnd",
        "mmrStart",
        "onchainSignature",
      ].sort(),
    );
    expect(base64ToBytes(body.certificate)[0]).toBe(0x84);
  });

  it("(b) prepares when the coordinator has no standing entry, then delegates", async () => {
    const { outcome, replay, sleeps } = await run([
      ex("pending-empty"),
      ex("prepare-201"),
      ex("pending-standing"),
      ex("certificate-200"),
    ]);
    expect(outcome).toMatchObject({ kind: "delegated", prepared: true });
    expect(replay.calls.map((x) => `${x.method} ${x.url}`)).toEqual([
      `GET ${pendingUrl}`,
      `POST ${prepareUrl}`,
      `GET ${pendingUrl}`,
      `POST ${certUrl}`,
    ]);
    const prepare = replay.callsTo("POST", prepareUrl)[0]!;
    expect(prepare.headers["authorization"]).toBe(
      `Forestrie-Grant ${grantB64}`,
    );
    expect(prepare.body).toHaveLength(0);
    // Injected sleep, never a real wait: one poll interval.
    expect(sleeps).toEqual([2000]);
    expect(replay.remaining()).toBe(0);
  });

  it("(c) reports a prepare refusal at stage prepare, with no certificate POST", async () => {
    const { outcome, replay } = await run([
      ex("pending-empty"),
      ex("prepare-403"),
    ]);
    expect(outcome).toMatchObject({
      kind: "problem",
      stage: "prepare",
      prepared: false,
      problem: { status: 403, title: "Forbidden", reason: "grant_rejected" },
    });
    expect(replay.callsTo("POST", certUrl)).toHaveLength(0);
    expect(replay.calls).toHaveLength(2);
  });

  it("(d) rejects a voucher signed by the wrong key at stage voucher", async () => {
    const { outcome, replay } = await run([
      ex("pending-standing-bad-voucher"),
    ]);
    expect(outcome).toMatchObject({ kind: "problem", stage: "voucher" });
    expect(replay.callsTo("POST", certUrl)).toHaveLength(0);
    expect(replay.calls).toHaveLength(1);
  });

  it("(d') rejects a good voucher when the pinned key is wrong", async () => {
    const { outcome, replay } = await run(
      [ex("pending-standing")],
      {},
      otherLogKeyXY,
    );
    expect(outcome).toMatchObject({ kind: "problem", stage: "voucher" });
    expect(replay.callsTo("POST", certUrl)).toHaveLength(0);
  });

  it("(e) gives up at stage pending_delegation when prepare never produces a standing entry", async () => {
    const polls = 3;
    const { outcome, replay, sleeps } = await run(
      [
        ex("pending-empty"),
        ex("prepare-201"),
        ...Array.from({ length: polls }, () => ex("pending-empty")),
      ],
      { pollsAfterPrepare: polls, pollIntervalMs: 10 },
    );
    expect(outcome).toMatchObject({
      kind: "problem",
      stage: "pending_delegation",
      prepared: true,
    });
    expect(sleeps).toEqual([10, 10, 10]);
    expect(replay.callsTo("GET", pendingUrl)).toHaveLength(1 + polls);
    expect(replay.callsTo("POST", certUrl)).toHaveLength(0);
    expect(replay.remaining()).toBe(0);
  });

  it("does not call prepare with a grant prepare would refuse", async () => {
    const { outcome, replay } = await run([ex("pending-empty")], {
      grant: { ...grant, createAndExtend: false },
    });
    expect(outcome).toMatchObject({ kind: "problem", stage: "prepare" });
    expect(replay.callsTo("POST", prepareUrl)).toHaveLength(0);
  });

  it("reports a coordinator rejection of the certificate at stage certificate", async () => {
    const rejected: Exchange = {
      ...ex("certificate-200"),
      status: 409,
      body: new TextEncoder().encode(
        JSON.stringify({ error: "conflict", message: "overlapping lease" }),
      ),
    };
    const { outcome } = await run([ex("pending-standing"), rejected]);
    expect(outcome).toMatchObject({
      kind: "problem",
      stage: "certificate",
      problem: { status: 409, title: "conflict", detail: "overlapping lease" },
    });
  });

  it("reports a non-200 or non-JSON pending-delegation at stage pending_delegation", async () => {
    const down: Exchange = {
      ...ex("pending-empty"),
      status: 503,
      body: new Uint8Array(0),
    };
    expect((await run([down])).outcome).toMatchObject({
      kind: "problem",
      stage: "pending_delegation",
    });
    const html: Exchange = {
      ...ex("pending-empty"),
      body: new TextEncoder().encode("<html>"),
    };
    expect((await run([html])).outcome).toMatchObject({
      kind: "problem",
      stage: "pending_delegation",
    });
  });
});
