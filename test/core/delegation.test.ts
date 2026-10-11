import {
  isLowS,
  uuidToBytes,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import {
  buildOnchainDelegationToBeSignedEs256,
  decodeCoseSign1Parts,
  decodeDelegatedCoseKeyFromBytes,
  parseDelegatedCoseKeyFromPayload,
  parseDelegationCertificate,
} from "@forestrie/delegation-cose";
import { describe, expect, it } from "vitest";
import { base64ToBytes } from "../../src/core/base64.js";
import {
  DEFAULT_MMR_END,
  DelegationError,
  buildCertificateSubmission,
  checkVoucher,
  findStandingEntry,
  type StandingEntry,
} from "../../src/core/delegation.js";
import { toHex } from "../../src/core/hex.js";
import {
  coordinates,
  jwkSigner,
  logKeyXY,
  otherLogKeyXY,
  registrarKeyXY,
  verifyKeyFromXY,
  wp,
  wpJson,
} from "../net/write-path-fixture.js";

const entry = wpJson<Record<string, unknown>>("standing-entry.json");
const standing = findStandingEntry({
  entries: [entry],
  limit: 50,
}) as StandingEntry;
const badVoucher = Buffer.from(wp("voucher-bad.cose")).toString("base64");

describe("findStandingEntry", () => {
  it("picks the standing entry", () => {
    expect(standing).toEqual({
      delegatedPublicKey: entry["delegatedPublicKey"],
      suggestedTtlSeconds: coordinates.suggestedTtlSeconds,
      voucher: entry["voucher"],
      sealerId: coordinates.sealerId,
      epoch: coordinates.epoch,
    });
  });

  it("is undefined for an empty list, no entries field, or only demand rows", () => {
    expect(findStandingEntry({ entries: [], limit: 50 })).toBeUndefined();
    expect(findStandingEntry({})).toBeUndefined();
    expect(
      findStandingEntry({
        entries: [
          { mmrStart: 0, mmrEnd: 100, delegatedPublicKey: "x" },
          { suggestedTtlSeconds: 10, mmrStart: 5 },
        ],
      }),
    ).toBeUndefined();
  });

  it("finds the standing row among demand rows", () => {
    const got = findStandingEntry({
      entries: [{ mmrStart: 0, mmrEnd: 9 }, entry],
    });
    expect(got?.sealerId).toBe(coordinates.sealerId);
  });

  it("accepts a numeric-string epoch", () => {
    expect(
      findStandingEntry({ entries: [{ ...entry, epoch: "7" }] })?.epoch,
    ).toBe(7);
  });

  it("rejects malformed bodies and entries", () => {
    for (const body of [null, "x", 3, { entries: "nope" }])
      expect(() => findStandingEntry(body)).toThrow(DelegationError);
    const { voucher: _v, ...noVoucher } = entry;
    expect(() => findStandingEntry({ entries: [noVoucher] })).toThrow(
      expect.objectContaining({ code: "voucher_rejected" }),
    );
    expect(() =>
      findStandingEntry({ entries: [{ ...entry, epoch: -1 }] }),
    ).toThrow(expect.objectContaining({ code: "voucher_rejected" }));
    expect(() =>
      findStandingEntry({ entries: [{ ...entry, epoch: "seven" }] }),
    ).toThrow(expect.objectContaining({ code: "voucher_rejected" }));
  });
});

describe("checkVoucher", () => {
  it("passes for the good voucher under the registrar key", async () => {
    await expect(
      checkVoucher(standing, registrarKeyXY),
    ).resolves.toBeUndefined();
  });

  it("throws voucher_rejected for the voucher signed by a different key", async () => {
    await expect(
      checkVoucher({ ...standing, voucher: badVoucher }, registrarKeyXY),
    ).rejects.toMatchObject({ code: "voucher_rejected" });
  });

  it("throws voucher_rejected for a wrong pinned key", async () => {
    await expect(checkVoucher(standing, otherLogKeyXY)).rejects.toMatchObject({
      code: "voucher_rejected",
    });
  });

  it("throws voucher_rejected when the entry's claims differ from the voucher's", async () => {
    await expect(
      checkVoucher({ ...standing, epoch: standing.epoch + 1 }, registrarKeyXY),
    ).rejects.toMatchObject({ code: "voucher_rejected" });
    await expect(
      checkVoucher({ ...standing, sealerId: "someone-else" }, registrarKeyXY),
    ).rejects.toMatchObject({ code: "voucher_rejected" });
  });

  it("rejects a pinned key that is not 64 bytes", async () => {
    await expect(
      checkVoucher(standing, registrarKeyXY.slice(0, 32)),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });
});

describe("buildCertificateSubmission", () => {
  async function build(extra: { mmrEnd?: number; ttlSeconds?: number } = {}) {
    const signer = await jwkSigner();
    return buildCertificateSubmission(
      { logId: coordinates.dataLogId, standing, ...extra },
      signer,
    );
  }

  it("builds a certificate naming the log, the lease and the delegate key", async () => {
    const sub = await build();
    expect(sub.logId).toBe(coordinates.dataLogId);
    expect(sub.mmrStart).toBe(0);
    expect(sub.mmrEnd).toBe(DEFAULT_MMR_END);
    expect(sub.mmrEnd).toBe(Number.MAX_SAFE_INTEGER);
    expect(sub.delegatedPublicKey).toBe(standing.delegatedPublicKey);

    const cert = base64ToBytes(sub.certificate);
    const info = parseDelegationCertificate(cert);
    expect(info.logIdHex32).toBe(toHex(uuidToBytes(coordinates.dataLogId)));
    expect(info.mmrStart).toBe(0);
    expect(info.mmrEnd).toBe(Number.MAX_SAFE_INTEGER);
    expect(info.issuedAt).toBe(sub.issuedAt);
    expect(info.expiresAt).toBe(sub.expiresAt);
    expect(sub.expiresAt - sub.issuedAt).toBe(coordinates.suggestedTtlSeconds);

    // The log key signed the certificate.
    expect(
      await verifyCoseSign1WithParsedKey(cert, {
        x: logKeyXY.slice(0, 32),
        y: logKeyXY.slice(32),
        curve: "P-256",
      }),
    ).toBe(true);
    expect(
      await verifyCoseSign1WithParsedKey(cert, {
        x: otherLogKeyXY.slice(0, 32),
        y: otherLogKeyXY.slice(32),
        curve: "P-256",
      }),
    ).toBe(false);
    expect(decodeCoseSign1Parts(cert).payloadBytes.length).toBeGreaterThan(0);
  });

  it("honours mmrEnd and ttlSeconds", async () => {
    const sub = await build({ mmrEnd: 1000, ttlSeconds: 60 });
    expect(sub.mmrEnd).toBe(1000);
    expect(sub.expiresAt - sub.issuedAt).toBe(60);
    expect(
      parseDelegationCertificate(base64ToBytes(sub.certificate)).mmrEnd,
    ).toBe(1000);
  });

  it("rejects a negative or unsafe mmrEnd", async () => {
    await expect(build({ mmrEnd: -1 })).rejects.toMatchObject({
      code: "invalid_input",
    });
    await expect(build({ mmrEnd: 2 ** 60 })).rejects.toMatchObject({
      code: "invalid_input",
    });
  });

  it("signs the on-chain delegation proof low-s with the log key", async () => {
    const sub = await build({ mmrEnd: 4096 });
    const sig = base64ToBytes(sub.onchainSignature);
    expect(sig).toHaveLength(64);
    expect(isLowS(sig)).toBe(true);

    const delegated = parseDelegatedCoseKeyFromPayload(
      decodeDelegatedCoseKeyFromBytes(
        base64ToBytes(standing.delegatedPublicKey),
      ),
    );
    const tbs = buildOnchainDelegationToBeSignedEs256({
      logIdHex: toHex(uuidToBytes(coordinates.dataLogId)),
      mmrStart: 0,
      mmrEnd: 4096,
      delegatedKeyX: delegated.x,
      delegatedKeyY: delegated.y,
    });
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await verifyKeyFromXY(logKeyXY),
      sig as BufferSource,
      tbs.sigStructureBytes as BufferSource,
    );
    expect(ok).toBe(true);
  });

  it("always low-s, even when the signer returns a high-s signature", async () => {
    const real = await jwkSigner();
    const N =
      0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const highS = {
      ...real,
      sign: async (m: Uint8Array) => {
        const sig = await real.sign(m);
        const s = BigInt("0x" + toHex(sig.slice(32)));
        const flipped = s <= N / 2n ? N - s : s;
        const out = sig.slice();
        out.set(
          Uint8Array.from(
            flipped
              .toString(16)
              .padStart(64, "0")
              .match(/../g)!
              .map((h) => parseInt(h, 16)),
          ),
          32,
        );
        return out;
      },
    };
    const sub = await buildCertificateSubmission(
      { logId: coordinates.dataLogId, standing },
      highS,
    );
    expect(isLowS(base64ToBytes(sub.onchainSignature))).toBe(true);
  });
});
