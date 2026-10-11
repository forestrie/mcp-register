/**
 * The default payer builds the x402 v2 payment payload itself, because the
 * upstream client (`@x402/evm`) draws a random EIP-3009 nonce and cannot be
 * given the grant's. This checks that, nonce aside, it is the upstream
 * client's payload: same fields, same order, same values, and both pass the
 * stub facilitator's EIP-712 check.
 */
import { x402Client } from "@x402/core/client";
import { encodePaymentSignatureHeader } from "@x402/core/http";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readPaymentRequired } from "../../src/core/x402.js";
import { evmPayer } from "../../src/node/payer.js";
import { pg, pgx } from "../net/paid-grant-fixture.js";
import { decodeB64Json, stubVerify } from "../net/stub-facilitator.js";

const NOW = new Date("2026-10-11T12:00:00Z");
const nowSeconds = Math.floor(NOW.getTime() / 1000);

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
});

describe("evmPayer", () => {
  it("builds the upstream x402 client's payload, with the nonce it is given", async () => {
    const header = pgx("register-grant-402").headers["x-payment-required"]!;
    const raw = decodeB64Json(header);
    const required = readPaymentRequired(raw);
    const nonce = `0x${"5a".repeat(32)}`;

    const ours = await evmPayer(pg.payerPrivateKey, "test").pay({
      required,
      option: required.accepts[0]!,
      nonce,
      nowSeconds,
    });

    const client = new x402Client();
    registerExactEvmScheme(client, {
      signer: privateKeyToAccount(pg.payerPrivateKey),
      networks: [pg.network as `${string}:${string}`],
    });
    const upstream = encodePaymentSignatureHeader(
      await client.createPaymentPayload(raw),
    );

    const a = decodeB64Json(ours);
    const b = decodeB64Json(upstream);
    expect(Object.keys(a)).toEqual(Object.keys(b));
    expect(a.accepted).toEqual(b.accepted);
    expect(a.resource).toEqual(b.resource);
    expect(a.x402Version).toBe(b.x402Version);
    const { nonce: na, ...restA } = a.payload.authorization;
    const { nonce: nb, ...restB } = b.payload.authorization;
    expect(restA).toEqual(restB);
    expect(na).toBe(nonce);
    expect(nb).not.toBe(nonce);

    const requirement = raw.accepts[0];
    expect(await stubVerify(ours, requirement, nowSeconds)).toEqual({
      isValid: true,
      payer: pg.payerAddress,
    });
    expect(await stubVerify(upstream, requirement, nowSeconds)).toEqual({
      isValid: true,
      payer: pg.payerAddress,
    });
  });

  it("refuses requirements without the EIP-712 domain, and a malformed nonce", async () => {
    const required = readPaymentRequired(
      decodeB64Json(pgx("register-grant-402").headers["x-payment-required"]!),
    );
    const { extra: _e, ...bare } = required.accepts[0]!;
    const payer = evmPayer(pg.payerPrivateKey, "test");
    await expect(
      payer.pay({
        required,
        option: bare,
        nonce: `0x${"00".repeat(32)}`,
        nowSeconds,
      }),
    ).rejects.toThrow(/EIP-712 domain/);
    await expect(
      payer.pay({
        required,
        option: required.accepts[0]!,
        nonce: "0x12",
        nowSeconds,
      }),
    ).rejects.toThrow(/nonce/);
  });
});
