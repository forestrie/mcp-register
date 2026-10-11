/**
 * The cap logic over decoded requirements: each refusal, and what it
 * refuses first.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_PAY_ASSET,
  DEFAULT_PAY_NETWORK,
  PaymentError,
  readPaymentPayload,
  readPaymentRequired,
  selectWithinCaps,
  type PaymentCaps,
} from "../../src/core/x402.js";

const RESOURCE = "https://canopy.example.test/register/r/grants";
const PAY_TO = "0x00000000000000000000000000000000000fee01";

function required(over: Record<string, unknown> = {}) {
  return {
    x402Version: 2,
    accepts: [
      {
        scheme: "exact",
        network: DEFAULT_PAY_NETWORK,
        amount: "8000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        payTo: PAY_TO,
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2" },
        ...over,
      },
    ],
    resource: { url: RESOURCE, mimeType: "application/cose" },
  };
}

const caps: PaymentCaps = {
  network: DEFAULT_PAY_NETWORK,
  asset: DEFAULT_PAY_ASSET,
  maxPerCallAtomic: 10000n,
  maxPerDayAtomic: 20000n,
  allowMainnet: false,
};

const ctx = { resourceUrl: RESOURCE, spentTodayAtomic: 0n };

function refusal(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    expect(err).toBeInstanceOf(PaymentError);
    return (err as PaymentError).code;
  }
  throw new Error("expected a refusal");
}

describe("readPaymentRequired", () => {
  it("reads canopy's requirements", () => {
    const r = readPaymentRequired(required());
    expect(r.accepts[0]).toMatchObject({ amount: "8000", payTo: PAY_TO });
    expect(r.resource?.url).toBe(RESOURCE);
  });

  it.each([
    ["not an object", 7],
    ["wrong version", { ...required(), x402Version: 1 }],
    ["no accepts", { ...required(), accepts: [] }],
    ["a non-integer amount", required({ amount: "1.5" })],
    ["a bad address", required({ payTo: "nobody" })],
    ["no exact scheme", required({ scheme: "upto" })],
  ])("refuses %s", (_what, json) => {
    expect(refusal(() => readPaymentRequired(json))).toBe(
      "invalid_payment_requirements",
    );
  });
});

describe("selectWithinCaps", () => {
  it("picks the one option within every cap", () => {
    expect(
      selectWithinCaps(readPaymentRequired(required()), caps, ctx),
    ).toMatchObject({ amount: "8000" });
  });

  it("allows exactly the per-call and per-day limits", () => {
    const r = readPaymentRequired(required({ amount: "10000" }));
    expect(
      selectWithinCaps(r, caps, { ...ctx, spentTodayAtomic: 10000n }).amount,
    ).toBe("10000");
  });

  it.each<[string, Record<string, unknown>, Partial<PaymentCaps>, bigint]>([
    ["cap_network", { network: "eip155:8453" }, {}, 0n],
    [
      "cap_asset",
      { asset: "0x00000000000000000000000000000000000a55e7" },
      {},
      0n,
    ],
    [
      "cap_testnet_only",
      { network: "eip155:8453" },
      { network: "eip155:8453" },
      0n,
    ],
    [
      "cap_payee",
      {},
      { payTo: "0x00000000000000000000000000000000000fee02" },
      0n,
    ],
    ["cap_per_call", { amount: "10001" }, {}, 0n],
    ["cap_per_day", {}, {}, 12001n],
  ])("%s", (code, over, capOver, spent) => {
    expect(
      refusal(() =>
        selectWithinCaps(
          readPaymentRequired(required(over)),
          { ...caps, ...capOver },
          { ...ctx, spentTodayAtomic: spent },
        ),
      ),
    ).toBe(code);
  });

  it("cap_resource: requirements for a different URL", () => {
    expect(
      refusal(() =>
        selectWithinCaps(readPaymentRequired(required()), caps, {
          ...ctx,
          resourceUrl: "https://canopy.example.test/register/other/grants",
        }),
      ),
    ).toBe("cap_resource");
  });

  it("pays on a mainnet only when allowed", () => {
    const main = { ...caps, network: "eip155:8453", allowMainnet: true };
    expect(
      selectWithinCaps(
        readPaymentRequired(required({ network: "eip155:8453" })),
        main,
        ctx,
      ).network,
    ).toBe("eip155:8453");
  });
});

describe("readPaymentPayload", () => {
  it("summarises an exact EVM payload without its signature", () => {
    const s = readPaymentPayload({
      x402Version: 2,
      accepted: { network: DEFAULT_PAY_NETWORK, asset: DEFAULT_PAY_ASSET },
      payload: {
        signature: "0xsig",
        authorization: {
          from: "0x1",
          to: PAY_TO,
          value: "8000",
          validAfter: "0",
          validBefore: "99",
          nonce: "0x2",
        },
      },
    });
    expect(s).toEqual({
      network: DEFAULT_PAY_NETWORK,
      asset: DEFAULT_PAY_ASSET,
      from: "0x1",
      to: PAY_TO,
      value: "8000",
      nonce: "0x2",
      validBefore: "99",
    });
    expect(JSON.stringify(s)).not.toContain("0xsig");
  });

  it("refuses something else", () => {
    expect(refusal(() => readPaymentPayload({ x402Version: 2 }))).toBe(
      "invalid_payment",
    );
  });
});
