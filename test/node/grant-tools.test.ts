/**
 * issue_grant and register_grant through the real MCP server over the SDK's
 * in-memory transport. canopy's register-grant endpoint is played by
 * `grantEndpoint` over the recorded paid-grant exchanges, with the stub
 * facilitator deciding whether a payment is admitted; everything else goes
 * through `createReplay`. The unit project's forbidden-fetch global stays in
 * force underneath.
 */
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  decodeCborDeterministic,
  decodeCoseSign1,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import { signGrantPayloadWithEs256Pem } from "@forestrie/grant-builder";
import { decodeForestrieGrantCose } from "@forestrie/receipt-verify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "../../src/core/base64.js";
import { inspectGrant, statementGrantProblems } from "../../src/core/grant.js";
import { toHex } from "../../src/core/hex.js";
import { grantContent } from "../../src/core/issue.js";
import { grantPaymentNonce } from "../../src/core/x402.js";
import type { Es256Signer } from "../../src/core/signer.js";
import { evmPayer, type PayerBackend } from "../../src/node/payer.js";
import { createServer } from "../../src/node/server.js";
import { SpendLedger } from "../../src/node/ledger.js";
import { createReplay, type Exchange, type Replay } from "../net/replay.js";
import {
  PAID_GRANT_DIR,
  amount,
  authorityGrantPath,
  challengeWith,
  freeAuthorityGrantPath,
  grantReceiptUrl,
  grantStatusUrl,
  grantsUrl,
  pg,
  pgBytes,
  pgSigner,
  pgx,
} from "../net/paid-grant-fixture.js";
import {
  grantEndpoint,
  decodeB64Json,
  type GrantEndpoint,
} from "../net/stub-facilitator.js";
import {
  grantPath as dataLogGrantPath,
  jwkSigner,
  logKeyXY,
} from "../net/write-path-fixture.js";

type Structured = Record<string, any>;

/** 2026-10-11T12:00:00Z: inside every authorisation's validity window. */
const NOW = new Date("2026-10-11T12:00:00Z");
const nowSeconds = () => Math.floor(NOW.getTime() / 1000);

const CAPS = {
  MCP_REGISTER_PAY_MAX_PER_CALL: "10000",
  MCP_REGISTER_PAY_MAX_PER_DAY: "20000",
};

let home: string;
let client: Client | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "mcp-register-grant-test-"));
});
afterEach(async () => {
  await client?.close();
  client = undefined;
  rmSync(home, { recursive: true, force: true });
});

interface Setup {
  /** Replayed exchanges for every URL but the register-grant one. */
  exchanges?: Exchange[];
  challenge?: Exchange;
  refused?: Exchange;
  accepted?: Exchange;
  answers?: Array<Exchange | Error>;
  gated?: boolean;
  env?: Record<string, string>;
  payer?: PayerBackend | null;
  /** Omit for the paid-grant fixture's authority key. */
  authoritySigner?: Es256Signer | null;
  now?: () => Date;
}

async function connect(opts: Setup = {}): Promise<{
  call: (name: string, args?: Record<string, unknown>) => Promise<Structured>;
  replay: Replay;
  endpoint: GrantEndpoint;
}> {
  const replay = createReplay(opts.exchanges ?? []);
  const endpoint = grantEndpoint({
    url: grantsUrl,
    challenge: opts.challenge ?? pgx("register-grant-402"),
    refused: opts.refused ?? pgx("register-grant-402-refused"),
    accepted: opts.accepted ?? pgx("register-grant-303"),
    rest: replay.fetch,
    nowSeconds,
    ...(opts.gated !== undefined ? { gated: opts.gated } : {}),
    ...(opts.answers !== undefined ? { answers: opts.answers } : {}),
  });
  const authority =
    opts.authoritySigner === null
      ? undefined
      : (opts.authoritySigner ?? (await pgSigner()));
  const server = createServer({
    fetchImpl: endpoint.fetch,
    env: {
      FORESTRIE_BASE_URL: pg.baseUrl,
      FORESTRIE_ROOT_LOG_ID: pg.rootLogId,
      FORESTRIE_AUTHORITY_GRANT: authorityGrantPath,
      ...(opts.env ?? {}),
    },
    home,
    signer: await jwkSigner(),
    ...(authority !== undefined ? { authoritySigner: authority } : {}),
    ...(opts.payer ? { payer: opts.payer } : {}),
    now: opts.now ?? (() => NOW),
    sleep: async () => {},
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "mcp-register-grant-test", version: "0" });
  await client.connect(clientTransport);
  return {
    replay,
    endpoint,
    call: async (name, args = {}) => {
      const res = (await client!.callTool({ name, arguments: args })) as {
        structuredContent?: Structured;
        isError?: boolean;
      };
      expect(res.isError).toBeFalsy();
      return res.structuredContent as Structured;
    },
  };
}

const payer = () => evmPayer(pg.payerPrivateKey, "test payer (Anvil #0)");

async function issue(
  call: (n: string, a?: Record<string, unknown>) => Promise<Structured>,
  extra: Record<string, unknown> = {},
): Promise<Structured> {
  const r = await call("issue_grant", {
    maxHeight: pg.maxHeight,
    logId: pg.childLogId,
    ...extra,
  });
  expect(r["problem"]).toBeUndefined();
  return r;
}

function ledgerLines(): string[] {
  const dir = path.join(home, "payments");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((f) =>
    readFileSync(path.join(dir, f), "utf8").trim().split("\n").filter(Boolean),
  );
}

/* ------------------------------ issue_grant ----------------------------- */

describe("issue_grant", () => {
  it("signs a data-log creation grant under the authority log, with the authority key, naming this server's log key", async () => {
    const { call, replay, endpoint } = await connect();
    const r = await issue(call);
    expect(r).toMatchObject({
      state: "issued",
      logId: pg.childLogId,
      ownerLogId: pg.authorityLogId,
      maxHeight: pg.maxHeight,
      granteeHex: toHex(logKeyXY),
      issuedHere: true,
      parentRequiresPayment: true,
      flagsHex: "0000000300000002",
    });
    // Nothing is sent.
    expect(replay.calls).toHaveLength(0);
    expect(endpoint.posts).toHaveLength(0);

    const grant = base64ToBytes(r["grantBase64"]);
    const decoded = decodeForestrieGrantCose(grant);
    const view = inspectGrant(grant);
    expect(toHex(view.grantData)).toBe(toHex(logKeyXY));
    expect(view).toMatchObject({
      logId: pg.childLogId,
      ownerLogId: pg.authorityLogId,
      maxHeight: pg.maxHeight,
      dataLogStatementGrant: true,
      createAndExtend: true,
    });
    expect(decoded.grant.maxHeight).toBe(pg.maxHeight);

    // The COSE payload is sha256(grant v0 CBOR), signed by the authority key.
    const sign1 = decodeCoseSign1(grant)!;
    const grantCbor = (sign1.unprotected as Map<number, unknown>).get(
      -65538,
    ) as Uint8Array;
    expect(toHex(sign1.payloadBstr)).toBe(
      createHash("sha256").update(grantCbor).digest("hex"),
    );
    const authorityXY = await (await pgSigner()).publicKeyXY();
    expect(
      await verifyCoseSign1WithParsedKey(grant, {
        x: authorityXY.slice(0, 32),
        y: authorityXY.slice(32),
        curve: "P-256",
      }),
    ).toBe(true);
    // Byte for byte the reference: @forestrie/grant-builder's ES256 PEM
    // profile over the same grant and key, but for the ECDSA signature
    // (randomised), which is the last 64 bytes of both.
    const { warning: _w, ...authorityJwk } = JSON.parse(
      readFileSync(
        path.join(PAID_GRANT_DIR, "authority-key.jwk.json"),
        "utf8",
      ),
    );
    const pem = createPrivateKey({ key: authorityJwk, format: "jwk" })
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    const reference = signGrantPayloadWithEs256Pem(grantCbor, pem);
    expect(grant.length).toBe(reference.length);
    expect(toHex(grant.slice(0, -64))).toBe(toHex(reference.slice(0, -64)));

    // Saved under the child log id, with the parent.
    const dir = path.join(home, "grants", pg.childLogId);
    expect(readFileSync(path.join(dir, "grant.cose"))).toEqual(
      Buffer.from(grant),
    );
    expect(readFileSync(path.join(dir, "parent.cose"))).toEqual(
      readFileSync(authorityGrantPath),
    );
  });

  it("names another key when grantee is given, and checks its length", async () => {
    const { call } = await connect();
    const other = new Uint8Array(64).fill(7);
    const r = await issue(call, { grantee: bytesToBase64(other) });
    expect(r["granteeHex"]).toBe(toHex(other));
    const bad = await call("issue_grant", {
      maxHeight: 1,
      grantee: bytesToBase64(new Uint8Array(33)),
    });
    expect(bad["problem"]).toMatchObject({ code: "invalid_input" });
  });

  it("makes a fresh child log id by default, and refuses to issue twice for one log", async () => {
    const { call } = await connect();
    const a = await call("issue_grant", { maxHeight: 1 });
    expect(a["logId"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(a["logId"]).not.toBe(pg.childLogId);
    await issue(call);
    const again = await call("issue_grant", {
      maxHeight: 1,
      logId: pg.childLogId,
    });
    expect(again["problem"]).toMatchObject({ code: "already_issued" });
  });

  it("refuses a parent grant that names a different authority key", async () => {
    // The real key-file authority signer: a fresh key the parent does not name.
    const { call } = await connect({ authoritySigner: null });
    const r = await call("issue_grant", { maxHeight: 1 });
    expect(r["problem"]).toMatchObject({ code: "parent_unusable" });
    expect(r["problem"].message).toMatch(/different key/);
  });

  it("refuses a data-log grant as the parent", async () => {
    const { call } = await connect({
      env: { FORESTRIE_AUTHORITY_GRANT: dataLogGrantPath },
    });
    const r = await call("issue_grant", { maxHeight: 1 });
    expect(r["problem"]).toMatchObject({ code: "parent_unusable" });
    expect(r["problem"].message).toMatch(/not an authority-log grant/);
  });

  it("needs a parent grant", async () => {
    const { call } = await connect({
      env: { FORESTRIE_AUTHORITY_GRANT: "" },
    });
    const r = await call("issue_grant", { maxHeight: 1 });
    expect(r["problem"]).toMatchObject({ code: "missing_input" });
  });

  it("keeps a parentGrant path off the key files and the home", async () => {
    const { call } = await connect({ authoritySigner: null });
    await call("get_log_key", { which: "authority" });
    const r = await call("issue_grant", {
      maxHeight: 1,
      parentGrant: path.join(home, "authority-key.jwk"),
    });
    expect(r["problem"]).toMatchObject({ code: "invalid_input" });
    expect(r["problem"].message).toMatch(/inside this server's own home/);
  });
});

/* ------------------------------ relay mode ------------------------------ */

describe("register_grant, relay mode (no payer configured)", () => {
  it("returns canopy's payment requirements and pays nothing", async () => {
    const { call, endpoint } = await connect();
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r).toMatchObject({
      state: "payment_required",
      logId: pg.childLogId,
      resourceUrl: grantsUrl,
      requirements: {
        accepts: [
          {
            scheme: "exact",
            network: pg.network,
            amount,
            asset: pg.asset,
            payTo: pg.payTo,
          },
        ],
      },
    });
    expect(r["paymentRequiredHeader"]).toBe(
      pgx("register-grant-402").headers["x-payment-required"],
    );
    // One POST: the grant, the parent as evidence, no payment.
    expect(endpoint.posts).toHaveLength(1);
    const post = endpoint.posts[0]!;
    expect(post.headers["authorization"]).toMatch(/^Forestrie-Grant /);
    expect(post.headers["content-type"]).toBe("application/cbor");
    expect(post.headers["x-payment"]).toBeUndefined();
    const body = decodeCborDeterministic(post.body) as Map<string, unknown>;
    expect(Buffer.from(body.get("parentGrant") as Uint8Array)).toEqual(
      readFileSync(authorityGrantPath),
    );
    expect(ledgerLines()).toEqual([]);
  });

  it("resumes on a retry carrying X-PAYMENT from the caller's own wallet, and the stub facilitator admits it", async () => {
    const { call, endpoint } = await connect();
    await issue(call);
    const challenge = await call("register_grant", { logId: pg.childLogId });

    // The caller's own wallet, outside this server: the same upstream client.
    const wallet = payer();
    const required = decodeB64Json(challenge["paymentRequiredHeader"]);
    const payment = await wallet.pay({
      required,
      option: required.accepts[0],
      nonce: `0x${"ab".repeat(32)}`,
      nowSeconds: nowSeconds(),
    });

    const r = await call("register_grant", {
      logId: pg.childLogId,
      payment,
    });
    expect(r).toMatchObject({
      state: "accepted",
      statusUrl: grantStatusUrl,
      payment: {
        via: "relay",
        value: amount,
        to: expect.stringMatching(new RegExp(`^${pg.payTo}$`, "i")),
        from: pg.payerAddress,
        network: pg.network,
      },
    });
    expect(endpoint.posts).toHaveLength(2);
    expect(endpoint.posts[1]!.headers["x-payment"]).toBe(payment);
    expect(endpoint.verdicts).toEqual([
      { isValid: true, payer: pg.payerAddress },
    ]);
    // Relay spends nothing of this server's.
    expect(ledgerLines()).toEqual([]);
  });

  it("reports a payment canopy refuses, and registers nothing", async () => {
    const { call, endpoint } = await connect();
    await issue(call);
    const challenge = await call("register_grant", { logId: pg.childLogId });
    const required = decodeB64Json(challenge["paymentRequiredHeader"]);
    // A wallet that signs for the wrong amount.
    const wrong = { ...required.accepts[0], amount: "1" };
    const payment = await payer().pay({
      required,
      option: wrong,
      nonce: `0x${"cd".repeat(32)}`,
      nowSeconds: nowSeconds(),
    });

    const r = await call("register_grant", { logId: pg.childLogId, payment });
    expect(r["problem"]).toMatchObject({
      code: "payment_rejected",
      logId: pg.childLogId,
    });
    expect(r["problem"].message).toMatch(
      /invalid_exact_evm_payload_signature/,
    );
    expect(endpoint.verdicts[0]).toMatchObject({
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_authorization_value",
    });
    const record = JSON.parse(
      readFileSync(
        path.join(home, "grants", pg.childLogId, "record.json"),
        "utf8",
      ),
    );
    expect(record.state).toBe("payment_required");
  });

  it("refuses a payment value that is not an x402 payload before sending it", async () => {
    const { call, endpoint } = await connect();
    await issue(call);
    const r = await call("register_grant", {
      logId: pg.childLogId,
      payment: Buffer.from("{}").toString("base64"),
    });
    expect(r["problem"]).toMatchObject({ code: "invalid_payment" });
    expect(endpoint.posts).toHaveLength(0);
  });
});

/* ------------------------------ payer mode ------------------------------ */

describe("register_grant, payer configured", () => {
  it("answers the 402 challenge by paying within the caps, and canopy admits it", async () => {
    const { call, endpoint } = await connect({ payer: payer(), env: CAPS });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r).toMatchObject({
      state: "accepted",
      statusUrl: grantStatusUrl,
      retryAfterSeconds: 5,
      payment: {
        via: "payer",
        value: amount,
        to: expect.stringMatching(new RegExp(`^${pg.payTo}$`, "i")),
      },
    });
    // Challenge, then the paid retry.
    expect(endpoint.posts).toHaveLength(2);
    expect(endpoint.posts[0]!.headers["x-payment"]).toBeUndefined();
    const xPayment = endpoint.posts[1]!.headers["x-payment"]!;
    expect(decodeB64Json(xPayment)).toMatchObject({
      x402Version: 2,
      accepted: { network: pg.network, amount, payTo: pg.payTo },
      payload: { authorization: { from: pg.payerAddress, value: amount } },
    });
    expect(endpoint.verdicts).toEqual([
      { isValid: true, payer: pg.payerAddress },
    ]);
    // The nonce is the grant's own, and the payment is counted once.
    const expectedNonce = await grantPaymentNonce(
      grantContent(
        readFileSync(path.join(home, "grants", pg.childLogId, "grant.cose")),
      ),
      Buffer.from(pg.payerAddress.slice(2), "hex"),
    );
    expect(decodeB64Json(xPayment).payload.authorization.nonce).toBe(
      expectedNonce,
    );
    const lines = ledgerLines().map((l) => JSON.parse(l));
    expect(lines).toEqual([
      expect.objectContaining({
        amount,
        network: pg.network,
        asset: pg.asset.toLowerCase(),
        payTo: pg.payTo,
        from: pg.payerAddress,
        nonce: expectedNonce,
        logId: pg.childLogId,
      }),
    ]);
    // Nothing secret in the result.
    expect(JSON.stringify(r)).not.toContain(pg.payerPrivateKey.slice(2));
    expect(JSON.stringify(r)).not.toContain(xPayment);
  });

  it("registers a grant under a parent without the payment flag without paying", async () => {
    const { call, endpoint } = await connect({
      payer: payer(),
      env: { ...CAPS, FORESTRIE_AUTHORITY_GRANT: freeAuthorityGrantPath },
      gated: false,
    });
    const issued = await issue(call);
    expect(issued["parentRequiresPayment"]).toBe(false);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["state"]).toBe("accepted");
    expect(r["payment"]).toBeUndefined();
    expect(endpoint.posts).toHaveLength(1);
    expect(ledgerLines()).toEqual([]);
  });

  it("a retry after a lost answer signs with the same nonce, so at most one payment can settle", async () => {
    let now = NOW;
    const { call, endpoint } = await connect({
      payer: payer(),
      env: CAPS,
      answers: [new TypeError("socket hang up")],
      now: () => now,
    });
    await issue(call);
    const lost = await call("register_grant", { logId: pg.childLogId });
    expect(lost["problem"]).toMatchObject({ code: "network" });
    expect(lost["problem"].message).toMatch(/the grant's own nonce/);

    now = new Date(NOW.getTime() + 60_000);
    const resumed = await call("register_grant", { logId: pg.childLogId });
    expect(resumed["state"]).toBe("accepted");
    // challenge, paid (lost), challenge again, paid again: a new
    // authorisation (a later validBefore), the same nonce.
    const paid = endpoint.posts
      .map((p) => p.headers["x-payment"])
      .filter((h): h is string => h !== undefined)
      .map((h) => decodeB64Json(h).payload.authorization);
    expect(paid).toHaveLength(2);
    expect(paid[0].validBefore).not.toBe(paid[1].validBefore);
    expect(paid[1].nonce).toBe(paid[0].nonce);
    // Two ledger lines, one payment counted.
    expect(ledgerLines()).toHaveLength(2);
    expect(
      new SpendLedger(home).spentToday(
        NOW,
        pg.network,
        pg.asset.toLowerCase(),
      ),
    ).toBe(BigInt(amount));
  });

  it("overlapping calls for one grant all sign the same nonce", async () => {
    const { call, endpoint } = await connect({ payer: payer(), env: CAPS });
    await issue(call);
    const results = await Promise.all([
      call("register_grant", { logId: pg.childLogId }),
      call("register_grant", { logId: pg.childLogId }),
      call("register_grant", { logId: pg.childLogId }),
    ]);
    expect(results.some((r) => r["state"] === "accepted")).toBe(true);
    const nonces = new Set(
      endpoint.posts
        .map((p) => p.headers["x-payment"])
        .filter((h): h is string => h !== undefined)
        .map((h) => decodeB64Json(h).payload.authorization.nonce),
    );
    expect(nonces.size).toBe(1);
    expect(
      new SpendLedger(home).spentToday(
        NOW,
        pg.network,
        pg.asset.toLowerCase(),
      ),
    ).toBe(BigInt(amount));
  });

  it("refuses to send a payment that does not carry the grant's nonce", async () => {
    const own = payer();
    const careless: PayerBackend = {
      ...own,
      description: "a wallet that picks its own nonce",
      pay: (req) => own.pay({ ...req, nonce: `0x${"ee".repeat(32)}` }),
    };
    const { call, endpoint } = await connect({ payer: careless, env: CAPS });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["problem"]).toMatchObject({ code: "invalid_payment" });
    expect(r["problem"].message).toMatch(/grant's nonce/);
    expect(endpoint.posts).toHaveLength(1);
    expect(ledgerLines()).toEqual([]);
  });

  it("reports a payer that fails to sign, and counts nothing", async () => {
    const broken: PayerBackend = {
      address: pg.payerAddress,
      description: "a broken wallet",
      pay: async () => {
        throw new Error("wallet locked");
      },
    };
    const { call, endpoint } = await connect({ payer: broken, env: CAPS });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["problem"]).toMatchObject({ code: "payer_failed" });
    expect(r["problem"].message).toMatch(/wallet locked/);
    expect(endpoint.posts).toHaveLength(1);
    expect(ledgerLines()).toEqual([]);
  });

  it("reports canopy's other refusals as problems", async () => {
    const { call } = await connect({
      payer: payer(),
      env: CAPS,
      answers: [pgx("register-grant-409")],
    });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["problem"]).toMatchObject({ code: "http_error", status: 409 });
    expect(r["problem"].message).toMatch(/global uniqueness/);
  });

  it("refuses to pay without both caps configured", async () => {
    const { call, endpoint } = await connect({
      payer: payer(),
      env: { MCP_REGISTER_PAY_MAX_PER_CALL: "10000" },
    });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["problem"]).toMatchObject({ code: "payer_misconfigured" });
    expect(r["problem"].message).toMatch(/MCP_REGISTER_PAY_MAX_PER_DAY/);
    expect(endpoint.posts).toHaveLength(1);
  });
});

/* ------------------------------ cap refusals ---------------------------- */

describe("register_grant cap refusals: each refuses before signing anything", () => {
  async function refused(
    setup: Setup,
    code: string,
    args: Record<string, unknown> = {},
  ): Promise<Structured> {
    const { call, endpoint } = await connect({
      payer: payer(),
      ...setup,
      env: { ...CAPS, ...(setup.env ?? {}) },
    });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId, ...args });
    expect(r["problem"]).toMatchObject({ code });
    // Only the challenge went out; nothing was signed or counted.
    expect(endpoint.posts).toHaveLength(1);
    expect(endpoint.verdicts).toHaveLength(0);
    expect(ledgerLines()).toEqual([]);
    return r;
  }

  it("per call", async () => {
    const r = await refused(
      { env: { MCP_REGISTER_PAY_MAX_PER_CALL: "7999" } },
      "cap_per_call",
    );
    expect(r["problem"].message).toMatch(/8000.*7999/);
  });

  it("per day, counting what was already committed today", async () => {
    new SpendLedger(home).record(NOW, {
      at: NOW.toISOString(),
      network: pg.network,
      asset: pg.asset.toLowerCase(),
      amount: "15000",
      payTo: pg.payTo,
      from: pg.payerAddress,
      nonce: "0x01",
      logId: "00000000-0000-4000-8000-000000000000",
    });
    const { call, endpoint } = await connect({ payer: payer(), env: CAPS });
    await issue(call);
    const r = await call("register_grant", { logId: pg.childLogId });
    expect(r["problem"]).toMatchObject({ code: "cap_per_day" });
    expect(r["problem"].message).toMatch(/23000/);
    expect(endpoint.posts).toHaveLength(1);
    expect(ledgerLines()).toHaveLength(1);
  });

  it("per day, across grants, and resets at the next UTC day", async () => {
    let now = NOW;
    const { call, endpoint } = await connect({
      payer: payer(),
      env: { ...CAPS, MCP_REGISTER_PAY_MAX_PER_DAY: "12000" },
      now: () => now,
    });
    await issue(call);
    expect(
      (await call("register_grant", { logId: pg.childLogId }))["state"],
    ).toBe("accepted");
    const second = (await call("issue_grant", { maxHeight: pg.maxHeight }))[
      "logId"
    ];
    const r = await call("register_grant", { logId: second });
    expect(r["problem"]).toMatchObject({ code: "cap_per_day" });

    now = new Date("2026-10-12T00:00:01Z");
    const next = await call("register_grant", { logId: second });
    expect(next["state"]).toBe("accepted");
    expect(endpoint.verdicts.filter((v) => v.isValid)).toHaveLength(2);
    expect(ledgerLines()).toHaveLength(2);
  });

  it("one network", async () => {
    await refused(
      {
        challenge: challengeWith((q) => {
          q.accepts[0].network = "eip155:8453";
        }),
      },
      "cap_network",
    );
  });

  it("one asset", async () => {
    await refused(
      {
        challenge: challengeWith((q) => {
          q.accepts[0].asset = "0x00000000000000000000000000000000000a55e7";
        }),
      },
      "cap_asset",
    );
  });

  it("testnet only by default", async () => {
    const r = await refused(
      {
        env: {
          MCP_REGISTER_PAY_NETWORK: "eip155:8453",
          MCP_REGISTER_PAY_ASSET: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        },
      },
      "cap_testnet_only",
    );
    expect(r["problem"].message).toMatch(/MCP_REGISTER_PAY_ALLOW_MAINNET/);
  });

  it("the configured payee", async () => {
    await refused(
      {
        env: {
          MCP_REGISTER_PAY_TO: "0x00000000000000000000000000000000000fee02",
        },
      },
      "cap_payee",
    );
  });

  it("the resource this server asked for", async () => {
    await refused(
      {
        challenge: challengeWith((q) => {
          q.resource.url = "https://canopy.example.test/register/other/grants";
        }),
      },
      "cap_resource",
    );
  });

  it("only the configured canopy", async () => {
    const elsewhere = "https://elsewhere.example.test";
    const replay = createReplay([
      {
        ...pgx("register-grant-402"),
        url: `${elsewhere}/register/${pg.rootLogId}/grants`,
      },
    ]);
    const server = createServer({
      fetchImpl: replay.fetch,
      env: {
        FORESTRIE_BASE_URL: pg.baseUrl,
        FORESTRIE_ROOT_LOG_ID: pg.rootLogId,
        FORESTRIE_AUTHORITY_GRANT: authorityGrantPath,
        ...CAPS,
      },
      home,
      signer: await jwkSigner(),
      authoritySigner: await pgSigner(),
      payer: payer(),
      now: () => NOW,
    });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    client = new Client({ name: "t", version: "0" });
    await client.connect(ct);
    await client.callTool({
      name: "issue_grant",
      arguments: { maxHeight: pg.maxHeight, logId: pg.childLogId },
    });
    const r = (await client.callTool({
      name: "register_grant",
      arguments: { logId: pg.childLogId, baseUrl: elsewhere },
    })) as { structuredContent: Structured };
    expect(r.structuredContent["problem"]).toMatchObject({
      code: "cap_origin",
    });
    expect(replay.calls).toHaveLength(1);
    expect(ledgerLines()).toEqual([]);
  });
});

/* --------------------------- to the receipt ----------------------------- */

describe("register_grant follows an accepted grant to its receipt", () => {
  it("pending → sequenced → awaiting seal → sealed, then completes the grant", async () => {
    const { call, endpoint, replay } = await connect({
      payer: payer(),
      env: CAPS,
      exchanges: [
        pgx("grant-status-pending"),
        pgx("grant-status-sequenced"),
        pgx("grant-receipt-404"),
        pgx("grant-receipt-200"),
      ],
    });
    await issue(call);
    expect(
      (await call("register_grant", { logId: pg.childLogId }))["state"],
    ).toBe("accepted");

    const pending = await call("register_grant", { logId: pg.childLogId });
    expect(pending).toMatchObject({ state: "accepted", retryAfterSeconds: 2 });

    const awaiting = await call("register_grant", { logId: pg.childLogId });
    expect(awaiting).toMatchObject({
      state: "accepted",
      sealed: false,
      entryId: pg.entryId,
      receiptUrl: grantReceiptUrl,
    });
    expect(awaiting["reason"]).toMatch(/checkpoint missing/);

    const done = await call("register_grant", { logId: pg.childLogId });
    expect(done).toMatchObject({
      state: "complete",
      logId: pg.childLogId,
      entryId: pg.entryId,
      namesThisServer: true,
    });
    expect(replay.remaining()).toBe(0);

    // The completed grant: the signed grant plus its receipt and idtimestamp,
    // and usable for this server's statements.
    const completed = base64ToBytes(done["grantBase64"]);
    const unprotected = decodeCoseSign1(completed)!.unprotected as Map<
      number,
      unknown
    >;
    expect(Buffer.from(unprotected.get(396) as Uint8Array)).toEqual(
      Buffer.from(pgBytes("grant-receipt-200.body")),
    );
    expect(toHex(unprotected.get(-65537) as Uint8Array)).toBe(
      pg.entryId.slice(0, 16),
    );
    const view = inspectGrant(completed);
    expect(view.logId).toBe(pg.childLogId);
    expect(statementGrantProblems(view, logKeyXY)).toEqual([]);

    // Complete is final: no more requests.
    const before = replay.calls.length + endpoint.posts.length;
    expect(
      (await call("register_grant", { logId: pg.childLogId }))["state"],
    ).toBe("complete");
    expect(replay.calls.length + endpoint.posts.length).toBe(before);
  });

  it("registers a grant signed elsewhere, and refuses a different grant for the same log", async () => {
    const { call } = await connect({ gated: false });
    const issued = await issue(call);
    // A second server-free copy: the same grant passed inline resumes it.
    const same = await call("register_grant", {
      grant: issued["grantBase64"],
    });
    expect(same["state"]).toBe("accepted");
    const other = await call("register_grant", {
      grant: bytesToBase64(readFileSync(dataLogGrantPath)),
      logId: pg.childLogId,
    });
    expect(other["problem"]).toMatchObject({ code: "invalid_input" });
  });
});

/* ------------------------------- keys ----------------------------------- */

describe("the authority key and the payer key", () => {
  it("get_log_key which: authority is a separate key, with an SPKI PEM", async () => {
    const { call } = await connect({ authoritySigner: null });
    const log = await call("get_log_key");
    const auth = await call("get_log_key", { which: "authority" });
    expect(auth).toMatchObject({ which: "authority", created: true });
    expect(auth["publicKeyXYHex"]).not.toBe(log["publicKeyXYHex"]);
    const jwk = createPublicKey(auth["publicKeyPem"]).export({
      format: "jwk",
    });
    expect(
      Buffer.concat([
        Buffer.from(jwk.x!, "base64url"),
        Buffer.from(jwk.y!, "base64url"),
      ]).toString("hex"),
    ).toBe(auth["publicKeyXYHex"]);
    expect(existsSync(path.join(home, "authority-key.jwk"))).toBe(true);
    expect(JSON.stringify(auth)).not.toMatch(/"d"/);
  });

  it("delegate_sealing as: authority checks the authority grant against the authority key", async () => {
    const { call } = await connect({
      authoritySigner: null,
      env: {
        FORESTRIE_COORDINATOR_URL: pg.coordinatorUrl,
        FORESTRIE_KNOWN_SEALER_KEY: bytesToBase64(new Uint8Array(64).fill(1)),
      },
    });
    const r = await call("delegate_sealing", { as: "authority" });
    expect(r["problem"]).toMatchObject({ code: "grant_unusable" });
    expect(r["problem"].message).toMatch(/authority key/);
    expect(r["problem"].message).toContain(pg.authorityLogId);
  });

  it("keeps every {path} input off the payer key file", async () => {
    const keyFile = path.join(
      mkdtempSync(path.join(tmpdir(), "payer-")),
      "payer.key",
    );
    writeFileSync(keyFile, `${pg.payerPrivateKey}\n`, { mode: 0o600 });
    const { call } = await connect({
      env: {
        MCP_REGISTER_PAYER_KEY_FILE: keyFile,
        FORESTRIE_GRANT: dataLogGrantPath,
      },
    });
    const r = await call("register_statement", {
      payload: { path: keyFile },
      contentType: "text/plain",
    });
    expect(r["problem"]).toMatchObject({ code: "invalid_input" });
    rmSync(path.dirname(keyFile), { recursive: true, force: true });
  });

  it("pays from MCP_REGISTER_PAYER_KEY_FILE, and refuses a loose or linked key file", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "payer-"));
    try {
      const keyFile = path.join(dir, "payer.key");
      writeFileSync(keyFile, `${pg.payerPrivateKey}\n`);
      chmodSync(keyFile, 0o644);
      const loose = await connect({
        env: { ...CAPS, MCP_REGISTER_PAYER_KEY_FILE: keyFile },
      });
      await issue(loose.call);
      const r = await loose.call("register_grant", { logId: pg.childLogId });
      expect(r["problem"]).toMatchObject({ code: "payer_unavailable" });
      expect(r["problem"].message).toMatch(/chmod 600/);
      await client?.close();
      rmSync(path.join(home, "grants"), { recursive: true, force: true });

      const link = path.join(dir, "link.key");
      symlinkSync(keyFile, link);
      chmodSync(keyFile, 0o600);
      const linked = await connect({
        env: { ...CAPS, MCP_REGISTER_PAYER_KEY_FILE: link },
      });
      await issue(linked.call);
      const l = await linked.call("register_grant", { logId: pg.childLogId });
      expect(l["problem"]).toMatchObject({ code: "payer_unavailable" });
      await client?.close();
      rmSync(path.join(home, "grants"), { recursive: true, force: true });

      const good = await connect({
        env: { ...CAPS, MCP_REGISTER_PAYER_KEY_FILE: keyFile },
      });
      await issue(good.call);
      const g = await good.call("register_grant", { logId: pg.childLogId });
      expect(g["state"]).toBe("accepted");
      expect(g["payment"]).toMatchObject({ from: pg.payerAddress });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
