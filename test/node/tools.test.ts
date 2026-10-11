/**
 * The tool handlers, through the real MCP server over the SDK's in-memory
 * transport. Every network call goes through `createReplay`'s fetch, built
 * from recorded exchanges (synthetic/write-path for the write path, the real
 * lane-a-0.5.0 recordings for the read side); the unit project's
 * forbidden-fetch global stays in force underneath.
 */
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { verifyCoseSign1WithParsedKey } from "@forestrie/encoding";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { base64ToBytes, bytesToBase64 } from "../../src/core/base64.js";
import { toHex } from "../../src/core/hex.js";
import type { Es256Signer } from "../../src/core/signer.js";
import { createServer } from "../../src/node/server.js";
import { RegistrationStore } from "../../src/node/store.js";
import {
  createReplay,
  loadExchange,
  type Exchange,
  type Replay,
} from "../net/replay.js";
import {
  LANE_A_DIR,
  WRITE_PATH_DIR,
  coordinates as c,
  ex,
  grantOtherKeyPath,
  grantPath,
  jwkSigner,
  logKeyXY,
  registrarKeyXY,
} from "../net/write-path-fixture.js";

type Structured = Record<string, any>;

const sha256Hex = (b: Uint8Array) =>
  createHash("sha256").update(b).digest("hex");

const registerUrl = `${c.baseUrl}/register/${c.rootLogId}/entries`;
const statusUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/entries/${c.statusEntryHash}`;
const receiptUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/${c.massifHeight}/entries/${c.entryId}/receipt`;
const prepareUrl = `${c.baseUrl}/api/forest/${c.dataLogId}/prepare`;
const pendingUrl = `${c.coordinatorUrl}/api/logs/${c.dataLogId}/pending-delegation`;
const certUrl = `${c.coordinatorUrl}/api/delegations/certificate`;

let home: string;
let client: Client | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "mcp-register-test-"));
});
afterEach(async () => {
  await client?.close();
  client = undefined;
  rmSync(home, { recursive: true, force: true });
});

async function connect(opts: {
  exchanges: Exchange[];
  /** Omit to use the real key-file signer, in this test's temp home. */
  signer?: Es256Signer;
  env?: Record<string, string>;
}): Promise<{
  call: (name: string, args?: Record<string, unknown>) => Promise<Structured>;
  replay: Replay;
  raw: (name: string, args?: Record<string, unknown>) => Promise<unknown>;
}> {
  const replay = createReplay(opts.exchanges);
  const sleeps: number[] = [];
  const server = createServer({
    fetchImpl: replay.fetch,
    env: {
      FORESTRIE_BASE_URL: c.baseUrl,
      FORESTRIE_ROOT_LOG_ID: c.rootLogId,
      FORESTRIE_GRANT: grantPath,
      FORESTRIE_COORDINATOR_URL: c.coordinatorUrl,
      FORESTRIE_KNOWN_SEALER_KEY: bytesToBase64(registrarKeyXY),
      ...(opts.env ?? {}),
    },
    home,
    ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "mcp-register-test", version: "0" });
  await client.connect(clientTransport);
  const raw = (name: string, args: Record<string, unknown> = {}) =>
    client!.callTool({ name, arguments: args });
  return {
    replay,
    raw,
    call: async (name, args = {}) => {
      const res = (await raw(name, args)) as {
        structuredContent?: Structured;
        isError?: boolean;
      };
      expect(res.isError).toBeFalsy();
      return res.structuredContent as Structured;
    },
  };
}

const payload = new TextEncoder().encode('{"artefact":"sha256:abc"}');
const payloadArg = { b64: bytesToBase64(payload) };

describe("get_log_key", () => {
  it("returns the public key and no private material", async () => {
    const signer = await jwkSigner();
    const { raw, call } = await connect({ exchanges: [], signer });
    const out = await call("get_log_key");
    expect(out["publicKeyXYHex"]).toBe(toHex(logKeyXY));
    expect(out["publicKeyXYBase64"]).toBe(bytesToBase64(logKeyXY));
    expect(out["statementKidHex"]).toBe(toHex(logKeyXY.slice(0, 32)));
    expect(out["alg"]).toBe("ES256");

    const whole = JSON.stringify(await raw("get_log_key"));
    const jwk = JSON.parse(
      readFileSync(path.join(WRITE_PATH_DIR, "log-key.jwk.json"), "utf8"),
    ) as { d: string };
    expect(whole).not.toContain(jwk.d);
    expect(whole).not.toContain(
      Buffer.from(jwk.d, "base64url").toString("hex"),
    );
    expect(whole).not.toContain(
      Buffer.from(jwk.d, "base64url").toString("base64"),
    );
    expect(whole).not.toMatch(/"d"\s*:/);
  });
});

describe("register_statement and check_registration", () => {
  it("signs, registers, then walks pending, awaiting_seal and sealed", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [
        ex("register-303"),
        ex("status-pending"),
        ex("status-sequenced"),
        ex("receipt-404"),
        ex("receipt-200"),
      ],
    });
    const reg = await call("register_statement", {
      payload: payloadArg,
      contentType: "application/json",
    });
    expect(reg["state"]).toBe("accepted");

    const post = replay.callsTo("POST", registerUrl);
    expect(post).toHaveLength(1);
    const sent = post[0]!;
    expect(sent.headers["content-type"]).toBe("application/cose");
    expect(sent.headers["authorization"]).toBe(
      `Forestrie-Grant ${bytesToBase64(new Uint8Array(readFileSync(grantPath)))}`,
    );
    expect(
      await verifyCoseSign1WithParsedKey(sent.body, {
        x: logKeyXY.slice(0, 32),
        y: logKeyXY.slice(32),
        curve: "P-256",
      }),
    ).toBe(true);
    expect(reg["contentHash"]).toBe(sha256Hex(sent.body));
    expect(reg["statusUrl"]).toBe(statusUrl);
    expect(reg["logId"]).toBe(c.dataLogId);
    expect(reg["retryAfterSeconds"]).toBe(5);
    expect(reg["statementBytes"]).toBe(sent.body.length);
    expect(new Uint8Array(readFileSync(reg["statementPath"]))).toEqual(
      sent.body,
    );

    const hash = reg["contentHash"] as string;
    const pending = await call("check_registration", { contentHash: hash });
    expect(pending).toMatchObject({
      state: "pending",
      contentHash: hash,
      retryAfterSeconds: 1,
    });

    const awaiting = await call("check_registration", { contentHash: hash });
    expect(awaiting).toMatchObject({
      state: "awaiting_seal",
      entryId: c.entryId,
      massifHeight: c.massifHeight,
      receiptUrl,
    });

    const sealed = await call("check_registration", { contentHash: hash });
    expect(sealed).toMatchObject({ state: "sealed", entryId: c.entryId });
    expect(new Uint8Array(readFileSync(sealed["receiptPath"]))).toEqual(
      ex("receipt-200").body,
    );

    // A sealed registration is answered from the store: no further request.
    const before = replay.calls.length;
    const again = await call("check_registration", { contentHash: hash });
    expect(again["state"]).toBe("sealed");
    expect(replay.calls.length).toBe(before);
    expect(replay.remaining()).toBe(0);
  });

  it("refuses a grant naming another key before any request", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
      env: { FORESTRIE_GRANT: grantOtherKeyPath },
    });
    const out = await call("register_statement", {
      payload: payloadArg,
      contentType: "application/json",
    });
    expect(out["problem"]).toMatchObject({ code: "grant_unusable" });
    expect(out["problem"].message).toMatch(/different key/);
    expect(replay.calls).toHaveLength(0);
  });

  it("surfaces canopy's CBOR refusal as http_error", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [ex("register-403")],
    });
    const out = await call("register_statement", {
      payload: payloadArg,
      contentType: "application/json",
    });
    expect(out["problem"]).toMatchObject({
      code: "http_error",
      status: 403,
      title: "Forbidden",
      reason: "signer_mismatch",
    });
    expect(out["problem"].message).toContain("Forbidden");
    expect(replay.calls).toHaveLength(1);
    // Saved before sending, so the handle survives whatever canopy answers.
    expect(readFileSync(out["problem"].statementPath)).toEqual(
      Buffer.from(replay.calls[0]!.body),
    );
    expect(out["problem"].contentHash).toBe(sha256Hex(replay.calls[0]!.body));
  });

  it("reports missing inputs without a request", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
      env: { FORESTRIE_BASE_URL: "" },
    });
    const out = await call("register_statement", {
      payload: payloadArg,
      contentType: "application/json",
    });
    expect(out["problem"]).toMatchObject({ code: "missing_input" });
    expect(replay.calls).toHaveLength(0);
  });

  it("reports an unknown registration", async () => {
    const { call } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
    });
    const out = await call("check_registration", {
      contentHash: "0".repeat(64),
    });
    expect(out["problem"]).toMatchObject({ code: "unknown_registration" });
  });
});

describe("a real recorded registration (lane-a-0.5.0)", () => {
  const lane = JSON.parse(
    readFileSync(path.join(LANE_A_DIR, "coordinates.json"), "utf8"),
  ) as {
    baseUrl: string;
    bootstrapLogId: string;
    publicationsLogId: string;
    contentHashSha256: string;
    entryId: string;
    massifHeight: number;
    receiptUrl: string;
  };
  const laneKeyXY = base64ToBytes(
    readFileSync(path.join(LANE_A_DIR, "log-key.xy.b64"), "utf8").trim(),
  );

  /** A signer that can only name the lane's key: verify must never sign. */
  const verifyOnlySigner: Es256Signer = {
    description: "lane-a-0.5.0 log key (public half only)",
    publicKeyXY: async () => laneKeyXY.slice(),
    sign: async () => {
      throw new Error("verify_registration must not sign");
    },
  };

  it("checks to sealed over the real status and receipt, then verifies", async () => {
    const statusSelf = loadExchange(LANE_A_DIR, "status-self");
    const receiptSelf = loadExchange(
      LANE_A_DIR,
      "receipt-self",
      "receipt-self.cbor",
    );
    const statement = new Uint8Array(
      readFileSync(path.join(LANE_A_DIR, "statement.cose")),
    );
    expect(sha256Hex(statement)).toBe(lane.contentHashSha256);

    const store = new RegistrationStore(home);
    store.saveStatement(
      {
        contentHash: lane.contentHashSha256,
        state: "accepted",
        statusUrl: statusSelf.url,
        baseUrl: lane.baseUrl,
        rootLogId: lane.bootstrapLogId,
        logId: lane.publicationsLogId,
        contentType: "application/cose",
        issuer: "lane-a-0.5.0",
        subject: "lane-a-0.5.0",
        signedAt: "2026-09-22T19:58:31Z",
        acceptedAt: "2026-09-22T19:58:32Z",
      },
      statement,
    );

    const { call, replay } = await connect({
      signer: verifyOnlySigner,
      exchanges: [statusSelf, receiptSelf],
    });
    const sealed = await call("check_registration", {
      contentHash: lane.contentHashSha256,
    });
    expect(sealed).toMatchObject({
      state: "sealed",
      entryId: lane.entryId,
      massifHeight: lane.massifHeight,
      receiptUrl: lane.receiptUrl,
      receiptBytes: 438,
    });
    expect(replay.calls.map((x) => `${x.method} ${x.url}`)).toEqual([
      `GET ${statusSelf.url}`,
      `GET ${lane.receiptUrl}`,
    ]);

    const verified = await call("verify_registration", {
      contentHash: lane.contentHashSha256,
    });
    expect(verified["root"]).toBe("known-log-key");
    expect(verified["entryId"]).toBe(lane.entryId);
    // The verifier's answers pass through unaltered; see the console dump in
    // the assertions below for what it returns on this lane.
    const result = verified["result"] as Structured;
    expect(result["ok"]).toBe(true);
    const questions = result["questions"] as Structured;
    expect(questions["sealing"]).toMatchObject({ status: "ok" });
    expect(questions["attribution"]).toMatchObject({ status: "ok" });
    expect(questions["split-view"]).toMatchObject({
      status: "not_answered_by_this_root",
    });
    expect(questions).toHaveProperty("append-authority");
  });
});

describe("delegate_sealing", () => {
  it("prepares, polls and posts the certificate end to end", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [
        ex("pending-empty"),
        ex("prepare-201"),
        ex("pending-standing"),
        ex("certificate-200"),
      ],
    });
    const out = await call("delegate_sealing");
    expect(out).toMatchObject({
      state: "delegated",
      logId: c.dataLogId,
      sealerId: c.sealerId,
      epoch: c.epoch,
      prepared: true,
    });
    const prepare = replay.callsTo("POST", prepareUrl)[0]!;
    expect(prepare.headers["authorization"]).toMatch(/^Forestrie-Grant /);
    expect(prepare.body).toHaveLength(0);
    expect(replay.callsTo("POST", certUrl)).toHaveLength(1);
    expect(replay.callsTo("GET", pendingUrl)).toHaveLength(2);
  });

  it("refuses a grant that names another key without a request", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
      env: { FORESTRIE_GRANT: grantOtherKeyPath },
    });
    const out = await call("delegate_sealing");
    expect(out["problem"]).toMatchObject({ code: "grant_unusable" });
    expect(replay.calls).toHaveLength(0);
  });

  it("reports a bad voucher as voucher_failed", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [ex("pending-standing-bad-voucher")],
    });
    const out = await call("delegate_sealing");
    expect(out["problem"]).toMatchObject({
      code: "voucher_failed",
      stage: "voucher",
    });
    expect(replay.callsTo("POST", certUrl)).toHaveLength(0);
  });

  it("rejects a known sealer key that is not 64 bytes", async () => {
    const { call } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
      env: {
        FORESTRIE_KNOWN_SEALER_KEY: bytesToBase64(registrarKeyXY.slice(0, 32)),
      },
    });
    const out = await call("delegate_sealing");
    expect(out["problem"]).toMatchObject({ code: "invalid_input" });
  });
});

describe("review hardening", () => {
  it("refuses a payload path that is the log key or inside the home, before any request", async () => {
    const { call, replay } = await connect({ exchanges: [] });
    const key = await call("get_log_key");
    expect(key["created"]).toBe(true);
    const keyFile = path.join(home, "log-key.jwk");
    for (const p of [keyFile, home, path.join(home, "registrations")]) {
      const out = await call("register_statement", {
        payload: { path: p },
        contentType: "application/json",
      });
      expect(out["problem"]?.code, p).toBe("invalid_input");
    }
    const acc = await call("verify_registration", {
      contentHash: "0".repeat(64),
      knownAccumulator: { path: keyFile },
    });
    expect(acc["problem"]).toBeDefined();
    expect(replay.calls).toHaveLength(0);
  });

  it("reports the key as created once, and never leaks the private half in any result", async () => {
    const { raw, call } = await connect({ exchanges: [] });
    const first = await call("get_log_key");
    const second = await call("get_log_key");
    expect(first["created"]).toBe(true);
    expect(second["created"]).toBe(false);
    expect(second["publicKeyXYHex"]).toBe(first["publicKeyXYHex"]);
    const jwk = JSON.parse(
      readFileSync(path.join(home, "log-key.jwk"), "utf8"),
    ) as { d: string };
    const everything = JSON.stringify([
      first,
      second,
      await raw("get_log_key"),
      await raw("register_statement", {
        payload: payloadArg,
        contentType: "application/json",
        baseUrl: "",
      }),
    ]);
    expect(everything).not.toContain(jwk.d);
  });

  it("verify_registration never creates a key", async () => {
    const store = new RegistrationStore(home);
    const hash = "a".repeat(64);
    store.saveStatement(
      {
        contentHash: hash,
        state: "accepted",
        statusUrl,
        baseUrl: c.baseUrl,
        rootLogId: c.rootLogId,
        logId: c.dataLogId,
        contentType: "application/json",
        issuer: "i",
        subject: "s",
        signedAt: "2026-10-11T00:00:00Z",
        entryId: c.entryId,
        sealedAt: "2026-10-11T00:01:00Z",
      },
      payload,
    );
    store.saveReceipt(hash, new Uint8Array([0xd2]));
    const { call } = await connect({ exchanges: [] });
    const out = await call("verify_registration", { contentHash: hash });
    expect(out["problem"]?.code).toBe("signer_unavailable");
    expect(existsSync(path.join(home, "log-key.jwk"))).toBe(false);
  });

  it("turns a directory grant, a corrupt record and a missing statement into problems", async () => {
    const dirGrant = path.join(home, "..", `grant-dir-${process.pid}`);
    mkdirSync(dirGrant, { recursive: true });
    try {
      const { call } = await connect({
        signer: await jwkSigner(),
        exchanges: [],
        env: { FORESTRIE_GRANT: dirGrant },
      });
      const out = await call("register_statement", {
        payload: payloadArg,
        contentType: "application/json",
      });
      expect(out["problem"]?.code).toBe("invalid_input");
    } finally {
      rmSync(dirGrant, { recursive: true, force: true });
    }

    const hash = "b".repeat(64);
    const dir = path.join(home, "registrations", hash);
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "record.json"), "null");
    const { call } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
    });
    expect(
      (await call("check_registration", { contentHash: hash }))["problem"]
        ?.code,
    ).toBe("corrupt_record");

    const store = new RegistrationStore(home);
    const hash2 = "c".repeat(64);
    store.saveStatement(
      {
        contentHash: hash2,
        state: "accepted",
        statusUrl,
        baseUrl: c.baseUrl,
        rootLogId: c.rootLogId,
        logId: c.dataLogId,
        contentType: "application/json",
        issuer: "i",
        subject: "s",
        signedAt: "2026-10-11T00:00:00Z",
        entryId: c.entryId,
        sealedAt: "2026-10-11T00:01:00Z",
      },
      payload,
    );
    store.saveReceipt(hash2, new Uint8Array([0xd2]));
    rmSync(store.statementPath(hash2));
    expect(
      (await call("verify_registration", { contentHash: hash2 }))["problem"]
        ?.code,
    ).toBe("store_failed");
  });

  it("keeps the handle when the POST fails, and check_registration finds it by its derived status URL", async () => {
    const { call, replay } = await connect({
      signer: await jwkSigner(),
      exchanges: [],
    });
    const out = await call("register_statement", {
      payload: payloadArg,
      contentType: "application/json",
    });
    // The replay has nothing for the POST: a network-level failure.
    expect(out["problem"]?.code).toBe("network");
    const hash = out["problem"].contentHash as string;
    expect(existsSync(out["problem"].statementPath)).toBe(true);
    const record = JSON.parse(
      readFileSync(
        path.join(home, "registrations", hash, "record.json"),
        "utf8",
      ),
    );
    expect(record).toMatchObject({ state: "signed", contentHash: hash });
    expect(record.statusUrl).toBeUndefined();
    expect(replay.calls.map((x) => x.method)).toEqual(["POST"]);

    // No status URL was ever returned; check_registration derives it.
    const derived = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/entries/${hash}`;
    const again = await connect({
      signer: await jwkSigner(),
      exchanges: [{ ...ex("status-pending"), url: derived }],
    });
    const pending = await again.call("check_registration", {
      contentHash: hash,
    });
    expect(pending).toMatchObject({ state: "pending" });
    expect(again.replay.calls[0]!.url).toBe(derived);
  });

  it("warns once a registration has been pending for ten minutes", async () => {
    const store = new RegistrationStore(home);
    const hash = "d".repeat(64);
    store.saveStatement(
      {
        contentHash: hash,
        state: "accepted",
        statusUrl,
        baseUrl: c.baseUrl,
        rootLogId: c.rootLogId,
        logId: c.dataLogId,
        contentType: "application/json",
        issuer: "i",
        subject: "s",
        signedAt: "2026-10-11T00:00:00Z",
        firstPendingAt: "2000-01-01T00:00:00Z",
      },
      payload,
    );
    const { call } = await connect({
      signer: await jwkSigner(),
      exchanges: [ex("status-pending")],
    });
    const out = await call("check_registration", { contentHash: hash });
    expect(out).toMatchObject({ state: "pending", stale: true });
  });
});

describe("the key-file signer (src/node/signer-file.ts)", () => {
  it("creates nothing until a tool needs the key, then 0600 in a 0700 dir, and never overwrites", async () => {
    const keyFile = path.join(home, "log-key.jwk");
    await connect({ exchanges: [] });
    expect(existsSync(keyFile)).toBe(false);

    const { openKeyFileSigner } =
      await import("../../src/node/signer-file.js");
    const nested = path.join(home, "nested", "log-key.jwk");
    const a = await openKeyFileSigner(nested);
    expect(a.created).toBe(true);
    expect(statSync(nested).mode & 0o777).toBe(0o600);
    expect(statSync(path.dirname(nested)).mode & 0o777).toBe(0o700);
    const before = readFileSync(nested, "utf8");
    const b = await openKeyFileSigner(nested);
    expect(b.created).toBe(false);
    expect(readFileSync(nested, "utf8")).toBe(before);
    expect(toHex(await b.publicKeyXY())).toBe(toHex(await a.publicKeyXY()));
  });

  it("refuses a key readable by others, a symlinked key, and a missing key without create", async () => {
    const { openKeyFileSigner } =
      await import("../../src/node/signer-file.js");
    const keyFile = path.join(home, "k.jwk");
    await openKeyFileSigner(keyFile);
    chmodSync(keyFile, 0o644);
    await expect(openKeyFileSigner(keyFile)).rejects.toThrow(/other users/);
    chmodSync(keyFile, 0o600);

    const { symlinkSync } = await import("node:fs");
    const link = path.join(home, "link.jwk");
    symlinkSync(keyFile, link);
    await expect(openKeyFileSigner(link)).rejects.toThrow(
      /not a regular file/,
    );
    const dangling = path.join(home, "dangling.jwk");
    symlinkSync(path.join(home, "nowhere"), dangling);
    await expect(openKeyFileSigner(dangling)).rejects.toThrow(
      /not a regular file/,
    );

    await expect(
      openKeyFileSigner(path.join(home, "absent.jwk"), { create: false }),
    ).rejects.toThrow(/no log key/);
    expect(existsSync(path.join(home, "absent.jwk"))).toBe(false);
  });

  it("signs ES256 that verifies under its own public key", async () => {
    const { openKeyFileSigner } =
      await import("../../src/node/signer-file.js");
    const signer = await openKeyFileSigner(path.join(home, "s.jwk"));
    const xy = await signer.publicKeyXY();
    const msg = new TextEncoder().encode("message");
    const sig = await signer.sign(msg);
    const point = new Uint8Array(65);
    point[0] = 4;
    point.set(xy, 1);
    const pub = await crypto.subtle.importKey(
      "raw",
      point as BufferSource,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        pub,
        sig as BufferSource,
        msg as BufferSource,
      ),
    ).toBe(true);
  });
});
