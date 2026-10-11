import { createHash } from "node:crypto";
import {
  decodeCborDeterministic,
  decodeCoseSign1,
  signCoseSign1Statement,
  encodeCoseProtectedMapBytes,
  verifyCoseSign1WithParsedKey,
} from "@forestrie/encoding";
import { describe, expect, it } from "vitest";
import { toHex } from "../../src/core/hex.js";
import { MAX_STATEMENT_BYTES } from "../../src/core/limits.js";
import type { Es256Signer } from "../../src/core/signer.js";
import { StatementError, signStatement } from "../../src/core/statement.js";
import { jwkSigner, keyJwk, logKeyXY } from "../net/write-path-fixture.js";

const payload = new TextEncoder().encode('{"hello":"forestrie"}');
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

function protectedMap(statement: Uint8Array): Map<number, unknown> {
  const decoded = decodeCoseSign1(statement);
  expect(decoded).not.toBeNull();
  return decodeCborDeterministic(decoded!.protectedBstr) as Map<
    number,
    unknown
  >;
}

describe("signStatement", () => {
  it("builds the statement canopy registers", async () => {
    const signer = await jwkSigner();
    const out = await signStatement(
      { payload, contentType: "application/json", issuedAt: 1_700_000_000 },
      signer,
    );
    const kid = logKeyXY.slice(0, 32);
    const decoded = decodeCoseSign1(out.statement)!;
    expect(decoded.payloadBstr).toEqual(payload);

    const prot = protectedMap(out.statement);
    expect(prot.get(1)).toBe(-7);
    expect(prot.get(3)).toBe("application/json");
    expect(prot.get(4)).toEqual(kid);
    const cwt = prot.get(15) as Map<number, unknown>;
    expect(cwt.get(1)).toBe(toHex(kid));
    expect(cwt.get(2)).toBe(`sha-256:${sha(payload)}`);
    expect(cwt.get(6)).toBe(1_700_000_000);

    // Unprotected header is empty.
    const unprot = decoded.unprotected;
    const size =
      unprot instanceof Map
        ? unprot.size
        : Object.keys(unprot as object).length;
    expect(size).toBe(0);

    expect(
      await verifyCoseSign1WithParsedKey(out.statement, {
        x: logKeyXY.slice(0, 32),
        y: logKeyXY.slice(32),
        curve: "P-256",
      }),
    ).toBe(true);
    expect(out.contentHash).toBe(sha(out.statement));
    expect(out.kid).toEqual(kid);
    expect(out.issuer).toBe(toHex(kid));
    expect(out.subject).toBe(`sha-256:${sha(payload)}`);
  });

  it("honours explicit issuer and subject, and omits iat when not given", async () => {
    const out = await signStatement(
      {
        payload,
        contentType: "text/plain",
        issuer: "did:example:me",
        subject: "thing-1",
      },
      await jwkSigner(),
    );
    const cwt = protectedMap(out.statement).get(15) as Map<number, unknown>;
    expect(cwt.get(1)).toBe("did:example:me");
    expect(cwt.get(2)).toBe("thing-1");
    expect(cwt.has(6)).toBe(false);
  });

  it("has the protected header signCoseSign1Statement produces", async () => {
    const { warning: _w, ...jwk } = keyJwk("log-key.jwk.json");
    const priv = await crypto.subtle.importKey(
      "jwk",
      { ...jwk, key_ops: ["sign"] },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const kid = logKeyXY.slice(0, 32);
    const options = {
      alg: -7,
      cty: "application/json",
      cwtClaims: {
        iss: toHex(kid),
        sub: `sha-256:${sha(payload)}`,
        iat: 1_700_000_000,
      },
    };
    const reference = await signCoseSign1Statement(
      payload,
      kid,
      priv,
      options,
    );
    const ours = await signStatement(
      { payload, contentType: "application/json", issuedAt: 1_700_000_000 },
      await jwkSigner(),
    );
    expect(decoded(ours.statement).protectedBstr).toEqual(
      decoded(reference).protectedBstr,
    );
    expect(decoded(ours.statement).protectedBstr).toEqual(
      encodeCoseProtectedMapBytes(kid, options),
    );
    expect(decoded(ours.statement).payloadBstr).toEqual(
      decoded(reference).payloadBstr,
    );
  });

  it("refuses an empty payload", async () => {
    await expect(
      signStatement(
        { payload: new Uint8Array(0), contentType: "text/plain" },
        await jwkSigner(),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("refuses a payload over 4 MiB", async () => {
    const err = await signStatement(
      {
        payload: new Uint8Array(MAX_STATEMENT_BYTES + 1),
        contentType: "application/octet-stream",
      },
      await jwkSigner(),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(StatementError);
    expect((err as StatementError).code).toBe("too_large");
  });

  it("refuses a signer whose sign() uses a different key than publicKeyXY()", async () => {
    const real = await jwkSigner("log-key.jwk.json");
    const other = await jwkSigner("other-log-key.jwk.json");
    const liar: Es256Signer = {
      description: "liar",
      publicKeyXY: () => real.publicKeyXY(),
      sign: (m) => other.sign(m),
    };
    await expect(
      signStatement({ payload, contentType: "text/plain" }, liar),
    ).rejects.toMatchObject({ code: "signer_failed" });
  });

  it("refuses a signer returning a short signature or a short key", async () => {
    const real = await jwkSigner();
    await expect(
      signStatement(
        { payload, contentType: "text/plain" },
        { ...real, sign: async () => new Uint8Array(10) },
      ),
    ).rejects.toMatchObject({ code: "signer_failed" });
    await expect(
      signStatement(
        { payload, contentType: "text/plain" },
        { ...real, publicKeyXY: async () => new Uint8Array(33) },
      ),
    ).rejects.toMatchObject({ code: "signer_failed" });
  });
});

function decoded(b: Uint8Array) {
  return decodeCoseSign1(b)!;
}
