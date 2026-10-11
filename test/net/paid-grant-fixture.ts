/**
 * Loaders over `test/fixtures/synthetic/paid-grant/`, and the recorded
 * 402 challenge rewritten for the cap tests.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadExchange, type Exchange } from "./replay.js";
import { decodeB64Json, encodeB64Json } from "./stub-facilitator.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const PAID_GRANT_DIR = path.join(
  HERE,
  "..",
  "fixtures",
  "synthetic",
  "paid-grant",
);

export interface PaidGrantCoordinates {
  baseUrl: string;
  coordinatorUrl: string;
  rootLogId: string;
  authorityLogId: string;
  childLogId: string;
  grantCommitmentHex: string;
  entryId: string;
  massifHeight: number;
  unitPriceAtomic: string;
  maxHeight: number;
  network: string;
  asset: string;
  payTo: string;
  payerPrivateKey: `0x${string}`;
  payerAddress: string;
}

export const pg = JSON.parse(
  readFileSync(path.join(PAID_GRANT_DIR, "coordinates.json"), "utf8"),
) as PaidGrantCoordinates;

export const grantsUrl = `${pg.baseUrl}/register/${pg.rootLogId}/grants`;
export const grantStatusUrl = `${pg.baseUrl}/logs/${pg.rootLogId}/${pg.authorityLogId}/entries/${pg.grantCommitmentHex}?subject=${pg.childLogId}`;
export const grantReceiptUrl = `${pg.baseUrl}/logs/${pg.rootLogId}/${pg.authorityLogId}/${pg.massifHeight}/entries/${pg.entryId}/receipt`;
export const amount = String(
  BigInt(pg.unitPriceAtomic) * BigInt(pg.maxHeight),
);

export const authorityGrantPath = path.join(
  PAID_GRANT_DIR,
  "authority-grant.cose",
);
export const freeAuthorityGrantPath = path.join(
  PAID_GRANT_DIR,
  "authority-grant-free.cose",
);

export function pgx(name: string): Exchange {
  return loadExchange(PAID_GRANT_DIR, name);
}

export function pgBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(path.join(PAID_GRANT_DIR, name)));
}

/** The recorded challenge with its requirements edited. */
export function challengeWith(
  edit: (requirements: any) => void,
  name = "register-grant-402",
): Exchange {
  const ex = pgx(name);
  const requirements = decodeB64Json(ex.headers["x-payment-required"]!);
  edit(requirements);
  return {
    ...ex,
    headers: {
      ...ex.headers,
      "x-payment-required": encodeB64Json(requirements),
    },
  };
}

/** An `Es256Signer` over a paid-grant test JWK. */
export async function pgSigner(
  file = "authority-key.jwk.json",
): Promise<import("../../src/core/signer.js").Es256Signer> {
  const { warning: _w, ...jwk } = JSON.parse(
    readFileSync(path.join(PAID_GRANT_DIR, file), "utf8"),
  ) as JsonWebKey & { warning?: string };
  const key = await crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["sign"] },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const xy = new Uint8Array(64);
  xy.set(Buffer.from(jwk.x!, "base64url"), 0);
  xy.set(Buffer.from(jwk.y!, "base64url"), 32);
  return {
    description: `test key ${file}`,
    publicKeyXY: async () => xy.slice(),
    sign: async (message) =>
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          key,
          message as BufferSource,
        ),
      ),
  };
}
