/**
 * Loaders and a test signer over `test/fixtures/synthetic/write-path/`.
 * The signer is a real WebCrypto ES256 key (the committed TEST-ONLY log
 * key) behind the same `Es256Signer` seam the server uses.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { base64ToBytes } from "../../src/core/base64.js";
import type { Es256Signer } from "../../src/core/signer.js";
import { loadExchange, type Exchange } from "./replay.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const WRITE_PATH_DIR = path.join(
  HERE,
  "..",
  "fixtures",
  "synthetic",
  "write-path",
);
export const LANE_A_DIR = path.join(HERE, "..", "fixtures", "lane-a-0.5.0");

export interface WritePathCoordinates {
  baseUrl: string;
  coordinatorUrl: string;
  rootLogId: string;
  dataLogId: string;
  ownerLogId: string;
  statusEntryHash: string;
  entryId: string;
  massifHeight: number;
  sealerId: string;
  epoch: number;
  suggestedTtlSeconds: number;
  idtimestampHex: string;
}

export const coordinates = JSON.parse(
  readFileSync(path.join(WRITE_PATH_DIR, "coordinates.json"), "utf8"),
) as WritePathCoordinates;

export const grantPath = path.join(WRITE_PATH_DIR, "grant.cose");
export const grantOtherKeyPath = path.join(
  WRITE_PATH_DIR,
  "grant-other-key.cose",
);

export function wp(name: string): Uint8Array {
  return new Uint8Array(readFileSync(path.join(WRITE_PATH_DIR, name)));
}

export function wpJson<T = unknown>(name: string): T {
  return JSON.parse(
    readFileSync(path.join(WRITE_PATH_DIR, name), "utf8"),
  ) as T;
}

/** A synthetic recorded exchange by name. */
export function ex(name: string): Exchange {
  return loadExchange(WRITE_PATH_DIR, name);
}

export interface TestJwk extends JsonWebKey {
  warning?: string;
}

function b64urlToBytes(s: string): Uint8Array {
  return base64ToBytes(s);
}

/** x‖y of a committed test JWK. */
export function jwkXY(jwk: JsonWebKey): Uint8Array {
  const out = new Uint8Array(64);
  out.set(b64urlToBytes(jwk.x as string), 0);
  out.set(b64urlToBytes(jwk.y as string), 32);
  return out;
}

export function keyJwk(file: string): TestJwk {
  return wpJson<TestJwk>(file);
}

export const logKeyXY = jwkXY(keyJwk("log-key.jwk.json"));
export const otherLogKeyXY = jwkXY(keyJwk("other-log-key.jwk.json"));
export const registrarKeyXY = jwkXY(keyJwk("registrar-key.jwk.json"));

/** An `Es256Signer` over a committed test JWK (ECDSA P-256, SHA-256, r‖s). */
export async function jwkSigner(
  file = "log-key.jwk.json",
): Promise<Es256Signer> {
  const { warning: _warning, ...jwk } = keyJwk(file);
  const key = await crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["sign"] },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const xy = jwkXY(jwk);
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

/** Import x‖y as a WebCrypto verify key. */
export async function verifyKeyFromXY(xy: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(xy.slice(0, 32)).toString("base64url"),
      y: Buffer.from(xy.slice(32)).toString("base64url"),
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}
