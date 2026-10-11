/**
 * The default signer backend: an ES256 (P-256) private key in a local JWK
 * file, created on first use.
 *
 * Proportionate custody for what the key can do: it owns one data log
 * whose grant someone else issued and bounded, and it holds no funds. The
 * file is written once, `0600` in a `0700` directory, with an exclusive
 * create so two servers starting together cannot both write one. It is
 * never overwritten: a key that signed a grant's `grantData` must not
 * silently change under it.
 *
 * The private key is imported non-extractable for signing; nothing in this
 * package reads the `d` field again after import, and no tool result or
 * log line carries it.
 */
import { webcrypto } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Es256Signer } from "../core/signer.js";

const subtle = webcrypto.subtle;

export class KeyFileError extends Error {
  readonly code = "signer_unavailable" as const;
}

/** `$MCP_REGISTER_KEY_FILE`, else `<home>/log-key.jwk` under `registerHome`. */
export function defaultKeyFilePath(
  env: Record<string, string | undefined>,
): string {
  return (
    env["MCP_REGISTER_KEY_FILE"] ?? join(registerHome(env), "log-key.jwk")
  );
}

/** `$MCP_REGISTER_HOME`, else `$XDG_CONFIG_HOME/forestrie/mcp-register`, else `~/.config/…`. */
export function registerHome(env: Record<string, string | undefined>): string {
  if (env["MCP_REGISTER_HOME"]) return env["MCP_REGISTER_HOME"];
  const config = env["XDG_CONFIG_HOME"] ?? join(homedir(), ".config");
  return join(config, "forestrie", "mcp-register");
}

type P256Jwk = { kty: "EC"; crv: "P-256"; x: string; y: string; d: string };

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function isP256PrivateJwk(v: unknown): v is P256Jwk {
  const j = v as Partial<P256Jwk>;
  return (
    typeof v === "object" &&
    v !== null &&
    j.kty === "EC" &&
    j.crv === "P-256" &&
    typeof j.x === "string" &&
    typeof j.y === "string" &&
    typeof j.d === "string"
  );
}

async function createKeyFile(path: string): Promise<void> {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const pair = (await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", pair.privateKey);
  const record = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    d: jwk.d,
    use: "sig",
    alg: "ES256",
    note: "Forestrie log key for @forestrie/mcp-register. Grants name its public x‖y; keep this file private.",
  };
  try {
    writeFileSync(path, JSON.stringify(record, null, 2) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
  } catch (err) {
    // Lost a race to another process creating the same file: use theirs.
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return;
    throw err;
  }
  chmodSync(path, 0o600);
}

export interface KeyFileSigner extends Es256Signer {
  readonly path: string;
  /** True when this process created the key file. */
  readonly created: boolean;
}

/**
 * Load the key at `path`, creating it first if it does not exist. Lazy by
 * design: the server constructs the signer at the first tool call that
 * needs it, so starting the server never writes a file.
 */
export async function openKeyFileSigner(path: string): Promise<KeyFileSigner> {
  let created = false;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT")
      throw new KeyFileError(
        `cannot read the log key file ${path}: ${(err as Error).message}`,
      );
    await createKeyFile(path);
    created = true;
    text = readFileSync(path, "utf8");
  }
  let jwk: unknown;
  try {
    jwk = JSON.parse(text);
  } catch {
    throw new KeyFileError(`the log key file ${path} is not JSON`);
  }
  if (!isP256PrivateJwk(jwk))
    throw new KeyFileError(
      `the log key file ${path} is not a P-256 private JWK (kty EC, crv P-256, x, y, d)`,
    );
  const privateKey = await subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: false },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const xy = new Uint8Array(64);
  xy.set(b64urlToBytes(jwk.x), 0);
  xy.set(b64urlToBytes(jwk.y), 32);

  return {
    path,
    created,
    description: `local key file ${path}`,
    publicKeyXY: async () => xy.slice(),
    sign: async (message) =>
      new Uint8Array(
        await subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          privateKey,
          message as BufferSource,
        ),
      ),
  };
}
