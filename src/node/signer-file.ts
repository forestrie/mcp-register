/**
 * The default signer backend: an ES256 (P-256) private key in a local JWK
 * file, created on first use.
 *
 * Proportionate custody for what the key can do: it owns one data log
 * whose grant someone else issued and bounded, and it holds no funds. The
 * file is written once, `0600` in a `0700` directory, atomically (written
 * aside, then hard-linked into place), so two servers starting together
 * cannot both write one and neither can read a half-written one. It is
 * never overwritten: a key that signed a grant's `grantData` must not
 * silently change under it.
 *
 * The private key is imported non-extractable for signing; nothing in this
 * package reads the `d` field again after import, and no tool result or
 * log line carries it.
 */
import { webcrypto } from "node:crypto";
import {
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Es256Signer } from "../core/signer.js";

const subtle = webcrypto.subtle;

export class KeyFileError extends Error {
  readonly code = "signer_unavailable" as const;
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

/**
 * Write a new key without ever exposing a half-written file: the JWK goes
 * to a private temporary file first, then is hard-linked into place, which
 * fails (EEXIST) if another process got there first, in which case its key
 * is used. The temporary file is always removed.
 */
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
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(record, null, 2) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    try {
      linkSync(tmp, path);
    } catch (err) {
      // Lost a race to another process creating the same file: use theirs.
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      // already gone
    }
  }
}

export interface KeyFileSigner extends Es256Signer {
  readonly path: string;
  /** True when this process created the key file. */
  readonly created: boolean;
}

/**
 * Load the key at `path`. Lazy by design: the server opens the signer at the
 * first tool call that needs it, so starting the server never writes a
 * file. With `create` (the default) a missing key is created; without it a
 * missing key is a `KeyFileError`, so a read-only tool never makes one.
 *
 * Refused, like ssh refuses a loose private key: a key path that is a
 * symlink, or a key file readable or writable by group or others.
 */
export async function openKeyFileSigner(
  path: string,
  options: { create?: boolean } = {},
): Promise<KeyFileSigner> {
  let created = false;
  let stat = lstatOrUndefined(path);
  if (stat === undefined) {
    if (options.create === false)
      throw new KeyFileError(
        `no log key at ${path} yet: get_log_key or register_statement creates it`,
      );
    try {
      await createKeyFile(path);
    } catch (err) {
      throw new KeyFileError(
        `cannot create the log key file ${path}: ${(err as Error).message}`,
      );
    }
    created = true;
    stat = lstatOrUndefined(path);
  }
  if (stat === undefined || stat.isSymbolicLink() || !stat.isFile())
    throw new KeyFileError(
      `the log key path ${path} is not a regular file (a symlink or directory is refused)`,
    );
  if ((stat.mode & 0o077) !== 0)
    throw new KeyFileError(
      `the log key file ${path} is accessible to other users (mode ${(stat.mode & 0o777).toString(8)}); chmod 600 it`,
    );
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new KeyFileError(
      `cannot read the log key file ${path}: ${(err as Error).message}`,
    );
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
  let privateKey: CryptoKey;
  try {
    privateKey = await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: false },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
  } catch {
    throw new KeyFileError(
      `the log key file ${path} holds an invalid P-256 key`,
    );
  }
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

function lstatOrUndefined(path: string) {
  try {
    return lstatSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new KeyFileError(
      `cannot stat the log key path ${path}: ${(err as Error).message}`,
    );
  }
}
