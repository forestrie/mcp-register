/**
 * The `node:fs` boundary. Base64 in, or a path read from disk — nothing
 * else in `src/node` reads a file. Every core and net call in this package
 * takes `Uint8Array`, never a path and never a base64 string; this module
 * is where the MCP wire form of "bytes" (`{ base64 } | { path }`) becomes
 * one, for `tools.ts` to pass on.
 *
 * Validates aggressively rather than trusting a malformed input to fail
 * cleanly downstream: a bad base64 string that `Buffer.from` decodes
 * anyway (silently dropping what it does not understand) would otherwise
 * surface many calls later as a confusing "genesis document malformed" or
 * "receipt malformed" — a typo dressed up as a verification failure.
 * Mirrors `@forestrie/mcp-verify`'s `src/node/resolve-input.ts`. The wire
 * field is `b64`, as the verifier names it; `base64` is accepted as an
 * alias, permanently, because this package documented that name first
 * and a caller who learned either server's shape must not be turned away
 * by the other (plan-2609-08 U2).
 */
import { readFileSync } from "node:fs";

export class InputError extends Error {
  readonly code = "invalid_input" as const;
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

/** Bytes cross the MCP boundary as base64 — `b64` (the verifier's name) or
 *  its alias `base64` — and stdio additionally accepts a path. */
export type BytesInput =
  { b64: string } | { base64: string } | { path: string };

/**
 * Strict base64. `Buffer.from(s, "base64")` silently ignores anything it
 * does not understand, so a plainly wrong string decodes to a few
 * plausible bytes rather than failing here, where the message can still
 * say which field was wrong.
 */
function decodeBase64(
  value: string,
  what: string,
  key: "b64" | "base64",
): Uint8Array {
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(trimmed) || trimmed.length === 0) {
    throw new InputError(
      `${what}.${key} is not valid base64 (standard alphabet, optional '=' padding)`,
    );
  }
  const bytes = new Uint8Array(Buffer.from(trimmed, "base64"));
  if (bytes.length === 0) {
    throw new InputError(`${what}.${key} decoded to 0 bytes`);
  }
  // Round-trip guard: catches truncated / mis-padded input that Buffer would
  // otherwise accept by discarding the incomplete trailing group.
  if (
    Buffer.from(bytes).toString("base64").replace(/=+$/, "") !==
    trimmed.replace(/=+$/, "")
  ) {
    throw new InputError(
      `${what}.${key} is not canonical base64 (it does not round-trip)`,
    );
  }
  return bytes;
}

/** Resolve one `{ b64 } | { base64 } | { path }` input to bytes. Throws `InputError`
 *  — never a bare `Error` — so a caller can tell "your input was malformed"
 *  from a programming error and turn it into a `structuredContent.problem`
 *  rather than an uncaught exception. */
export function resolveBytes(input: BytesInput, what = "input"): Uint8Array {
  if ("b64" in input) {
    return decodeBase64(input.b64, what, "b64");
  }
  if ("base64" in input) {
    return decodeBase64(input.base64, what, "base64");
  }
  if (input.path.trim() === "") {
    throw new InputError(`${what}.path is empty`);
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(input.path));
  } catch (err) {
    throw new InputError(
      `cannot read ${what}.path '${input.path}': ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (bytes.length === 0) {
    throw new InputError(`${what}.path '${input.path}' is empty (0 bytes)`);
  }
  return bytes;
}
