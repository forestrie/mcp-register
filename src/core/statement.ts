/**
 * Build and sign the statement canopy registers: an untagged COSE Sign1,
 * payload attached, protected header `{1: -7, 3: cty, 4: kid, 15: {1: iss,
 * 2: sub}}`, empty unprotected header.
 *
 * Byte-for-byte the construction of `@forestrie/encoding`'s
 * `signCoseSign1Statement` (the one forestrie-cli uses), with the
 * WebCrypto call replaced by the signer seam: the same protected map, the
 * same Sig_structure, the same envelope encoder.
 *
 * kid is the key's 32-byte x coordinate, the binding canopy checks first
 * (canopy `grant/statement-signer-binding.ts`).
 */
import {
  COSE_ALG_ES256,
  encodeCoseProtectedMapBytes,
  encodeCoseSign1Statement,
  encodeSigStructure,
  verifyCoseSign1WithParsedKey,
  type CoseProtectedHeaderOptions,
} from "@forestrie/encoding";
import { MAX_STATEMENT_BYTES } from "./limits.js";
import { sha256, toHex } from "./hex.js";
import type { Es256Signer } from "./signer.js";

export class StatementError extends Error {
  constructor(
    readonly code: "invalid_input" | "too_large" | "signer_failed",
    message: string,
  ) {
    super(message);
  }
}

export interface SignStatementInput {
  payload: Uint8Array;
  /** The payload's media type, carried in protected header 3. */
  contentType: string;
  /** CWT iss; defaults to the hex of the kid. */
  issuer?: string;
  /** CWT sub; defaults to `sha-256:<hex of payload>`, as forestrie-cli does. */
  subject?: string;
  /** CWT iat, seconds since the epoch; omitted when absent. */
  issuedAt?: number;
}

export interface SignedStatement {
  statement: Uint8Array;
  /** sha256 of the statement: the id in canopy's status URL. */
  contentHash: string;
  kid: Uint8Array;
  issuer: string;
  subject: string;
}

export async function signStatement(
  input: SignStatementInput,
  signer: Es256Signer,
): Promise<SignedStatement> {
  if (input.payload.length === 0)
    throw new StatementError("invalid_input", "payload is empty");
  if (input.payload.length > MAX_STATEMENT_BYTES)
    throw new StatementError(
      "too_large",
      `payload is ${input.payload.length} bytes; canopy accepts signed statements up to ${MAX_STATEMENT_BYTES} bytes. Register a small manifest naming the artefact's digest instead`,
    );
  if (!input.contentType.trim())
    throw new StatementError("invalid_input", "contentType is empty");

  const xy = await signer.publicKeyXY();
  if (xy.length !== 64)
    throw new StatementError(
      "signer_failed",
      `signer returned a ${xy.length}-byte public key; ES256 needs 64 bytes x‖y`,
    );
  const kid = xy.slice(0, 32);
  const issuer = input.issuer ?? toHex(kid);
  const subject =
    input.subject ?? `sha-256:${toHex(await sha256(input.payload))}`;
  const options: CoseProtectedHeaderOptions = {
    alg: COSE_ALG_ES256,
    cty: input.contentType,
    cwtClaims: {
      iss: issuer,
      sub: subject,
      ...(input.issuedAt !== undefined ? { iat: input.issuedAt } : {}),
    },
  };

  const sigStructure = encodeSigStructure(
    encodeCoseProtectedMapBytes(kid, options),
    new Uint8Array(0),
    input.payload,
  );
  const signature = await signer.sign(sigStructure);
  if (signature.length !== 64)
    throw new StatementError(
      "signer_failed",
      `signer returned a ${signature.length}-byte signature; ES256 is 64 bytes r‖s`,
    );
  const statement = encodeCoseSign1Statement(
    input.payload,
    kid,
    signature,
    options,
  );

  // Check our own work before canopy does: a signer that signs with a key
  // other than the one it reports would otherwise surface as a bare 403.
  const verified = await verifyCoseSign1WithParsedKey(statement, {
    x: xy.slice(0, 32),
    y: xy.slice(32),
    curve: "P-256",
  });
  if (!verified)
    throw new StatementError(
      "signer_failed",
      "the signature does not verify under the signer's own public key",
    );
  if (statement.length > MAX_STATEMENT_BYTES)
    throw new StatementError(
      "too_large",
      `the signed statement is ${statement.length} bytes; canopy's limit is ${MAX_STATEMENT_BYTES}`,
    );

  return {
    statement,
    contentHash: toHex(await sha256(statement)),
    kid,
    issuer,
    subject,
  };
}
