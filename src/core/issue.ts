/**
 * Issue a child grant as the requester, and complete it once canopy has
 * sealed it.
 *
 * The requester owns an authority log (ARC-0028: the requester funds, the
 * performer writes) and is its own grant issuer: it signs a child grant
 * with its authority key, naming the performer's log key in `grantData`.
 * Forestrie runs no issuer.
 *
 * The bytes are the ES256 profile of `@forestrie/grant-builder`'s
 * `signGrantPayloadWithEs256Pem`, which univocity verifies
 * (`verifyCoseSign1ES256`), with the PEM replaced by the signer seam:
 *
 *  - untagged COSE Sign1, protected `{1: -7}` (wire `a10126`);
 *  - payload the 32-byte SHA-256 of the canonical grant v0 CBOR;
 *  - signature over `["Signature1", protected, h'', payload]`, r‖s;
 *  - unprotected `{-65537: 8 zero bytes, -65538: grant v0 CBOR}`, in that
 *    canonical order.
 *
 * grant-builder itself is not imported: its index pulls in its node-only
 * PEM module, and this file is browser-safe.
 *
 * Completing a grant merges the receipt (396) and the entry's idtimestamp
 * (-65537) into the unprotected header without re-signing, as forestrie-cli
 * `register-grant-complete.ts` does. The completed grant is the
 * `Forestrie-Grant` credential register_statement and delegate_sealing take.
 */
import {
  appendCborBstr,
  appendCborText,
  decodeCoseSign1,
  encodeCborDeterministic,
  encodeGrantPayloadV0Canonical,
  mergeUnprotectedIntoCoseSign1,
  uuidToBytes,
} from "@forestrie/encoding";
import { GrantError, type GrantView } from "./grant.js";
import { bytesEqual, sha256 } from "./hex.js";
import type { Es256Signer } from "./signer.js";

const ES256_PROTECTED_HEADER = new Uint8Array([0xa1, 0x01, 0x26]);
// CBOR negative-int keys (major type 1): -65537, then -65538.
const CBOR_KEY_IDTIMESTAMP = [0x3a, 0x00, 0x01, 0x00, 0x00];
const CBOR_KEY_FORESTRIE_GRANT_V0 = [0x3a, 0x00, 0x01, 0x00, 0x01];
const HEADER_RECEIPT = 396;
const HEADER_IDTIMESTAMP = -65537;

/** canopy's register-grant body key for the parent grant evidence. */
const PARENT_GRANT_BODY_KEY = "parentGrant";
/** canopy reads at most this much register-grant body (`auth-grant.ts`). */
export const MAX_PARENT_GRANT_BYTES = 16 * 1024;

/** GF_CREATE|GF_EXTEND (byte 3), GF_DATA_LOG (byte 7): a data-log creation
 *  grant, the shape that both opens the child log and carries statements. */
export function dataLogCreateExtendFlags(): Uint8Array {
  const flags = new Uint8Array(8);
  flags[3] = 0x03;
  flags[7] = 0x02;
  return flags;
}

export interface IssueGrantInput {
  /** The child data log the grant creates (UUID). */
  logId: string;
  /** The requester's authority log the grant is sequenced into (UUID). */
  ownerLogId: string;
  /** The key the grant names: 64 bytes x‖y of the performer's log key. */
  grantData: Uint8Array;
  /** The batch ceiling canopy prices a paid child grant by. At least 1. */
  maxHeight: number;
}

export interface IssuedGrant {
  /** The signed grant, untagged COSE Sign1. */
  grant: Uint8Array;
  /** The canonical grant v0 CBOR that was signed (its SHA-256 is the payload). */
  grantPayload: Uint8Array;
  flags: Uint8Array;
}

export async function issueChildGrant(
  input: IssueGrantInput,
  authority: Es256Signer,
): Promise<IssuedGrant> {
  let logId: Uint8Array;
  let ownerLogId: Uint8Array;
  try {
    logId = uuidToBytes(input.logId);
    ownerLogId = uuidToBytes(input.ownerLogId);
  } catch {
    throw new GrantError(
      `logId and ownerLogId must be UUIDs (got ${input.logId}, ${input.ownerLogId})`,
    );
  }
  if (bytesEqual(logId, ownerLogId))
    throw new GrantError(
      "a child grant must name a log other than its owner (logId equals ownerLogId)",
    );
  if (input.grantData.length !== 64)
    throw new GrantError(
      `grantData must be a 64-byte ES256 x‖y (got ${input.grantData.length} bytes): canopy forwards only ES256 child roots`,
    );
  if (!Number.isSafeInteger(input.maxHeight) || input.maxHeight < 1)
    throw new GrantError(
      `maxHeight must be a positive integer (got ${input.maxHeight})`,
    );

  const flags = dataLogCreateExtendFlags();
  const grantPayload = encodeGrantPayloadV0Canonical({
    logId,
    ownerLogId,
    grant: flags,
    maxHeight: input.maxHeight,
    minGrowth: 0,
    grantData: input.grantData,
  });
  const payload = await sha256(grantPayload);

  const sig: number[] = [0x84];
  appendCborText(sig, "Signature1");
  appendCborBstr(sig, ES256_PROTECTED_HEADER);
  appendCborBstr(sig, new Uint8Array(0));
  appendCborBstr(sig, payload);
  const signature = await authority.sign(new Uint8Array(sig));
  if (signature.length !== 64)
    throw new GrantError(
      `the authority signer returned ${signature.length} bytes; ES256 needs a 64-byte r‖s`,
    );

  const out: number[] = [0x84];
  appendCborBstr(out, ES256_PROTECTED_HEADER);
  out.push(0xa2);
  out.push(...CBOR_KEY_IDTIMESTAMP);
  appendCborBstr(out, new Uint8Array(8));
  out.push(...CBOR_KEY_FORESTRIE_GRANT_V0);
  appendCborBstr(out, grantPayload);
  appendCborBstr(out, payload);
  appendCborBstr(out, signature);
  return { grant: new Uint8Array(out), grantPayload, flags };
}

/**
 * Why `parent` cannot authorise a child grant signed by `authorityXY`, or
 * `[]`. The parent is the requester's own authority grant: an auth-log
 * grant naming the authority key, whose log becomes the child's owner.
 */
export function parentGrantProblems(
  parent: GrantView,
  authorityXY: Uint8Array,
): string[] {
  const problems: string[] = [];
  if (!parent.authLog)
    problems.push(
      `the parent grant's flags ${parent.flagsHex} are not an authority-log grant (GF_AUTH_LOG); only an authority log can own a child log`,
    );
  if (parent.grantData.length !== 64)
    problems.push(
      `the parent grant names a ${parent.grantData.length}-byte key; canopy's prepare refuses non-ES256 parents, so the authority key must be ES256`,
    );
  else if (!bytesEqual(parent.grantData, authorityXY))
    problems.push(
      "the parent grant names a different key than this server's authority key, so this key does not own that authority log and cannot issue under it",
    );
  return problems;
}

/** The register-grant request body: canonical CBOR `{parentGrant: <bytes>}`. */
export function registerGrantBody(parentGrant: Uint8Array): Uint8Array {
  return encodeCborDeterministic(
    new Map<string, unknown>([[PARENT_GRANT_BODY_KEY, parentGrant]]),
  );
}

const ENTRY_ID = /^[0-9a-f]{32}$/;

/** Merge the sealed receipt and the entry's idtimestamp into the grant. */
export function completeGrant(
  grant: Uint8Array,
  receipt: Uint8Array,
  entryIdHex: string,
): Uint8Array {
  if (!ENTRY_ID.test(entryIdHex))
    throw new GrantError(
      `entryId must be 32 lowercase hex (got ${entryIdHex})`,
    );
  const idtimestamp = new Uint8Array(8);
  for (let i = 0; i < 8; i++)
    idtimestamp[i] = parseInt(entryIdHex.slice(i * 2, i * 2 + 2), 16);
  return mergeUnprotectedIntoCoseSign1(
    grant,
    new Map<number, unknown>([
      [HEADER_RECEIPT, receipt],
      [HEADER_IDTIMESTAMP, idtimestamp],
    ]),
  );
}

/** The grant v0 CBOR a grant carries at unprotected -65538: its content. */
export function grantContent(grant: Uint8Array): Uint8Array {
  const sign1 = decodeCoseSign1(grant);
  const unprotected = sign1?.unprotected;
  const content =
    unprotected instanceof Map ? unprotected.get(-65538) : undefined;
  if (!(content instanceof Uint8Array) || content.length === 0)
    throw new GrantError(
      "not a Forestrie-Grant: no grant v0 CBOR at unprotected label -65538",
    );
  return content;
}
