/**
 * Sealing delegation for a data log this package's key owns.
 *
 * A data log's checkpoints are published by a sealer, and only the log's
 * root key — here, the key the creation grant's `grantData` names — can
 * authorise one. Without that authorisation entries sequence but no
 * checkpoint ever covers them, and receipts 404 forever.
 *
 * The coordinator offers a *standing* delegate key for each log whose
 * public root it knows: the pending-delegation entry with
 * `suggestedTtlSeconds` and no `mmrStart`, vouched for by the registrar.
 * This module picks that entry, verifies the voucher against the pinned
 * registrar key (fail closed: a compromised coordinator must not get a
 * root to delegate to a key the sealer does not hold), and builds the two
 * artefacts the coordinator takes, both signed through the signer seam:
 *
 *  - the delegation certificate (`buildDelegationCertificateEs256WithSigner`);
 *  - the on-chain delegation proof, low-s normalised because the on-chain
 *    P-256 verifier rejects high-s signatures.
 *
 * The same flow as forestrie-cli's `delegate` command and thinker's
 * `delegateSealing`, over the published `@forestrie/delegation-cose`.
 */
import {
  buildDelegationCertificateEs256WithSigner,
  buildOnchainDelegationToBeSignedEs256,
  decodeDelegatedCoseKeyFromBytes,
  normalizeEs256SignatureLowS,
  parseDelegatedCoseKeyFromPayload,
  parseDelegationCertificate,
  type DelegationInput,
} from "@forestrie/delegation-cose";
import {
  parseRegistrarKeyXY,
  uuidToBytes,
  verifyDelegateKeyVoucher,
} from "@forestrie/encoding";
import { base64ToBytes, bytesToBase64 } from "./base64.js";
import { sha256, toHex } from "./hex.js";
import type { Es256Signer } from "./signer.js";

/** Horizon default: effectively unbounded, as the CLI and thinker use. */
export const DEFAULT_MMR_END = Number.MAX_SAFE_INTEGER;

export class DelegationError extends Error {
  constructor(
    readonly code:
      | "no_standing_entry"
      | "voucher_rejected"
      | "invalid_response"
      | "invalid_input",
    message: string,
  ) {
    super(message);
  }
}

/** One entry of `GET /api/logs/{logId}/pending-delegation`'s `entries`. */
export interface PendingDelegationEntry {
  delegatedPublicKey?: string;
  suggestedTtlSeconds?: number;
  mmrStart?: number;
  voucher?: string;
  sealerId?: string;
  epoch?: number | string;
  [k: string]: unknown;
}

export interface StandingEntry {
  delegatedPublicKey: string;
  suggestedTtlSeconds: number;
  voucher: string;
  sealerId: string;
  epoch: number;
}

/**
 * The standing delegate-key entry, or `undefined` when the coordinator has
 * none — which is what it answers (200, no standing entry) when it has
 * never learned the log's public root. That is the case `prepare` fixes.
 */
export function findStandingEntry(body: unknown): StandingEntry | undefined {
  if (typeof body !== "object" || body === null)
    throw new DelegationError(
      "invalid_response",
      "pending-delegation did not return a JSON object",
    );
  const entries = (body as { entries?: unknown }).entries;
  if (entries !== undefined && !Array.isArray(entries))
    throw new DelegationError(
      "invalid_response",
      "pending-delegation `entries` is not an array",
    );
  const standing = ((entries ?? []) as PendingDelegationEntry[]).find(
    (e) =>
      typeof e === "object" &&
      e !== null &&
      e.suggestedTtlSeconds !== undefined &&
      e.mmrStart === undefined,
  );
  if (!standing) return undefined;
  if (
    typeof standing.delegatedPublicKey !== "string" ||
    typeof standing.voucher !== "string" ||
    typeof standing.sealerId !== "string" ||
    standing.epoch === undefined ||
    typeof standing.suggestedTtlSeconds !== "number"
  )
    throw new DelegationError(
      "voucher_rejected",
      "the standing entry is missing its registrar voucher, sealerId or epoch; refusing to delegate",
    );
  const epoch = Number(standing.epoch);
  if (!Number.isSafeInteger(epoch) || epoch < 0)
    throw new DelegationError(
      "voucher_rejected",
      `the standing entry's epoch ${String(standing.epoch)} is not a non-negative integer`,
    );
  return {
    delegatedPublicKey: standing.delegatedPublicKey,
    suggestedTtlSeconds: standing.suggestedTtlSeconds,
    voucher: standing.voucher,
    sealerId: standing.sealerId,
    epoch,
  };
}

/** Verify the registrar's voucher for the standing key. Throws on any mismatch. */
export async function checkVoucher(
  standing: StandingEntry,
  knownSealerKeyXY: Uint8Array,
): Promise<void> {
  const pinned = parseRegistrarKeyXY(knownSealerKeyXY);
  if (pinned === null)
    throw new DelegationError(
      "invalid_input",
      `the known sealer key must be 64 bytes x‖y (got ${knownSealerKeyXY.length})`,
    );
  const result = await verifyDelegateKeyVoucher(
    base64ToBytes(standing.voucher),
    pinned,
    {
      sealerId: standing.sealerId,
      epoch: standing.epoch,
      publicKey: base64ToBytes(standing.delegatedPublicKey),
    },
  );
  if (!result.ok)
    throw new DelegationError(
      "voucher_rejected",
      `the registrar voucher does not check out against the pinned sealer key (${result.reason}); refusing to delegate`,
    );
}

/** The JSON body of `POST /api/delegations/certificate`. */
export interface CertificateSubmission {
  logId: string;
  mmrStart: number;
  mmrEnd: number;
  delegatedPublicKey: string;
  certificate: string;
  issuedAt: number;
  expiresAt: number;
  onchainSignature: string;
}

export interface BuildDelegationInput {
  logId: string;
  standing: StandingEntry;
  mmrEnd?: number;
  ttlSeconds?: number;
}

/**
 * Build the certificate submission, signing both artefacts with the log
 * key. The certificate kid is `sha256(0x04‖x‖y)[0..16]`, the derivation
 * delegation-cose's CryptoKeyPair path uses.
 */
export async function buildCertificateSubmission(
  input: BuildDelegationInput,
  signer: Es256Signer,
): Promise<CertificateSubmission> {
  const mmrStart = 0;
  const mmrEnd = input.mmrEnd ?? DEFAULT_MMR_END;
  if (!Number.isSafeInteger(mmrEnd) || mmrEnd < 0)
    throw new DelegationError(
      "invalid_input",
      `mmrEnd ${mmrEnd} is not a non-negative safe integer`,
    );
  const logIdHex32 = toHex(uuidToBytes(input.logId));
  const delegatedPublicKeyCbor = base64ToBytes(
    input.standing.delegatedPublicKey,
  );

  const xy = await signer.publicKeyXY();
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(xy, 1);
  const rootKid = (await sha256(point)).slice(0, 16);

  const certInput: DelegationInput = {
    logIdHex32,
    mmrStart,
    mmrEnd,
    delegatedPublicKeyCbor,
    ttlSeconds: input.ttlSeconds ?? input.standing.suggestedTtlSeconds,
  };
  const certificate = await buildDelegationCertificateEs256WithSigner(
    certInput,
    rootKid,
    (sigStructure) => signer.sign(sigStructure),
  );

  const delegated = parseDelegatedCoseKeyFromPayload(
    decodeDelegatedCoseKeyFromBytes(delegatedPublicKeyCbor),
  );
  const tbs = buildOnchainDelegationToBeSignedEs256({
    logIdHex: logIdHex32,
    mmrStart,
    mmrEnd,
    delegatedKeyX: delegated.x,
    delegatedKeyY: delegated.y,
  });
  const onchainSignature = normalizeEs256SignatureLowS(
    await signer.sign(tbs.sigStructureBytes),
  );

  const info = parseDelegationCertificate(certificate);
  return {
    logId: input.logId,
    mmrStart,
    mmrEnd,
    delegatedPublicKey: input.standing.delegatedPublicKey,
    certificate: bytesToBase64(certificate),
    issuedAt: info.issuedAt,
    expiresAt: info.expiresAt,
    onchainSignature: bytesToBase64(onchainSignature),
  };
}
