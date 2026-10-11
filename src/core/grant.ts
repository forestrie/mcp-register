/**
 * Read the grant a caller holds, before anything goes over the wire.
 *
 * The credential canopy takes as `Authorization: Forestrie-Grant <base64>`
 * is the completed grant: a COSE Sign1 transparent statement carrying the
 * grant at unprotected label -65538 and its inclusion receipt at 396.
 * `decodeForestrieGrantCose` (`@forestrie/receipt-verify`) is the decoder
 * canopy's own verifier uses.
 *
 * The checks here are the ones canopy applies at register-signed-statement
 * and at prepare (canopy `grant/grant-flags.ts`,
 * `scrapi/register-signed-statement.ts`, `forest/prepare-child-log.ts`),
 * repeated so a wrong grant fails with a reason instead of a bare 403.
 * canopy stays the authority: passing here promises nothing.
 */
import { bytesToUuid, grantDataToBytes } from "@forestrie/encoding";
import { decodeForestrieGrantCose } from "@forestrie/receipt-verify";
import { bytesEqual, toHex } from "./hex.js";

export class GrantError extends Error {
  readonly code = "invalid_grant";
}

export interface GrantView {
  /** The log the grant authorises writes to (canopy's T): the data log. */
  logId: string;
  /** The governing authority log (canopy's O). */
  ownerLogId: string;
  /** The 8-byte wire flag bitmap, hex. */
  flagsHex: string;
  /** The key the grant names, as committed: 64 bytes x‖y for ES256. */
  grantData: Uint8Array;
  /** The batch ceiling, when the issuer sized the grant. */
  maxHeight?: number;
  /** GF_EXTEND with GF_DATA_LOG and not GF_AUTH_LOG. */
  dataLogStatementGrant: boolean;
  /**
   * canopy's `isStatementRegistrationGrant`: a data-log statement grant, or
   * an auth-log bootstrap grant (GF_AUTH_LOG only, with GF_CREATE|GF_EXTEND),
   * whose grantData likewise binds the statement signer.
   */
  statementRegistrationGrant: boolean;
  /** GF_CREATE and GF_EXTEND: the creation grant prepare requires. */
  createAndExtend: boolean;
  /** GF_AUTH_LOG without GF_DATA_LOG: an authority log, which can own children. */
  authLog: boolean;
  /** GF_DERIVED with GF_CHILD_PAYMENT_REQUIRED (adr-0062): registering a
   *  child grant under this one is x402 payment-gated where canopy enables it. */
  requiresChildPayment: boolean;
}

export function inspectGrant(credential: Uint8Array): GrantView {
  let decoded: ReturnType<typeof decodeForestrieGrantCose>;
  try {
    decoded = decodeForestrieGrantCose(credential);
  } catch (err) {
    throw new GrantError(
      `not a Forestrie-Grant (a completed grant COSE Sign1 with the grant at unprotected label -65538): ${(err as Error).message}`,
    );
  }
  const { grant } = decoded;
  const flags = grant.grant;
  const byte3 = flags.length >= 8 ? flags[3]! : 0;
  const low = flags.length >= 8 ? flags[7]! : 0;
  const dataLog =
    (byte3 & 0x02) !== 0 && (low & 0x02) !== 0 && (low & 0x01) === 0;
  return {
    logId: bytesToUuid(grant.logId),
    ownerLogId: bytesToUuid(grant.ownerLogId),
    flagsHex: toHex(flags),
    grantData: grantDataToBytes(grant.grantData),
    ...(grant.maxHeight !== undefined ? { maxHeight: grant.maxHeight } : {}),
    dataLogStatementGrant: dataLog,
    statementRegistrationGrant:
      dataLog || ((low & 0x03) === 0x01 && (byte3 & 0x03) === 0x03),
    createAndExtend: (byte3 & 0x03) === 0x03,
    authLog: (low & 0x03) === 0x01,
    requiresChildPayment: (byte3 & 0x0c) === 0x0c,
  };
}

/**
 * Why this grant cannot carry statements signed by `signerXY`, or `[]`.
 * Mirrors canopy's register-signed-statement admission
 * (`isStatementRegistrationGrant`, the data-log owner rule, the signer
 * binding).
 */
export function statementGrantProblems(
  grant: GrantView,
  signerXY: Uint8Array,
): string[] {
  const problems: string[] = [];
  if (!grant.statementRegistrationGrant)
    problems.push(
      `grant flags ${grant.flagsHex} do not authorise statement registration (need GF_DATA_LOG with GF_EXTEND, or GF_AUTH_LOG with GF_CREATE|GF_EXTEND)`,
    );
  // canopy applies the distinct-owner rule to data-log grants only.
  if (grant.dataLogStatementGrant && grant.logId === grant.ownerLogId)
    problems.push(
      "a data-log grant must name a log other than its owner (logId equals ownerLogId)",
    );
  if (grant.grantData.length !== 64)
    problems.push(
      `grantData is ${grant.grantData.length} bytes; this package signs with ES256 and needs a 64-byte x‖y`,
    );
  else if (!bytesEqual(grant.grantData, signerXY))
    problems.push(
      "the grant names a different key than this server's log key (grantData ≠ the signer's x‖y); ask the grant issuer for a grant naming the key get_log_key returns",
    );
  return problems;
}

/** Why `prepare` would refuse this grant, or `[]`. Mirrors canopy prepare-child-log. */
export function prepareGrantProblems(grant: GrantView): string[] {
  const problems: string[] = [];
  if (!grant.createAndExtend)
    problems.push(
      `grant flags ${grant.flagsHex} lack GF_CREATE|GF_EXTEND; prepare takes the log's creation grant`,
    );
  if (grant.logId === grant.ownerLogId)
    problems.push("prepare needs a child log (logId equals ownerLogId)");
  if (grant.grantData.length !== 64)
    problems.push(
      `prepare accepts only 64-byte ES256 roots; grantData is ${grant.grantData.length} bytes`,
    );
  return problems;
}
