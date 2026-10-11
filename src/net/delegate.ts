/**
 * Delegate sealing for the caller's data log, falling back to `prepare`.
 *
 *   1. GET pending-delegation. A standing entry means the coordinator knows
 *      the log's public root and has a vouched sealer key for it.
 *   2. No standing entry: the coordinator never learned the root. canopy
 *      forwards it at register-grant, best effort; `POST
 *      /api/forest/{child}/prepare` under the same creation grant does it
 *      explicitly. Then poll pending-delegation again, a bounded number of
 *      times.
 *   3. Verify the registrar voucher against the pinned sealer key, build the
 *      certificate and on-chain proof with the log key, and submit them.
 *
 * Each failure names its stage, so the caller can tell "prepare refused the
 * grant" from "the coordinator rejected the certificate".
 */
import type { FetchOptions } from "@forestrie/mcp-resolve/net";
import {
  buildCertificateSubmission,
  checkVoucher,
  type CertificateSubmission,
  DelegationError,
  findStandingEntry,
  type StandingEntry,
} from "../core/delegation.js";
import { prepareGrantProblems, type GrantView } from "../core/grant.js";
import { readProblem, type Problem } from "../core/scrapi.js";
import type { Es256Signer } from "../core/signer.js";
import {
  getPendingDelegation,
  postDelegationCertificate,
  prepareChildLog,
} from "./write.js";

export type DelegateStage =
  "pending_delegation" | "prepare" | "voucher" | "certificate";

export interface DelegateSealingInput {
  baseUrl: string;
  coordinatorUrl: string;
  /** The registrar's voucher key, 64 bytes x‖y, pinned out of band. */
  knownSealerKeyXY: Uint8Array;
  grantB64: string;
  grant: GrantView;
  mmrEnd?: number;
  ttlSeconds?: number;
  /** Polls of pending-delegation after a successful prepare. Default 5. */
  pollsAfterPrepare?: number;
  /** Wait between those polls, ms. Default 2000. */
  pollIntervalMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export type DelegateSealingOutcome =
  | {
      kind: "delegated";
      logId: string;
      sealerId: string;
      epoch: number;
      mmrEnd: number;
      issuedAt: number;
      expiresAt: number;
      /** True when this call had to run prepare first. */
      prepared: boolean;
      certificateKey?: string;
    }
  | {
      kind: "problem";
      stage: DelegateStage;
      message: string;
      problem?: Problem;
      prepared: boolean;
    };

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export async function delegateSealing(
  input: DelegateSealingInput,
  signer: Es256Signer,
  opts?: FetchOptions,
): Promise<DelegateSealingOutcome> {
  const logId = input.grant.logId;
  let prepared = false;

  const readStanding = async (): Promise<
    | { ok: true; standing: StandingEntry | undefined }
    | { ok: false; outcome: DelegateSealingOutcome }
  > => {
    const res = await getPendingDelegation(
      { coordinatorUrl: input.coordinatorUrl, logId },
      opts,
    );
    if (res.status !== 200)
      return {
        ok: false,
        outcome: {
          kind: "problem",
          stage: "pending_delegation",
          message: `pending-delegation answered HTTP ${res.status}`,
          problem: readJsonProblem(res.status, res.body),
          prepared,
        },
      };
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder().decode(res.body));
    } catch {
      return {
        ok: false,
        outcome: {
          kind: "problem",
          stage: "pending_delegation",
          message: "pending-delegation did not return JSON",
          prepared,
        },
      };
    }
    try {
      return { ok: true, standing: findStandingEntry(body) };
    } catch (err) {
      return {
        ok: false,
        outcome: {
          kind: "problem",
          stage:
            err instanceof DelegationError && err.code === "voucher_rejected"
              ? "voucher"
              : "pending_delegation",
          message: (err as Error).message,
          prepared,
        },
      };
    }
  };

  let read = await readStanding();
  if (!read.ok) return read.outcome;

  if (read.standing === undefined) {
    const refusals = prepareGrantProblems(input.grant);
    if (refusals.length > 0)
      return {
        kind: "problem",
        stage: "prepare",
        message: `the coordinator has no standing sealer key for log ${logId} (its public root was never forwarded), and prepare cannot fix that with this grant: ${refusals.join("; ")}`,
        prepared,
      };
    const res = await prepareChildLog(
      { baseUrl: input.baseUrl, logId, grantB64: input.grantB64 },
      opts,
    );
    if (res.status < 200 || res.status >= 300)
      return {
        kind: "problem",
        stage: "prepare",
        message: `prepare answered HTTP ${res.status}`,
        problem: readProblem(res),
        prepared,
      };
    prepared = true;
    const sleep = input.sleep ?? defaultSleep;
    const polls = input.pollsAfterPrepare ?? 5;
    for (let i = 0; i < polls; i++) {
      await sleep(input.pollIntervalMs ?? 2000);
      read = await readStanding();
      if (!read.ok) return read.outcome;
      if (read.standing !== undefined) break;
    }
    if (read.standing === undefined)
      return {
        kind: "problem",
        stage: "pending_delegation",
        message: `prepare succeeded, but after ${polls} polls the coordinator still offers no standing sealer key for log ${logId}; try delegate_sealing again shortly`,
        prepared,
      };
  }
  const standing = read.standing;

  try {
    await checkVoucher(standing, input.knownSealerKeyXY);
  } catch (err) {
    return {
      kind: "problem",
      stage: "voucher",
      message: (err as Error).message,
      prepared,
    };
  }

  let submission: CertificateSubmission;
  try {
    submission = await buildCertificateSubmission(
      {
        logId,
        standing,
        ...(input.mmrEnd !== undefined ? { mmrEnd: input.mmrEnd } : {}),
        ...(input.ttlSeconds !== undefined
          ? { ttlSeconds: input.ttlSeconds }
          : {}),
      },
      signer,
    );
  } catch (err) {
    // A malformed standing key, a bad ttl or a signer failure: report it
    // at its stage rather than as a raw throw.
    return {
      kind: "problem",
      stage: "certificate",
      message: `could not build the delegation certificate: ${err instanceof Error ? err.message : String(err)}`,
      prepared,
    };
  }
  const res = await postDelegationCertificate(
    { coordinatorUrl: input.coordinatorUrl, submission },
    opts,
  );
  if (res.status < 200 || res.status >= 300)
    return {
      kind: "problem",
      stage: "certificate",
      message: `the coordinator rejected the delegation certificate: HTTP ${res.status}`,
      problem: readJsonProblem(res.status, res.body),
      prepared,
    };
  let certificateKey: string | undefined;
  try {
    const body = JSON.parse(new TextDecoder().decode(res.body)) as {
      certificateKey?: unknown;
    };
    if (typeof body.certificateKey === "string")
      certificateKey = body.certificateKey;
  } catch {
    // A 2xx without a JSON body still means accepted.
  }
  return {
    kind: "delegated",
    logId,
    sealerId: standing.sealerId,
    epoch: standing.epoch,
    mmrEnd: submission.mmrEnd,
    issuedAt: submission.issuedAt,
    expiresAt: submission.expiresAt,
    prepared,
    ...(certificateKey !== undefined ? { certificateKey } : {}),
  };
}

function readJsonProblem(status: number, body: Uint8Array): Problem {
  const text = new TextDecoder().decode(body);
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const title =
      typeof parsed.title === "string"
        ? parsed.title
        : typeof parsed.error === "string"
          ? parsed.error
          : `HTTP ${status}`;
    const detail =
      typeof parsed.detail === "string"
        ? parsed.detail
        : typeof parsed.message === "string"
          ? parsed.message
          : undefined;
    return { status, title, ...(detail !== undefined ? { detail } : {}) };
  } catch {
    const printable = text.replace(/[^\x20-\x7e]+/g, " ").trim();
    return {
      status,
      title: `HTTP ${status}`,
      ...(printable ? { detail: printable.slice(0, 500) } : {}),
    };
  }
}
