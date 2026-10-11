/**
 * Read canopy's answers to the write path, over already-fetched responses.
 *
 * The registration contract (canopy `scrapi/register-signed-statement.ts`,
 * `scrapi/query-registration-status.ts`, `scrapi/resolve-receipt.ts`):
 *
 *  - `POST /register/{R}/entries` answers 303 with `Location` = the
 *    transient status URL `…/logs/{R}/{T}/entries/{sha256(statement)}`.
 *  - The status URL answers 303 to itself (`Retry-After`) until the entry is
 *    sequenced, then 303 to the permanent receipt URL
 *    `…/logs/{R}/{T}/{massifHeight}/entries/{entryId}/receipt`.
 *  - The receipt URL answers 404 "checkpoint missing" (or "checkpoint does
 *    not cover entry") until a checkpoint covering the entry is sealed,
 *    then 200 with the receipt. Other 404s are faults.
 *  - Failures are `application/problem+cbor` maps `{title, status, detail?,
 *    reason?}`.
 */
import { decodeCborDeterministic } from "@forestrie/encoding";

/** The parts of a response these readers look at. Headers keyed lowercase. */
export interface ResponseView {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface Problem {
  status: number;
  title: string;
  detail?: string;
  reason?: string;
  /** From the response's Retry-After, e.g. canopy's queue-full 503. */
  retryAfterSeconds?: number;
}

export function readProblem(res: ResponseView): Problem {
  const retry = retryAfter(res);
  const base: Problem = {
    status: res.status,
    title: `HTTP ${res.status}`,
    ...(retry !== undefined ? { retryAfterSeconds: retry } : {}),
  };
  if (res.body.length === 0) return base;
  try {
    const decoded = decodeCborDeterministic(res.body);
    const get = (k: string): unknown =>
      decoded instanceof Map
        ? decoded.get(k)
        : typeof decoded === "object" && decoded !== null
          ? (decoded as Record<string, unknown>)[k]
          : undefined;
    const title = get("title");
    const detail = get("detail");
    const reason = get("reason");
    if (typeof title === "string")
      return {
        ...base,
        title,
        ...(typeof detail === "string" ? { detail } : {}),
        ...(typeof reason === "string" ? { reason } : {}),
      };
  } catch {
    // Not CBOR: fall through to printable text.
  }
  const text = new TextDecoder()
    .decode(res.body)
    .replace(/[^\x20-\x7e]+/g, " ")
    .trim();
  return text ? { ...base, detail: text.slice(0, 200) } : base;
}

/**
 * Resolve a Location against the URL that answered, and keep it on the
 * expected origin: a status or receipt URL that points elsewhere is not
 * followed (the caller would otherwise fetch wherever a server says).
 */
function follow(
  location: string,
  res: ResponseView,
  origin: string | undefined,
): { ok: true; url: string } | { ok: false; problem: Problem } {
  let url: URL;
  try {
    url = new URL(location, res.url);
  } catch {
    return {
      ok: false,
      problem: {
        status: res.status,
        title: "Invalid Location",
        detail: `the Location header is not a URL: ${location.slice(0, 200)}`,
      },
    };
  }
  if (origin !== undefined && url.origin !== origin)
    return {
      ok: false,
      problem: {
        status: res.status,
        title: "Unexpected Location",
        detail: `the Location header points to ${url.origin}, not ${origin}; not following it`,
      },
    };
  return { ok: true, url: url.toString() };
}

/** The origin of a base URL, or `undefined` when it does not parse. */
export function originOf(baseUrl: string): string | undefined {
  try {
    return new URL(baseUrl).origin;
  } catch {
    return undefined;
  }
}

export type RegisterOutcome =
  | { kind: "accepted"; statusUrl: string; retryAfterSeconds?: number }
  | { kind: "problem"; problem: Problem };

export function readRegisterResponse(
  res: ResponseView,
  origin?: string,
): RegisterOutcome {
  if (res.status === 303 && res.headers["location"]) {
    const next = follow(res.headers["location"], res, origin);
    if (!next.ok) return { kind: "problem", problem: next.problem };
    const retry = retryAfter(res);
    return {
      kind: "accepted",
      statusUrl: next.url,
      ...(retry !== undefined ? { retryAfterSeconds: retry } : {}),
    };
  }
  return { kind: "problem", problem: readProblem(res) };
}

const RECEIPT_PATH = /\/(\d+)\/entries\/([0-9a-f]{32})\/receipt$/;

export type StatusOutcome =
  | { kind: "pending"; retryAfterSeconds: number }
  | {
      kind: "sequenced";
      receiptUrl: string;
      massifHeight: number;
      entryId: string;
    }
  | { kind: "problem"; problem: Problem };

export function readStatusResponse(
  res: ResponseView,
  origin?: string,
): StatusOutcome {
  if (res.status !== 303)
    return { kind: "problem", problem: readProblem(res) };
  const next = follow(res.headers["location"] ?? res.url, res, origin);
  if (!next.ok) return { kind: "problem", problem: next.problem };
  const match = RECEIPT_PATH.exec(new URL(next.url).pathname);
  if (match)
    return {
      kind: "sequenced",
      receiptUrl: next.url,
      massifHeight: Number(match[1]),
      entryId: match[2]!,
    };
  return { kind: "pending", retryAfterSeconds: retryAfter(res) ?? 1 };
}

export type ReceiptOutcome =
  | { kind: "sealed"; receipt: Uint8Array; contentType?: string }
  | { kind: "awaiting_seal"; reason: string }
  | { kind: "problem"; problem: Problem };

/**
 * The 404s that mean "sequenced, not yet sealed": no checkpoint yet, or one
 * that predates the entry (canopy `scrapi/resolve-receipt.ts`). canopy
 * answers 404 for other reasons too — a missing massif, a height or index
 * mismatch, an unknown forest — and those will not fix themselves by
 * waiting, so they are problems, with canopy's reason.
 */
const AWAITING_SEAL =
  /checkpoint missing\)$|checkpoint does not cover entry\)$/;

export function readReceiptResponse(res: ResponseView): ReceiptOutcome {
  if (res.status === 404) {
    const problem = readProblem(res);
    if (AWAITING_SEAL.test(problem.title))
      return { kind: "awaiting_seal", reason: problem.title };
    return { kind: "problem", problem };
  }
  if (res.status === 200 && res.body.length > 0)
    return {
      kind: "sealed",
      receipt: res.body,
      ...(res.headers["content-type"]
        ? { contentType: res.headers["content-type"] }
        : {}),
    };
  return { kind: "problem", problem: readProblem(res) };
}

function retryAfter(res: ResponseView): number | undefined {
  const raw = res.headers["retry-after"];
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}
