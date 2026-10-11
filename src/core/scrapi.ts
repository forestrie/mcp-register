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
 *  - The receipt URL answers 404 until a checkpoint covering the entry is
 *    sealed, then 200 with the receipt.
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
}

export function readProblem(res: ResponseView): Problem {
  const fallback: Problem = {
    status: res.status,
    title: `HTTP ${res.status}`,
  };
  if (res.body.length === 0) return fallback;
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
        status: res.status,
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
  return text ? { ...fallback, detail: text.slice(0, 500) } : fallback;
}

function absolute(location: string, base: string): string {
  return new URL(location, base).toString();
}

export type RegisterOutcome =
  | { kind: "accepted"; statusUrl: string; retryAfterSeconds?: number }
  | { kind: "problem"; problem: Problem };

export function readRegisterResponse(res: ResponseView): RegisterOutcome {
  if (res.status === 303 && res.headers["location"]) {
    const retry = retryAfter(res);
    return {
      kind: "accepted",
      statusUrl: absolute(res.headers["location"], res.url),
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

export function readStatusResponse(res: ResponseView): StatusOutcome {
  if (res.status !== 303)
    return { kind: "problem", problem: readProblem(res) };
  const location = absolute(res.headers["location"] ?? res.url, res.url);
  const match = RECEIPT_PATH.exec(new URL(location).pathname);
  if (match)
    return {
      kind: "sequenced",
      receiptUrl: location,
      massifHeight: Number(match[1]),
      entryId: match[2]!,
    };
  return { kind: "pending", retryAfterSeconds: retryAfter(res) ?? 1 };
}

export type ReceiptOutcome =
  | { kind: "sealed"; receipt: Uint8Array; contentType?: string }
  | { kind: "awaiting_seal" }
  | { kind: "problem"; problem: Problem };

export function readReceiptResponse(res: ResponseView): ReceiptOutcome {
  if (res.status === 404) return { kind: "awaiting_seal" };
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
