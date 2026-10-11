/**
 * The one request helper the write path uses. Same contract as
 * `@forestrie/mcp-resolve/net`'s readers, whose `NetError` and
 * `RawResponse` it reuses: `redirect: "manual"` (a 303 is the answer, not
 * something to follow), every non-2xx returned rather than thrown, and
 * `NetError` only when no response was obtained.
 */
import {
  NetError,
  type FetchOptions,
  type RawResponse,
} from "@forestrie/mcp-resolve/net";

export const DEFAULT_TIMEOUT_MS = 30_000;

export interface RequestInit {
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: Uint8Array | string;
}

export async function rawRequest(
  url: string,
  init: RequestInit,
  opts?: FetchOptions,
): Promise<RawResponse> {
  const fetchImpl = opts?.fetchImpl ?? globalThis.fetch;
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const at = new Date().toISOString();
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new NetError("timeout", `timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    const res = await Promise.race([
      fetchImpl(url, {
        method: init.method,
        redirect: "manual",
        signal: controller.signal,
        ...(init.headers ? { headers: init.headers } : {}),
        ...(init.body !== undefined ? { body: init.body as BodyInit } : {}),
      }),
      timeout,
    ]);
    const body = new Uint8Array(
      await Promise.race([res.arrayBuffer(), timeout]),
    );
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return { url, status: res.status, headers, body, at };
  } catch (err) {
    if (err instanceof NetError) throw err;
    throw new NetError(
      "network",
      `network error on ${init.method} ${url}: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    );
  } finally {
    clearTimeout(timer);
  }
}

export function trimBase(url: string): string {
  return url.replace(/\/+$/, "");
}
