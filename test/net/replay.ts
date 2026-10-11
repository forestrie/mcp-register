/**
 * A fake `fetch` built from recorded exchanges, for tests to inject through
 * `fetchImpl`. Never touches `globalThis.fetch`, which the unit project's
 * `test/setup/forbid-fetch.ts` replaces with a thrower.
 *
 * Responses are keyed by `METHOD URL`. Each key holds a QUEUE consumed in
 * order, so a status URL can answer "pending" then "sequenced". An unknown
 * key, or a queue already used up, throws: a request the test did not
 * expect is a bug, not a fixture gap.
 *
 * Every call is recorded with its method, URL, lowercased headers and body
 * bytes, so a test can assert what was sent, including that nothing was.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

export interface Exchange {
  method: string;
  url: string;
  status: number;
  /** Response headers, lowercase keys. */
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface RecordedCall {
  method: string;
  url: string;
  /** Request headers, lowercase keys. */
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface Replay {
  fetch: typeof fetch;
  calls: RecordedCall[];
  /** The recorded calls made to `METHOD url`. */
  callsTo(method: string, url: string): RecordedCall[];
  /** Responses queued but not yet consumed, over all keys. */
  remaining(): number;
}

interface Meta {
  url: string;
  method?: string;
  status: number;
  headers: Record<string, string>;
  bodyFile?: string | null;
}

/**
 * Load `<name>.meta.json` and its body from a fixture directory. The body
 * file is `meta.bodyFile` (the synthetic fixtures), else `bodyFile` when the
 * caller names one (the lane-a recordings keep `receipt-self.cbor` apart
 * from the meta), else empty. The method defaults to GET, as lane-a's
 * recordings carry it.
 */
export function loadExchange(
  dir: string,
  name: string,
  bodyFile?: string,
): Exchange {
  const meta = JSON.parse(
    readFileSync(path.join(dir, `${name}.meta.json`), "utf8"),
  ) as Meta;
  const file = meta.bodyFile ?? bodyFile;
  const body =
    file === undefined || file === null
      ? new Uint8Array(0)
      : new Uint8Array(readFileSync(path.join(dir, file)));
  return {
    method: (meta.method ?? "GET").toUpperCase(),
    url: meta.url,
    status: meta.status,
    headers: Object.fromEntries(
      Object.entries(meta.headers).map(([k, v]) => [k.toLowerCase(), v]),
    ),
    body,
  };
}

function lowerHeaders(h: HeadersInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (h === undefined) return out;
  new Headers(h).forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function bodyBytes(body: BodyInit | null | undefined): Uint8Array {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return new Uint8Array(body);
  throw new Error("replay: unsupported request body type");
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** Exchanges for the same `METHOD URL` are answered in the order given. */
export function createReplay(exchanges: Exchange[]): Replay {
  const queues = new Map<string, Exchange[]>();
  for (const ex of exchanges) {
    const key = `${ex.method} ${ex.url}`;
    const q = queues.get(key);
    if (q) q.push(ex);
    else queues.set(key, [ex]);
  }
  const calls: RecordedCall[] = [];

  const replayFetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const method = (init?.method ?? "GET").toUpperCase();
    const url = requestUrl(input);
    calls.push({
      method,
      url,
      headers: lowerHeaders(init?.headers),
      body: bodyBytes(init?.body),
    });
    const key = `${method} ${url}`;
    const q = queues.get(key);
    if (q === undefined)
      throw new Error(`replay: no recorded exchange for ${key}`);
    const ex = q.shift();
    if (ex === undefined)
      throw new Error(`replay: every recorded response for ${key} was used`);
    // A null-body status takes no body; every other status may carry one.
    const nullBody = ex.body.length === 0;
    return new Response(nullBody ? null : (ex.body as BodyInit), {
      status: ex.status,
      headers: ex.headers,
    });
  }) as typeof fetch;

  return {
    fetch: replayFetch,
    calls,
    callsTo: (method, url) =>
      calls.filter((c) => c.method === method && c.url === url),
    remaining: () => [...queues.values()].reduce((n, q) => n + q.length, 0),
  };
}
