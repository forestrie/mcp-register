import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  readProblem,
  readReceiptResponse,
  readRegisterResponse,
  readStatusResponse,
  type ResponseView,
} from "../../src/core/scrapi.js";
import { loadExchange, type Exchange } from "../net/replay.js";
import { LANE_A_DIR, coordinates, ex } from "../net/write-path-fixture.js";

function view(e: Exchange): ResponseView {
  return { url: e.url, status: e.status, headers: e.headers, body: e.body };
}

const lane = JSON.parse(
  readFileSync(path.join(LANE_A_DIR, "coordinates.json"), "utf8"),
) as {
  entryId: string;
  massifHeight: number;
  receiptUrl: string;
  baseUrl: string;
};

const c = coordinates;
const statusUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/entries/${c.statusEntryHash}`;
const receiptUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/${c.massifHeight}/entries/${c.entryId}/receipt`;

describe("synthetic recordings", () => {
  it("register 303 is accepted, with the status URL and retry-after", () => {
    expect(readRegisterResponse(view(ex("register-303")))).toEqual({
      kind: "accepted",
      statusUrl,
      retryAfterSeconds: 5,
    });
  });

  it("register 403 is a problem carrying the CBOR fields", () => {
    const out = readRegisterResponse(view(ex("register-403")));
    expect(out).toEqual({
      kind: "problem",
      problem: {
        status: 403,
        title: "Forbidden",
        detail: "statement signer does not match the grant's grantData",
        reason: "signer_mismatch",
      },
    });
  });

  it("a 303 without a location is a problem, not an acceptance", () => {
    const out = readRegisterResponse({
      url: statusUrl,
      status: 303,
      headers: {},
      body: new Uint8Array(0),
    });
    expect(out.kind).toBe("problem");
  });

  it("status pending is retry-after 1", () => {
    expect(readStatusResponse(view(ex("status-pending")))).toEqual({
      kind: "pending",
      retryAfterSeconds: 1,
    });
  });

  it("status pending without retry-after defaults to 1", () => {
    const e = ex("status-pending");
    const { "retry-after": _r, ...headers } = e.headers;
    expect(readStatusResponse({ ...view(e), headers })).toEqual({
      kind: "pending",
      retryAfterSeconds: 1,
    });
  });

  it("status sequenced yields the receipt URL, entry id and massif height", () => {
    expect(readStatusResponse(view(ex("status-sequenced")))).toEqual({
      kind: "sequenced",
      receiptUrl,
      massifHeight: c.massifHeight,
      entryId: c.entryId,
    });
  });

  it("a non-303 status answer is a problem", () => {
    const out = readStatusResponse(view(ex("receipt-404")));
    expect(out).toMatchObject({
      kind: "problem",
      problem: { status: 404, title: "Not Found" },
    });
  });

  it("receipt 404 is awaiting_seal", () => {
    expect(readReceiptResponse(view(ex("receipt-404")))).toEqual({
      kind: "awaiting_seal",
    });
  });

  it("receipt 200 is sealed, with the body and content type", () => {
    const e = ex("receipt-200");
    const out = readReceiptResponse(view(e));
    expect(out).toEqual({
      kind: "sealed",
      receipt: e.body,
      contentType: "application/scitt.receipt+cose",
    });
  });

  it("a 200 with an empty body is a problem, not a seal", () => {
    expect(
      readReceiptResponse({
        url: receiptUrl,
        status: 200,
        headers: {},
        body: new Uint8Array(0),
      }).kind,
    ).toBe("problem");
  });

  it("readProblem reads the CBOR map, and falls back to status and printable text", () => {
    expect(readProblem(view(ex("prepare-403")))).toEqual({
      status: 403,
      title: "Forbidden",
      detail: "grant not accepted for prepare",
      reason: "grant_rejected",
    });
    expect(
      readProblem({
        url: statusUrl,
        status: 502,
        headers: {},
        body: new Uint8Array(0),
      }),
    ).toEqual({ status: 502, title: "HTTP 502" });
    expect(
      readProblem({
        url: statusUrl,
        status: 502,
        headers: {},
        body: new TextEncoder().encode("bad gateway\u0000\u0001"),
      }),
    ).toEqual({ status: 502, title: "HTTP 502", detail: "bad gateway" });
  });
});

describe("real lane-a-0.5.0 recordings", () => {
  it("status-self is sequenced, at the coordinates the lane recorded", () => {
    const out = readStatusResponse(
      view(loadExchange(LANE_A_DIR, "status-self")),
    );
    expect(out).toEqual({
      kind: "sequenced",
      receiptUrl: lane.receiptUrl,
      massifHeight: lane.massifHeight,
      entryId: lane.entryId,
    });
  });

  it("receipt-self is sealed", () => {
    const e = loadExchange(LANE_A_DIR, "receipt-self", "receipt-self.cbor");
    const out = readReceiptResponse(view(e));
    expect(out.kind).toBe("sealed");
    if (out.kind === "sealed") {
      expect(out.receipt).toHaveLength(438);
      expect(out.contentType).toBe("application/scitt.receipt+cose");
    }
  });

  it("status-unknown (an entry canopy has never seen) is a 303 to itself: pending, retry 1", () => {
    // The real service answers an unknown content hash exactly as it answers
    // a not-yet-sequenced one: 303 to the same URL with Retry-After 1. There
    // is no 404 to distinguish "never registered" from "not yet sequenced".
    const e = loadExchange(LANE_A_DIR, "status-unknown");
    expect(e.status).toBe(303);
    expect(e.headers["location"]).toBe(e.url);
    expect(readStatusResponse(view(e))).toEqual({
      kind: "pending",
      retryAfterSeconds: 1,
    });
  });
});
