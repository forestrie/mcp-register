/**
 * The write path's requests. Thin: each builds one request, returns the
 * raw response, and leaves reading it to `src/core/scrapi.ts` or
 * `src/core/delegation.ts`. Every function takes `fetchImpl` through
 * `opts`.
 *
 * Endpoints, all public and none needing an operator token:
 *
 *  - canopy `POST /register/{R}/entries`, the statement as
 *    `application/cose`, authorised by `Forestrie-Grant <base64>`;
 *  - canopy `POST /api/forest/{childLogId}/prepare`, no body, the same
 *    grant: publishes the child log's public root to the delegation
 *    coordinator when register-grant's auto-forward did not;
 *  - coordinator `GET /api/logs/{logId}/pending-delegation`;
 *  - coordinator `POST /api/delegations/certificate`, JSON.
 */
import type { FetchOptions, RawResponse } from "@forestrie/mcp-resolve/net";
import type { CertificateSubmission } from "../core/delegation.js";
import { rawRequest, trimBase } from "./http.js";

export function postStatement(
  input: {
    baseUrl: string;
    rootLogId: string;
    statement: Uint8Array;
    grantB64: string;
  },
  opts?: FetchOptions,
): Promise<RawResponse> {
  return rawRequest(
    `${trimBase(input.baseUrl)}/register/${encodeURIComponent(input.rootLogId)}/entries`,
    {
      method: "POST",
      headers: {
        "content-type": "application/cose",
        authorization: `Forestrie-Grant ${input.grantB64}`,
      },
      body: input.statement,
    },
    opts,
  );
}

export function getRegistrationStatus(
  input: { statusUrl: string },
  opts?: FetchOptions,
): Promise<RawResponse> {
  return rawRequest(input.statusUrl, { method: "GET" }, opts);
}

export function prepareChildLog(
  input: { baseUrl: string; logId: string; grantB64: string },
  opts?: FetchOptions,
): Promise<RawResponse> {
  return rawRequest(
    `${trimBase(input.baseUrl)}/api/forest/${encodeURIComponent(input.logId)}/prepare`,
    {
      method: "POST",
      headers: { authorization: `Forestrie-Grant ${input.grantB64}` },
    },
    opts,
  );
}

export function getPendingDelegation(
  input: { coordinatorUrl: string; logId: string },
  opts?: FetchOptions,
): Promise<RawResponse> {
  return rawRequest(
    `${trimBase(input.coordinatorUrl)}/api/logs/${encodeURIComponent(input.logId)}/pending-delegation`,
    { method: "GET", headers: { accept: "application/json" } },
    opts,
  );
}

export function postDelegationCertificate(
  input: { coordinatorUrl: string; submission: CertificateSubmission },
  opts?: FetchOptions,
): Promise<RawResponse> {
  return rawRequest(
    `${trimBase(input.coordinatorUrl)}/api/delegations/certificate`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input.submission),
    },
    opts,
  );
}
