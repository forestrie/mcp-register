/**
 * A stub x402 facilitator and the register-grant endpoint in front of it,
 * for tests to inject through `fetchImpl`.
 *
 * The stub does what a facilitator's /verify does for the "exact" EVM
 * scheme, offline: it decodes the `X-PAYMENT`, checks that it answers the
 * requirements canopy issued (scheme, network, asset, payee, exact amount,
 * validity window), and recovers the EIP-712 `TransferWithAuthorization`
 * signature against the payer named in the authorisation. It settles
 * nothing. canopy's answer then comes from the recorded fixtures: 303 when
 * the stub accepts, the recorded refused 402 when it does not.
 *
 * Like canopy (`claimPaymentAuthorizationIdempotent`), an authorisation is
 * single-use per grant: the same one re-presented for the same grant is
 * accepted again; for a different grant it is refused.
 */
import { verifyTypedData } from "viem";
import type { Exchange, RecordedCall } from "./replay.js";

export interface Requirement {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: { name?: string; version?: string };
}

export interface FacilitatorVerdict {
  isValid: boolean;
  invalidReason?: string;
  payer?: string;
}

const TRANSFER_WITH_AUTHORIZATION = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export function decodeB64Json(value: string): any {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
}

export function encodeB64Json(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

/** Verify an `X-PAYMENT` value against one requirement, as /verify would. */
export async function stubVerify(
  xPayment: string,
  req: Requirement,
  nowSeconds: number,
): Promise<FacilitatorVerdict> {
  let p: any;
  try {
    p = decodeB64Json(xPayment);
  } catch {
    return { isValid: false, invalidReason: "invalid_payload" };
  }
  const accepted = p?.accepted ?? {};
  const auth = p?.payload?.authorization;
  const signature = p?.payload?.signature;
  if (p?.x402Version !== 2 || !auth || typeof signature !== "string")
    return { isValid: false, invalidReason: "invalid_payload" };
  if (accepted.scheme !== req.scheme)
    return { isValid: false, invalidReason: "unsupported_scheme" };
  if (accepted.network !== req.network)
    return { isValid: false, invalidReason: "invalid_network" };
  if (String(accepted.asset).toLowerCase() !== req.asset.toLowerCase())
    return {
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_asset",
    };
  if (String(auth.to).toLowerCase() !== req.payTo.toLowerCase())
    return {
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_recipient_mismatch",
    };
  if (auth.value !== req.amount)
    return {
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_authorization_value",
    };
  if (
    BigInt(auth.validBefore) <= BigInt(nowSeconds) ||
    BigInt(auth.validAfter) > BigInt(nowSeconds)
  )
    return {
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_authorization_valid_before",
    };
  const chainId = Number(req.network.split(":")[1]);
  const ok = await verifyTypedData({
    address: auth.from,
    domain: {
      name: req.extra?.name ?? "USDC",
      version: req.extra?.version ?? "2",
      chainId,
      verifyingContract: req.asset as `0x${string}`,
    },
    types: TRANSFER_WITH_AUTHORIZATION,
    primaryType: "TransferWithAuthorization",
    message: {
      from: auth.from,
      to: auth.to,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce,
    },
    signature: signature as `0x${string}`,
  });
  if (!ok)
    return {
      isValid: false,
      invalidReason: "invalid_exact_evm_payload_signature",
    };
  return { isValid: true, payer: auth.from };
}

export interface GrantEndpoint {
  fetch: typeof fetch;
  /** Every call to the register-grant URL, in order. */
  posts: RecordedCall[];
  /** The stub's verdict on each X-PAYMENT it saw. */
  verdicts: FacilitatorVerdict[];
}

/**
 * The register-grant URL answered by canopy's rules over the recorded
 * exchanges, with the stub as its facilitator; every other URL goes to
 * `rest`.
 *
 *  - no X-PAYMENT and a payment-gated parent: `challenge` (402);
 *  - an X-PAYMENT the stub refuses, or one already claimed for another
 *    grant: `refused` (402);
 *  - otherwise: `accepted` (303), or `answers` in order when given (to
 *    script a 409, a network failure, …).
 */
export function grantEndpoint(opts: {
  url: string;
  challenge: Exchange;
  refused: Exchange;
  accepted: Exchange;
  rest: typeof fetch;
  /** The parent is payment-gated (default true). */
  gated?: boolean;
  nowSeconds?: () => number;
  /** Scripted answers to a POST that is otherwise admitted. */
  answers?: Array<Exchange | Error>;
}): GrantEndpoint {
  const posts: RecordedCall[] = [];
  const verdicts: FacilitatorVerdict[] = [];
  const claims = new Map<string, string>();
  const respond = (ex: Exchange) =>
    new Response(ex.body.length === 0 ? null : (ex.body as BodyInit), {
      status: ex.status,
      headers: ex.headers,
    });
  const requirement = (): Requirement =>
    decodeB64Json(opts.challenge.headers["x-payment-required"]!).accepts[0];

  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url !== opts.url || (init?.method ?? "GET").toUpperCase() !== "POST")
      return opts.rest(input as RequestInfo, init);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => (headers[k] = v));
    const body =
      init?.body instanceof Uint8Array
        ? new Uint8Array(init.body)
        : new Uint8Array(0);
    posts.push({ method: "POST", url, headers, body });
    const grant = headers["authorization"] ?? "";
    if (opts.gated !== false) {
      const xPayment = headers["x-payment"];
      if (xPayment === undefined) return respond(opts.challenge);
      const verdict = await stubVerify(
        xPayment,
        requirement(),
        opts.nowSeconds?.() ?? Math.floor(Date.now() / 1000),
      );
      verdicts.push(verdict);
      if (!verdict.isValid) return respond(opts.refused);
      const nonce = decodeB64Json(xPayment).payload.authorization.nonce;
      const claimed = claims.get(nonce);
      if (claimed !== undefined && claimed !== grant)
        return respond(opts.refused);
      claims.set(nonce, grant);
    }
    const next = opts.answers?.shift();
    if (next instanceof Error) throw next;
    return respond(next ?? opts.accepted);
  }) as typeof fetch;
  return { fetch: f, posts, verdicts };
}
