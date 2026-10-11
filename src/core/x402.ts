/**
 * x402 over already-decoded JSON: read canopy's payment requirements, pick
 * the one option this server may pay, and refuse anything outside its caps.
 *
 * canopy's register-grant gate (canopy `scrapi/register-grant-payment.ts`)
 * answers a payment-gated child grant with 402 and an `X-PAYMENT-REQUIRED`
 * header: base64 of x402 v2 `PaymentRequirements`
 * (`{x402Version: 2, accepts: [{scheme: "exact", network, amount, asset,
 * payTo, maxTimeoutSeconds, extra}], resource: {url, …}}`), priced as a
 * unit price × the child grant's `maxHeight`. The retry carries
 * `X-PAYMENT`: base64 of the x402 v2 `PaymentPayload` (an EIP-3009
 * authorisation for the exact amount).
 *
 * The caps are the server's configuration, never a tool argument: a model
 * (or whatever prompt-injected it) cannot raise them. Every amount is in the
 * asset's atomic units.
 */

export class PaymentError extends Error {
  constructor(
    readonly code:
      "invalid_payment_requirements" | "invalid_payment" | CapRefusalCode,
    message: string,
  ) {
    super(message);
  }
}

export type CapRefusalCode =
  | "cap_network"
  | "cap_asset"
  | "cap_testnet_only"
  | "cap_payee"
  | "cap_resource"
  | "cap_per_call"
  | "cap_per_day";

export interface PaymentOption {
  scheme: "exact";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
}

export interface PaymentRequired {
  x402Version: 2;
  accepts: PaymentOption[];
  resource?: { url: string; description?: string; mimeType?: string };
  error?: string;
}

/** Hard limits from the server's configuration. */
export interface PaymentCaps {
  /** The one CAIP-2 network this server pays on, e.g. `eip155:84532`. */
  network: string;
  /** The one asset contract it pays in, lowercase `0x…`. */
  asset: string;
  maxPerCallAtomic: bigint;
  maxPerDayAtomic: bigint;
  /** When set, the only payee it pays. */
  payTo?: string;
  /** Pay on a network outside {@link TESTNETS}. Off by default. */
  allowMainnet: boolean;
}

/** EVM testnets x402 facilitators settle on. Anything else is mainnet money. */
export const TESTNETS: ReadonlySet<string> = new Set([
  "eip155:84532", // Base Sepolia
  "eip155:11155111", // Ethereum Sepolia
  "eip155:421614", // Arbitrum Sepolia
  "eip155:11155420", // OP Sepolia
  "eip155:80002", // Polygon Amoy
  "eip155:43113", // Avalanche Fuji
]);

/** Base Sepolia, and Circle's USDC on it: the network and asset canopy prices in. */
export const DEFAULT_PAY_NETWORK = "eip155:84532";
export const DEFAULT_PAY_ASSET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

const ATOMIC = /^[0-9]{1,78}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate decoded `X-PAYMENT-REQUIRED` JSON. Throws `PaymentError`. */
export function readPaymentRequired(json: unknown): PaymentRequired {
  const bad = (why: string) =>
    new PaymentError(
      "invalid_payment_requirements",
      `canopy's X-PAYMENT-REQUIRED is not x402 v2 payment requirements: ${why}`,
    );
  if (!isObject(json)) throw bad("not a JSON object");
  if (json["x402Version"] !== 2) throw bad("x402Version is not 2");
  const accepts = json["accepts"];
  if (!Array.isArray(accepts) || accepts.length === 0)
    throw bad("accepts is empty");
  const options: PaymentOption[] = [];
  for (const a of accepts) {
    if (!isObject(a)) throw bad("an accepts entry is not an object");
    const { scheme, network, amount, asset, payTo } = a;
    if (
      typeof scheme !== "string" ||
      typeof network !== "string" ||
      typeof amount !== "string" ||
      typeof asset !== "string" ||
      typeof payTo !== "string"
    )
      throw bad(
        "an accepts entry lacks scheme, network, amount, asset or payTo",
      );
    if (!ATOMIC.test(amount))
      throw bad(`amount ${amount} is not an atomic-unit integer`);
    if (!ADDRESS.test(asset) || !ADDRESS.test(payTo))
      throw bad("asset and payTo must be 0x-prefixed 20-byte addresses");
    if (scheme !== "exact") continue; // the only scheme canopy offers
    options.push({
      scheme,
      network,
      amount,
      asset,
      payTo,
      ...(typeof a["maxTimeoutSeconds"] === "number"
        ? { maxTimeoutSeconds: a["maxTimeoutSeconds"] }
        : {}),
      ...(isObject(a["extra"]) ? { extra: a["extra"] } : {}),
    });
  }
  if (options.length === 0) throw bad('no accepts entry has scheme "exact"');
  const resource = json["resource"];
  return {
    x402Version: 2,
    accepts: options,
    ...(isObject(resource) && typeof resource["url"] === "string"
      ? {
          resource: {
            url: resource["url"],
            ...(typeof resource["description"] === "string"
              ? { description: resource["description"] }
              : {}),
            ...(typeof resource["mimeType"] === "string"
              ? { mimeType: resource["mimeType"] }
              : {}),
          },
        }
      : {}),
    ...(typeof json["error"] === "string" ? { error: json["error"] } : {}),
  };
}

export interface CapContext {
  /** The URL the payment is for: the register-grant URL this server POSTed. */
  resourceUrl: string;
  /** Atomic units already committed today (UTC), on this network and asset. */
  spentTodayAtomic: bigint;
}

/**
 * The one option this server may pay, or a `PaymentError` naming the cap
 * that refuses it. Checked in the order a reader would ask: where, in what,
 * to whom, for what, how much now, how much today.
 */
export function selectWithinCaps(
  required: PaymentRequired,
  caps: PaymentCaps,
  ctx: CapContext,
): PaymentOption {
  const offered = (f: (o: PaymentOption) => string) =>
    [...new Set(required.accepts.map(f))].join(", ");
  if (!TESTNETS.has(caps.network) && !caps.allowMainnet)
    throw new PaymentError(
      "cap_testnet_only",
      `the configured network ${caps.network} is not a testnet, and paying on a mainnet is off (set MCP_REGISTER_PAY_ALLOW_MAINNET=1 to allow it)`,
    );
  const onNetwork = required.accepts.filter((o) => o.network === caps.network);
  if (onNetwork.length === 0)
    throw new PaymentError(
      "cap_network",
      `canopy asks for payment on ${offered((o) => o.network)}; this server pays only on ${caps.network}`,
    );
  const option = onNetwork.find((o) => o.asset.toLowerCase() === caps.asset);
  if (option === undefined)
    throw new PaymentError(
      "cap_asset",
      `canopy asks for payment in ${offered((o) => o.asset)}; this server pays only in ${caps.asset}`,
    );
  if (
    caps.payTo !== undefined &&
    option.payTo.toLowerCase() !== caps.payTo.toLowerCase()
  )
    throw new PaymentError(
      "cap_payee",
      `canopy asks for payment to ${option.payTo}; this server pays only ${caps.payTo}`,
    );
  if (
    required.resource !== undefined &&
    stripQuery(required.resource.url) !== stripQuery(ctx.resourceUrl)
  )
    throw new PaymentError(
      "cap_resource",
      `the payment requirements are for ${required.resource.url}, not the request this server made (${ctx.resourceUrl})`,
    );
  const amount = BigInt(option.amount);
  if (amount > caps.maxPerCallAtomic)
    throw new PaymentError(
      "cap_per_call",
      `canopy asks ${option.amount} atomic units; this server's per-call cap is ${caps.maxPerCallAtomic}. Issue a grant with a smaller maxHeight, or pay in relay mode from a wallet you control`,
    );
  if (ctx.spentTodayAtomic + amount > caps.maxPerDayAtomic)
    throw new PaymentError(
      "cap_per_day",
      `paying ${option.amount} would bring today's (UTC) spend to ${ctx.spentTodayAtomic + amount} atomic units; this server's daily cap is ${caps.maxPerDayAtomic}`,
    );
  return option;
}

function stripQuery(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return url;
  }
}

/** What an `X-PAYMENT` authorises, for reporting. Never includes the signature. */
export interface PaymentSummary {
  network: string;
  asset?: string;
  from: string;
  to: string;
  value: string;
  nonce: string;
  validBefore: string;
}

/** Read decoded `X-PAYMENT` JSON (x402 v2 exact EVM). Throws `PaymentError`. */
export function readPaymentPayload(json: unknown): PaymentSummary {
  const bad = (why: string) =>
    new PaymentError(
      "invalid_payment",
      `the payment is not an x402 v2 exact EVM payment payload: ${why}`,
    );
  if (!isObject(json)) throw bad("not a JSON object");
  if (json["x402Version"] !== 2 && json["x402Version"] !== 1)
    throw bad("x402Version is not 1 or 2");
  const accepted = isObject(json["accepted"]) ? json["accepted"] : json;
  const payload = json["payload"];
  if (!isObject(payload)) throw bad("payload is missing");
  const auth = payload["authorization"];
  if (!isObject(auth)) throw bad("payload.authorization is missing");
  const field = (k: string): string => {
    const v = auth[k];
    if (typeof v !== "string") throw bad(`authorization.${k} is missing`);
    return v;
  };
  const network = accepted["network"];
  if (typeof network !== "string") throw bad("network is missing");
  return {
    network,
    ...(typeof accepted["asset"] === "string"
      ? { asset: accepted["asset"] }
      : {}),
    from: field("from"),
    to: field("to"),
    value: field("value"),
    nonce: field("nonce"),
    validBefore: field("validBefore"),
  };
}
