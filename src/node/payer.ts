/**
 * The payer backend: what pays canopy's 402 when register_grant meets one.
 *
 * Separate from the log key and the authority key (D6): those are ES256 and
 * hold no funds; the payer is an EVM account that holds testnet USDC and
 * signs only standard x402 authorisations (EIP-3009
 * `transferWithAuthorization`, the "exact" scheme). The default backend is
 * a viem account loaded from a local key file. An embedder passes its own
 * `PayerBackend` (a hosted wallet) to `createServer({ payer })`.
 *
 * The default backend builds the x402 v2 payment payload exactly as the
 * upstream client does (`@x402/evm`'s `createEIP3009Payload`), with one
 * difference: the nonce is the one register_grant derives from the grant
 * (`grantPaymentNonce`), where upstream draws a random one and offers no way
 * to supply it. A derived nonce is what makes paying twice for one grant
 * impossible rather than merely avoided. `test/node/payer.test.ts` checks
 * the payload against the upstream client's, field for field.
 *
 * The payer key never crosses the MCP boundary: no tool takes or returns it,
 * the file is refused if it is a symlink or readable by others, and no
 * `{path}` input may read it. The caps are configuration
 * (`readPaymentCaps`), never tool arguments.
 */
import { lstatSync, readFileSync } from "node:fs";
import { getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  DEFAULT_PAY_ASSET,
  DEFAULT_PAY_NETWORK,
  type PaymentCaps,
  type PaymentOption,
  type PaymentRequired,
} from "../core/x402.js";

export interface PayerBackend {
  /** The paying account, `0x…`: public, safe to report. */
  readonly address: string;
  /** Where the key lives, for humans: never key material. */
  readonly description: string;
  /**
   * Sign a payment for exactly `option` (already checked against the caps)
   * and return the `X-PAYMENT` header value: base64 of the x402 v2 payment
   * payload. The authorisation MUST carry `nonce`; register_grant refuses
   * to send one that does not.
   */
  pay(request: PayRequest): Promise<string>;
}

export interface PayRequest {
  required: PaymentRequired;
  option: PaymentOption;
  /** The EIP-3009 nonce, `0x` + 64 hex, derived from the grant. */
  nonce: string;
  /** Seconds since the epoch; validBefore is this plus maxTimeoutSeconds. */
  nowSeconds: number;
}

export class PayerError extends Error {
  constructor(
    readonly code: "payer_unavailable" | "payer_misconfigured",
    message: string,
  ) {
    super(message);
  }
}

const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const ATOMIC = /^[0-9]{1,78}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * Load an EVM private key (`0x` + 64 hex, one line) from `path`. Refused,
 * as the log key is, when the path is a symlink or the file is accessible to
 * group or others.
 */
export function openKeyFilePayer(path: string): PayerBackend {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (err) {
    throw new PayerError(
      "payer_unavailable",
      `cannot open the payer key file ${path}: ${(err as Error).message}`,
    );
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    throw new PayerError(
      "payer_unavailable",
      `the payer key path ${path} is not a regular file (a symlink or directory is refused)`,
    );
  if ((stat.mode & 0o077) !== 0)
    throw new PayerError(
      "payer_unavailable",
      `the payer key file ${path} is accessible to other users (mode ${(stat.mode & 0o777).toString(8)}); chmod 600 it`,
    );
  const text = readFileSync(path, "utf8").trim();
  if (!PRIVATE_KEY.test(text))
    throw new PayerError(
      "payer_unavailable",
      `the payer key file ${path} must hold one EVM private key: 0x followed by 64 hex digits`,
    );
  return evmPayer(text as `0x${string}`, `local payer key file ${path}`);
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

/** An EIP-3009 "exact" payer over a viem account. */
export function evmPayer(
  privateKey: `0x${string}`,
  description: string,
): PayerBackend {
  const account = privateKeyToAccount(privateKey);
  return {
    address: account.address,
    description,
    pay: async ({ required, option, nonce, nowSeconds }) => {
      const chainId = Number(option.network.split(":")[1]);
      const name = option.extra?.["name"];
      const version = option.extra?.["version"];
      if (!/^eip155:[0-9]+$/.test(option.network))
        throw new Error(`not an EVM network: ${option.network}`);
      if (typeof name !== "string" || typeof version !== "string")
        throw new Error(
          `the payment requirements lack the EIP-712 domain (extra.name, extra.version) for asset ${option.asset}`,
        );
      if (!/^0x[0-9a-f]{64}$/.test(nonce))
        throw new Error(`nonce must be 0x + 64 lowercase hex`);
      const authorization = {
        from: account.address,
        to: getAddress(option.payTo),
        value: option.amount,
        validAfter: "0",
        validBefore: String(nowSeconds + (option.maxTimeoutSeconds ?? 300)),
        nonce,
      };
      const signature = await account.signTypedData({
        domain: {
          name,
          version,
          chainId,
          verifyingContract: getAddress(option.asset),
        },
        types: TRANSFER_WITH_AUTHORIZATION,
        primaryType: "TransferWithAuthorization",
        message: {
          from: authorization.from,
          to: authorization.to,
          value: BigInt(authorization.value),
          validAfter: 0n,
          validBefore: BigInt(authorization.validBefore),
          nonce: nonce as `0x${string}`,
        },
      });
      // The x402 v2 PaymentPayload, in the upstream client's field order.
      const payload = {
        x402Version: 2,
        payload: { authorization, signature },
        ...(required.resource !== undefined
          ? { resource: required.resource }
          : {}),
        accepted: option,
      };
      return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
    },
  };
}

/**
 * The caps, from configuration. Both amount caps are required once a payer
 * is configured: a payer with no cap is refused, never defaulted.
 *
 *  - `MCP_REGISTER_PAY_MAX_PER_CALL`, `MCP_REGISTER_PAY_MAX_PER_DAY`: atomic
 *    units of the asset (USDC has 6 decimals: 10000 is $0.01);
 *  - `MCP_REGISTER_PAY_NETWORK` (default Base Sepolia, `eip155:84532`) and
 *    `MCP_REGISTER_PAY_ASSET` (default Circle's USDC on Base Sepolia);
 *  - `MCP_REGISTER_PAY_TO`: optional, the only payee;
 *  - `MCP_REGISTER_PAY_ALLOW_MAINNET=1`: pay on a network that is not a
 *    testnet. Off by default.
 */
export function readPaymentCaps(
  env: Record<string, string | undefined>,
): PaymentCaps {
  const misconfigured = (message: string) =>
    new PayerError("payer_misconfigured", message);
  const amount = (name: string): bigint => {
    const raw = env[name]?.trim();
    if (!raw)
      throw misconfigured(
        `${name} is required when a payer is configured: the server pays nothing without a cap`,
      );
    if (!ATOMIC.test(raw))
      throw misconfigured(
        `${name} must be a whole number of atomic units (got ${raw})`,
      );
    return BigInt(raw);
  };
  const maxPerCallAtomic = amount("MCP_REGISTER_PAY_MAX_PER_CALL");
  const maxPerDayAtomic = amount("MCP_REGISTER_PAY_MAX_PER_DAY");
  const network =
    env["MCP_REGISTER_PAY_NETWORK"]?.trim() || DEFAULT_PAY_NETWORK;
  if (!/^eip155:[0-9]+$/.test(network))
    throw misconfigured(
      `MCP_REGISTER_PAY_NETWORK must be an EVM CAIP-2 id such as eip155:84532 (got ${network})`,
    );
  const asset = (
    env["MCP_REGISTER_PAY_ASSET"]?.trim() || DEFAULT_PAY_ASSET
  ).toLowerCase();
  if (!ADDRESS.test(asset))
    throw misconfigured(
      `MCP_REGISTER_PAY_ASSET must be a 0x-prefixed 20-byte address (got ${asset})`,
    );
  if (
    env["MCP_REGISTER_PAY_ASSET"] === undefined &&
    network !== DEFAULT_PAY_NETWORK
  )
    throw misconfigured(
      `MCP_REGISTER_PAY_ASSET is required with MCP_REGISTER_PAY_NETWORK=${network}: the default asset is USDC on ${DEFAULT_PAY_NETWORK} only`,
    );
  const payTo = env["MCP_REGISTER_PAY_TO"]?.trim();
  if (payTo && !ADDRESS.test(payTo))
    throw misconfigured(
      `MCP_REGISTER_PAY_TO must be a 0x-prefixed 20-byte address (got ${payTo})`,
    );
  return {
    network,
    asset,
    maxPerCallAtomic,
    maxPerDayAtomic,
    ...(payTo ? { payTo } : {}),
    allowMainnet: env["MCP_REGISTER_PAY_ALLOW_MAINNET"] === "1",
  };
}
