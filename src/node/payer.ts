/**
 * The payer backend: what pays canopy's 402 when register_grant meets one.
 *
 * Separate from the log key and the authority key (D6): those are ES256 and
 * hold no funds; the payer is an EVM account that holds testnet USDC and
 * signs only standard x402 authorisations (EIP-3009
 * `transferWithAuthorization`, the "exact" scheme). The default backend is
 * the upstream x402 client (`@x402/core` with `@x402/evm`'s exact scheme)
 * over a viem account loaded from a local key file. An embedder passes its
 * own `PayerBackend` (a hosted wallet) to `createServer({ payer })`.
 *
 * The payer key never crosses the MCP boundary: no tool takes or returns it,
 * the file is refused if it is a symlink or readable by others, and no
 * `{path}` input may read it. The caps are configuration
 * (`readPaymentCaps`), never tool arguments.
 */
import { lstatSync, readFileSync } from "node:fs";
import { x402Client } from "@x402/core/client";
import { encodePaymentSignatureHeader } from "@x402/core/http";
import type { Network } from "@x402/core/types";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
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
   * payload.
   */
  pay(required: PaymentRequired, option: PaymentOption): Promise<string>;
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

/** The upstream x402 client over a viem account. */
export function evmPayer(
  privateKey: `0x${string}`,
  description: string,
): PayerBackend {
  const account = privateKeyToAccount(privateKey);
  return {
    address: account.address,
    description,
    pay: async (required, option) => {
      // The caps were applied before this call, over this one option; the
      // client sees nothing else to choose from. Its own default spend
      // control (a $1 per-payment cap on assets it recognises) stays on as a
      // second, independent limit.
      const client = new x402Client();
      registerExactEvmScheme(client, {
        signer: account,
        networks: [option.network as Network],
      });
      const payload = await client.createPaymentPayload({
        x402Version: 2,
        accepts: [option],
        ...(required.resource !== undefined
          ? { resource: required.resource }
          : {}),
      } as Parameters<x402Client["createPaymentPayload"]>[0]);
      return encodePaymentSignatureHeader(payload);
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
