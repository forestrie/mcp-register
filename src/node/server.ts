/**
 * `createServer(deps?)` — the MCP adapter. No transport: the caller connects
 * one (stdio from `cli.ts`, `InMemoryTransport` from the smoke test), which
 * is also what lets an embedder mount tools on their own transport without
 * the CLI.
 *
 * Tools register from `TOOL_NAMES` and prompts from `PROMPT_NAMES`
 * (`text.ts`), in that order.
 *
 * The signers are seams: pass `deps.signer` (the log key) or
 * `deps.authoritySigner` (the requester's authority key) to use a KMS or a
 * remote signer. Without them, the defaults open local key files
 * (`MCP_REGISTER_KEY_FILE`, else `log-key.jwk` in the home;
 * `MCP_REGISTER_AUTHORITY_KEY_FILE`, else `authority-key.jwk`) at the first
 * tool call that needs each, creating it then if it does not exist.
 *
 * The payer is a seam too: pass `deps.payer` for a hosted wallet. Without
 * it, `MCP_REGISTER_PAYER_KEY_FILE` names a local EVM key file; with
 * neither, register_grant runs in relay mode. The payer is never created.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PACKAGE_VERSION } from "../core/index.js";
import type { Es256Signer } from "../core/signer.js";
import { join } from "node:path";
import { GrantStore } from "./grant-store.js";
import {
  issueGrantInputShape,
  makeIssueGrantTool,
  makeRegisterGrantTool,
  registerGrantInputShape,
} from "./grant-tools.js";
import { SpendLedger } from "./ledger.js";
import { openKeyFilePayer, type PayerBackend } from "./payer.js";
import {
  openKeyFileSigner,
  registerHome,
  type KeyRole,
} from "./signer-file.js";
import { RegistrationStore } from "./store.js";
import {
  INSTRUCTIONS,
  PROMPT_DESCRIPTIONS,
  PROMPT_NAMES,
  PROMPT_TITLES,
  TOOL_DESCRIPTIONS,
  TOOL_NAMES,
  TOOL_TITLES,
  auditPromptText,
  issueAndPayPromptText,
  registerPromptText,
} from "./text.js";
import {
  checkRegistrationInputShape,
  delegateSealingInputShape,
  getLogKeyInputShape,
  makeCheckRegistrationTool,
  makeDelegateSealingTool,
  makeGetLogKeyTool,
  makeRegisterStatementTool,
  makeVerifyRegistrationTool,
  registerStatementInputShape,
  verifyRegistrationInputShape,
  type ResolvedDeps,
} from "./tools.js";

export const SERVER_NAME = "forestrie-mcp-register";

export type { Es256Signer } from "../core/signer.js";
export { openKeyFileSigner, publicKeyPem } from "./signer-file.js";
export { evmPayer, openKeyFilePayer, readPaymentCaps } from "./payer.js";
export type { PayerBackend } from "./payer.js";

/** Every field optional; defaults to `process.env` / `globalThis.fetch` /
 *  `() => new Date()` / the local key file, so tests can inject fakes
 *  without touching the real network, environment or home directory. */
export type Deps = {
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  now?: () => Date;
  signer?: Es256Signer;
  /** The requester's authority key; defaults to a local key file. */
  authoritySigner?: Es256Signer;
  /** Pays canopy's 402; defaults to MCP_REGISTER_PAYER_KEY_FILE, else none
   *  (relay mode). */
  payer?: PayerBackend;
  /** Where registrations are kept; defaults to MCP_REGISTER_HOME. */
  home?: string;
  sleep?: (ms: number) => Promise<void>;
};

/** Writes to the operator's log and to the local store; never destroys. */
const WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

export function createServer(deps: Deps = {}): McpServer {
  const env = deps.env ?? process.env;
  const home = deps.home ?? registerHome(env);
  const keyFile = env["MCP_REGISTER_KEY_FILE"] ?? join(home, "log-key.jwk");
  const authorityKeyFile =
    env["MCP_REGISTER_AUTHORITY_KEY_FILE"] ?? join(home, "authority-key.jwk");
  const payerKeyFile = env["MCP_REGISTER_PAYER_KEY_FILE"];

  /** A lazily opened key-file signer, unless the embedder passed one. */
  const lazySigner = (
    path: string,
    role: KeyRole,
    given: Es256Signer | undefined,
  ): ResolvedDeps["signer"] => {
    let opened: Promise<Es256Signer & { created?: boolean }> | undefined;
    const open = (create: boolean) =>
      openKeyFileSigner(path, { create, role }).catch((err: unknown) => {
        opened = undefined;
        throw err;
      });
    return (options) => {
      if (given !== undefined) return Promise.resolve(given);
      if (opened !== undefined) return opened;
      // A no-create open is not remembered: a later call may create.
      if (options?.create === false) return open(false);
      return (opened = open(true));
    };
  };

  let payer: PayerBackend | undefined = deps.payer;
  const resolved: ResolvedDeps = {
    fetchImpl: deps.fetchImpl ?? ((...a) => globalThis.fetch(...a)),
    env,
    now: deps.now ?? (() => new Date()),
    signer: lazySigner(keyFile, "log", deps.signer),
    authoritySigner: lazySigner(
      authorityKeyFile,
      "authority",
      deps.authoritySigner,
    ),
    payer: () => {
      if (payer === undefined && payerKeyFile)
        payer = openKeyFilePayer(payerKeyFile);
      return payer;
    },
    protectedPaths: [
      keyFile,
      authorityKeyFile,
      ...(payerKeyFile ? [payerKeyFile] : []),
      home,
    ],
    store: new RegistrationStore(home),
    grants: new GrantStore(home),
    ledger: new SpendLedger(home),
    ...(deps.sleep !== undefined ? { sleep: deps.sleep } : {}),
  };

  const server = new McpServer(
    { name: SERVER_NAME, version: PACKAGE_VERSION },
    { instructions: INSTRUCTIONS },
  );

  server.registerTool(
    TOOL_NAMES[0],
    {
      title: TOOL_TITLES.get_log_key,
      description: TOOL_DESCRIPTIONS.get_log_key,
      inputSchema: getLogKeyInputShape,
      // May create the key file on first use; otherwise reads it.
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    makeGetLogKeyTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[1],
    {
      title: TOOL_TITLES.register_statement,
      description: TOOL_DESCRIPTIONS.register_statement,
      inputSchema: registerStatementInputShape,
      annotations: WRITE,
    },
    makeRegisterStatementTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[2],
    {
      title: TOOL_TITLES.check_registration,
      description: TOOL_DESCRIPTIONS.check_registration,
      inputSchema: checkRegistrationInputShape,
      // Reads canopy; saves the receipt locally once sealed.
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    makeCheckRegistrationTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[3],
    {
      title: TOOL_TITLES.verify_registration,
      description: TOOL_DESCRIPTIONS.verify_registration,
      inputSchema: verifyRegistrationInputShape,
      // Offline: reads the local store and the key's public half only; never
      // creates a key.
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    makeVerifyRegistrationTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[4],
    {
      title: TOOL_TITLES.delegate_sealing,
      description: TOOL_DESCRIPTIONS.delegate_sealing,
      inputSchema: delegateSealingInputShape,
      annotations: WRITE,
    },
    makeDelegateSealingTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[5],
    {
      title: TOOL_TITLES.issue_grant,
      description: TOOL_DESCRIPTIONS.issue_grant,
      inputSchema: issueGrantInputShape,
      // Signs and saves locally; sends nothing.
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    makeIssueGrantTool(resolved),
  );

  server.registerTool(
    TOOL_NAMES[6],
    {
      title: TOOL_TITLES.register_grant,
      description: TOOL_DESCRIPTIONS.register_grant,
      inputSchema: registerGrantInputShape,
      // Writes to the operator's log, and may spend from the payer.
      annotations: WRITE,
    },
    makeRegisterGrantTool(resolved),
  );

  server.registerPrompt(
    PROMPT_NAMES[0],
    {
      title: PROMPT_TITLES.register,
      description: PROMPT_DESCRIPTIONS.register,
      argsSchema: {
        what: z
          .string()
          .optional()
          .describe("what to register, in a few words (optional)"),
      },
    },
    (args) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: registerPromptText(args) },
        },
      ],
    }),
  );

  server.registerPrompt(
    PROMPT_NAMES[1],
    {
      title: PROMPT_TITLES.audit,
      description: PROMPT_DESCRIPTIONS.audit,
      argsSchema: {
        contentHash: z
          .string()
          .optional()
          .describe("the registration to audit (optional)"),
      },
    },
    (args) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: auditPromptText(args) },
        },
      ],
    }),
  );

  server.registerPrompt(
    PROMPT_NAMES[2],
    {
      title: PROMPT_TITLES["issue-and-pay"],
      description: PROMPT_DESCRIPTIONS["issue-and-pay"],
      argsSchema: {
        purpose: z
          .string()
          .optional()
          .describe("what the grant is for, in a few words (optional)"),
      },
    },
    (args) => ({
      messages: [
        {
          role: "user",
          content: { type: "text", text: issueAndPayPromptText(args) },
        },
      ],
    }),
  );

  return server;
}
