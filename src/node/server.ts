/**
 * `createServer(deps?)` — the MCP adapter. No transport: the caller connects
 * one (stdio from `cli.ts`, `InMemoryTransport` from the smoke test), which
 * is also what lets an embedder mount tools on their own transport without
 * the CLI.
 *
 * Tools register from `TOOL_NAMES` and prompts from `PROMPT_NAMES`
 * (`text.ts`), in that order.
 *
 * The signer is a seam: pass `deps.signer` to use a KMS or a remote signer.
 * Without one, the default opens the local key file
 * (`MCP_REGISTER_KEY_FILE`, else `<MCP_REGISTER_HOME>/log-key.jwk`) at the
 * first tool call that needs it, creating it then if it does not exist.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PACKAGE_VERSION } from "../core/index.js";
import type { Es256Signer } from "../core/signer.js";
import {
  defaultKeyFilePath,
  openKeyFileSigner,
  registerHome,
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
export { openKeyFileSigner } from "./signer-file.js";

/** Every field optional; defaults to `process.env` / `globalThis.fetch` /
 *  `() => new Date()` / the local key file, so tests can inject fakes
 *  without touching the real network, environment or home directory. */
export type Deps = {
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  now?: () => Date;
  signer?: Es256Signer;
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
  let opened: Promise<Es256Signer & { created?: boolean }> | undefined;
  const resolved: ResolvedDeps = {
    fetchImpl: deps.fetchImpl ?? ((...a) => globalThis.fetch(...a)),
    env,
    now: deps.now ?? (() => new Date()),
    signer: () =>
      deps.signer !== undefined
        ? Promise.resolve(deps.signer)
        : (opened ??= openKeyFileSigner(defaultKeyFilePath(env)).catch(
            (err: unknown) => {
              opened = undefined;
              throw err;
            },
          )),
    store: new RegistrationStore(deps.home ?? registerHome(env)),
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
      // Offline: reads the local store and the key's public half only.
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

  return server;
}
