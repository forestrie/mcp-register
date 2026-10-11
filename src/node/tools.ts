/**
 * The tool handlers. Each returns `{ content, structuredContent, isError:
 * false }`; a refusal, an HTTP failure or bad input is a
 * `structuredContent.problem` with a `code`, never a throw. Only programming
 * errors propagate.
 *
 * Nothing here returns key material or accepts a signature: the signer is
 * reached only through `deps.signer()`.
 */
import { existsSync, readFileSync } from "node:fs";
import { z } from "zod";
import { NetError, fetchReceipt } from "@forestrie/mcp-resolve/net";
import { verifyFetched, summarizeFetched } from "@forestrie/mcp-resolve";
import type { TrustRoot } from "@forestrie/mcp-verify";
import {
  GrantError,
  inspectGrant,
  statementGrantProblems,
  type GrantView,
} from "../core/grant.js";
import { base64ToBytes, bytesToBase64 } from "../core/base64.js";
import { toHex } from "../core/hex.js";
import { MAX_STATEMENT_BYTES } from "../core/limits.js";
import {
  readReceiptResponse,
  readRegisterResponse,
  readStatusResponse,
  type Problem,
} from "../core/scrapi.js";
import type { Es256Signer } from "../core/signer.js";
import { StatementError, signStatement } from "../core/statement.js";
import { delegateSealing } from "../net/delegate.js";
import { getRegistrationStatus, postStatement } from "../net/write.js";
import { InputError, resolveBytes, type BytesInput } from "./resolve-input.js";
import { KeyFileError } from "./signer-file.js";
import { RegistrationStore, StoreError } from "./store.js";
import type { ToolName } from "./text.js";

/* -------------------------------- deps ---------------------------------- */

export interface ResolvedDeps {
  fetchImpl: typeof fetch;
  env: Record<string, string | undefined>;
  now: () => Date;
  /** Opened on first use, so starting the server writes no file. */
  signer: () => Promise<Es256Signer & { created?: boolean }>;
  store: RegistrationStore;
  sleep?: (ms: number) => Promise<void>;
}

/* ------------------------------- schemas -------------------------------- */

const BYTES_SHAPES = "{ b64 } | { base64 } | { path }";

const BytesInputSchema = z
  .union(
    [
      z.object({ b64: z.string().min(1) }).describe("standard base64"),
      z
        .object({ base64: z.string().min(1) })
        .describe("standard base64 (alias of b64)"),
      z
        .object({ path: z.string().min(1) })
        .describe("filesystem path, read by the stdio adapter"),
    ],
    { error: `expected bytes as ${BYTES_SHAPES}` },
  )
  .describe(`Bytes as ${BYTES_SHAPES}`);

function bytesInput(what: string) {
  return BytesInputSchema.describe(`${what} — ${BYTES_SHAPES}`);
}

const GrantSchema = z
  .string()
  .min(1)
  .describe(
    "the Forestrie-Grant: base64 (standard or URL-safe) of the completed grant, or a path to a file holding it as raw bytes or base64 text; falls back to FORESTRIE_GRANT",
  );

const BaseUrlSchema = z
  .string()
  .min(1)
  .describe(
    "the canopy SCRAPI base URL; falls back to FORESTRIE_BASE_URL — never defaulted by the package itself",
  );

const ContentHashSchema = z
  .string()
  .regex(/^[0-9a-f]{64}$/)
  .describe("the content hash register_statement returned (64 lowercase hex)");

export const getLogKeyInputShape = {};

export const registerStatementInputShape = {
  payload: bytesInput("the payload to sign and register, up to 4 MiB"),
  contentType: z
    .string()
    .min(1)
    .describe("the payload's media type, e.g. application/json"),
  grant: GrantSchema.optional(),
  baseUrl: BaseUrlSchema.optional(),
  rootLogId: z
    .string()
    .min(1)
    .optional()
    .describe(
      "the forest's root log id (R in /register/{R}/entries); falls back to FORESTRIE_ROOT_LOG_ID",
    ),
  subject: z
    .string()
    .min(1)
    .optional()
    .describe("CWT sub; defaults to sha-256:<hex of the payload>"),
  issuer: z
    .string()
    .min(1)
    .optional()
    .describe("CWT iss; defaults to the hex of the key id"),
};

export const checkRegistrationInputShape = {
  contentHash: ContentHashSchema,
};

export const verifyRegistrationInputShape = {
  contentHash: ContentHashSchema,
  knownAccumulator: bytesInput(
    "optional: a known accumulator (e.g. from @forestrie/mcp-resolve's fetch_accumulator) to verify against instead of this server's own log key",
  ).optional(),
};

export const delegateSealingInputShape = {
  grant: GrantSchema.optional(),
  baseUrl: BaseUrlSchema.optional(),
  coordinatorUrl: z
    .string()
    .min(1)
    .optional()
    .describe(
      "the delegation coordinator base URL; falls back to FORESTRIE_COORDINATOR_URL",
    ),
  knownSealerKey: z
    .string()
    .min(1)
    .optional()
    .describe(
      "the registrar's voucher key, base64 of 64 bytes x‖y, as the operator publishes it; falls back to FORESTRIE_KNOWN_SEALER_KEY",
    ),
  ttlSeconds: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      "how long the delegation lasts; defaults to the coordinator's suggestion",
    ),
};

type Args<S extends Record<string, z.ZodType>> = {
  [K in keyof S]: z.infer<S[K]>;
};

/* ------------------------------- results -------------------------------- */

export type ToolResult = {
  content: [{ type: "text"; text: string }];
  structuredContent: Record<string, unknown>;
  isError: false;
};

function ok(
  text: string,
  structuredContent: Record<string, unknown>,
): ToolResult {
  return {
    content: [{ type: "text", text }],
    structuredContent,
    isError: false,
  };
}

function problemResult(
  toolName: ToolName,
  problem: Record<string, unknown>,
): ToolResult {
  const message =
    typeof problem["message"] === "string"
      ? problem["message"]
      : JSON.stringify(problem);
  const code =
    typeof problem["code"] === "string" ? problem["code"] : "problem";
  return ok(`${toolName}: problem (${code}): ${message}`, { problem });
}

function httpProblem(
  toolName: ToolName,
  message: string,
  p: Problem,
): ToolResult {
  return problemResult(toolName, {
    code: "http_error",
    message: `${message}: ${p.title}${p.detail ? ` — ${p.detail}` : ""}`,
    status: p.status,
    title: p.title,
    ...(p.detail !== undefined ? { detail: p.detail } : {}),
    ...(p.reason !== undefined ? { reason: p.reason } : {}),
  });
}

function missingInput(
  toolName: ToolName,
  field: string,
  envVar: string,
): ToolResult {
  return problemResult(toolName, {
    code: "missing_input",
    message: `${field} is required: pass it explicitly or set ${envVar}`,
  });
}

async function guardHandler(
  toolName: ToolName,
  run: () => Promise<ToolResult>,
): Promise<ToolResult> {
  try {
    return await run();
  } catch (err) {
    if (
      err instanceof InputError ||
      err instanceof GrantError ||
      err instanceof StoreError ||
      err instanceof KeyFileError ||
      err instanceof StatementError ||
      err instanceof NetError
    ) {
      return problemResult(toolName, { code: err.code, message: err.message });
    }
    throw err;
  }
}

/* -------------------------------- grant --------------------------------- */

interface ResolvedGrant {
  b64: string;
  view: GrantView;
}

/** A grant from a tool argument or FORESTRIE_GRANT: inline base64, or a path
 *  to a file of raw COSE bytes or of base64 text. */
function resolveGrant(
  explicit: string | undefined,
  deps: ResolvedDeps,
): ResolvedGrant | undefined {
  const raw = explicit ?? deps.env["FORESTRIE_GRANT"];
  if (raw === undefined || raw.trim() === "") return undefined;
  let bytes: Uint8Array;
  if (existsSync(raw)) {
    const file = new Uint8Array(readFileSync(raw));
    // A COSE Sign1 starts 0x84 (untagged) or 0xd2 (tag 18); anything else is
    // read as base64 text.
    bytes =
      file[0] === 0x84 || file[0] === 0xd2
        ? file
        : decodeBase64Text(
            new TextDecoder().decode(file),
            `grant file ${raw}`,
          );
  } else {
    bytes = decodeBase64Text(raw, "grant");
  }
  return { b64: bytesToBase64(bytes), view: inspectGrant(bytes) };
}

function decodeBase64Text(text: string, what: string): Uint8Array {
  const trimmed = text.trim();
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed))
    throw new InputError(
      `${what} is neither an existing file nor base64 (standard or URL-safe)`,
    );
  const bytes = base64ToBytes(trimmed);
  if (bytes.length === 0) throw new InputError(`${what} decoded to 0 bytes`);
  return bytes;
}

/* ----------------------------- get_log_key ------------------------------ */

export function makeGetLogKeyTool(deps: ResolvedDeps) {
  return () =>
    guardHandler("get_log_key", async () => {
      const signer = await deps.signer();
      const xy = await signer.publicKeyXY();
      const structured = {
        alg: "ES256",
        publicKeyXYHex: toHex(xy),
        publicKeyXYBase64: bytesToBase64(xy),
        statementKidHex: toHex(xy.slice(0, 32)),
        backend: signer.description,
        created: signer.created === true,
      };
      return ok(
        `log key (ES256) x‖y ${structured.publicKeyXYHex}${structured.created ? " — created just now" : ""}; held in ${signer.description}. A grant must name this key in its grantData.`,
        structured,
      );
    });
}

/* -------------------------- register_statement -------------------------- */

export function makeRegisterStatementTool(deps: ResolvedDeps) {
  return (args: Args<typeof registerStatementInputShape>) =>
    guardHandler("register_statement", async () => {
      const baseUrl = args.baseUrl ?? deps.env["FORESTRIE_BASE_URL"];
      if (!baseUrl)
        return missingInput(
          "register_statement",
          "baseUrl",
          "FORESTRIE_BASE_URL",
        );
      const rootLogId = args.rootLogId ?? deps.env["FORESTRIE_ROOT_LOG_ID"];
      if (!rootLogId)
        return missingInput(
          "register_statement",
          "rootLogId",
          "FORESTRIE_ROOT_LOG_ID",
        );
      const grant = resolveGrant(args.grant, deps);
      if (!grant)
        return missingInput("register_statement", "grant", "FORESTRIE_GRANT");

      const signer = await deps.signer();
      const xy = await signer.publicKeyXY();
      const refusals = statementGrantProblems(grant.view, xy);
      if (refusals.length > 0)
        return problemResult("register_statement", {
          code: "grant_unusable",
          message: refusals.join("; "),
          logId: grant.view.logId,
        });

      const payload = resolveBytes(args.payload as BytesInput, "payload");
      if (payload.length > MAX_STATEMENT_BYTES)
        return problemResult("register_statement", {
          code: "too_large",
          message: `payload is ${payload.length} bytes; canopy accepts signed statements up to ${MAX_STATEMENT_BYTES} bytes. Register a small manifest naming the artefact's digest instead`,
        });

      const signed = await signStatement(
        {
          payload,
          contentType: args.contentType,
          ...(args.subject !== undefined ? { subject: args.subject } : {}),
          ...(args.issuer !== undefined ? { issuer: args.issuer } : {}),
          issuedAt: Math.floor(deps.now().getTime() / 1000),
        },
        signer,
      );

      const res = await postStatement(
        {
          baseUrl,
          rootLogId,
          statement: signed.statement,
          grantB64: grant.b64,
        },
        { fetchImpl: deps.fetchImpl },
      );
      const outcome = readRegisterResponse(res);
      if (outcome.kind === "problem")
        return httpProblem(
          "register_statement",
          "canopy refused the statement",
          outcome.problem,
        );

      const record = {
        contentHash: signed.contentHash,
        statusUrl: outcome.statusUrl,
        baseUrl,
        rootLogId,
        logId: grant.view.logId,
        contentType: args.contentType,
        issuer: signed.issuer,
        subject: signed.subject,
        registeredAt: res.at,
      };
      deps.store.saveStatement(record, signed.statement);
      return ok(
        `registered: accepted by canopy for log ${record.logId}, content hash ${record.contentHash}. Not yet sequenced: call check_registration with that content hash${outcome.retryAfterSeconds !== undefined ? ` in about ${outcome.retryAfterSeconds}s` : ""}.`,
        {
          state: "accepted",
          ...record,
          statementPath: deps.store.statementPath(record.contentHash),
          statementBytes: signed.statement.length,
          ...(outcome.retryAfterSeconds !== undefined
            ? { retryAfterSeconds: outcome.retryAfterSeconds }
            : {}),
        },
      );
    });
}

/* -------------------------- check_registration -------------------------- */

export function makeCheckRegistrationTool(deps: ResolvedDeps) {
  return (args: Args<typeof checkRegistrationInputShape>) =>
    guardHandler("check_registration", async () => {
      const record = deps.store.load(args.contentHash);
      const paths = {
        statementPath: deps.store.statementPath(record.contentHash),
        receiptPath: deps.store.receiptPath(record.contentHash),
      };
      if (
        record.sealedAt !== undefined &&
        deps.store.readReceipt(record.contentHash)
      )
        return ok(
          `sealed: entry ${record.entryId}; receipt at ${paths.receiptPath}`,
          { state: "sealed", ...record, ...paths },
        );

      let receiptUrl = record.receiptUrl;
      if (receiptUrl === undefined) {
        const res = await getRegistrationStatus(
          { statusUrl: record.statusUrl },
          { fetchImpl: deps.fetchImpl },
        );
        const status = readStatusResponse(res);
        if (status.kind === "problem")
          return httpProblem(
            "check_registration",
            "the status URL answered with a problem",
            status.problem,
          );
        if (status.kind === "pending")
          return ok(
            `pending: not yet sequenced; check again in ${status.retryAfterSeconds}s`,
            {
              state: "pending",
              contentHash: record.contentHash,
              retryAfterSeconds: status.retryAfterSeconds,
            },
          );
        record.receiptUrl = status.receiptUrl;
        record.entryId = status.entryId;
        record.massifHeight = status.massifHeight;
        deps.store.saveRecord(record);
        receiptUrl = status.receiptUrl;
      }

      const res = await fetchReceipt(
        { receiptUrl },
        { fetchImpl: deps.fetchImpl },
      );
      const receipt = readReceiptResponse(res);
      if (receipt.kind === "problem")
        return httpProblem(
          "check_registration",
          "the receipt URL answered with a problem",
          receipt.problem,
        );
      if (receipt.kind === "awaiting_seal")
        return ok(
          `awaiting_seal: sequenced as entry ${record.entryId}; no checkpoint covers it yet. Sealing takes minutes, and needs delegate_sealing to have run for log ${record.logId}. Check again in about a minute.`,
          {
            state: "awaiting_seal",
            contentHash: record.contentHash,
            entryId: record.entryId,
            massifHeight: record.massifHeight,
            receiptUrl,
          },
        );
      deps.store.saveReceipt(record.contentHash, receipt.receipt);
      record.sealedAt = res.at;
      deps.store.saveRecord(record);
      return ok(
        `sealed: entry ${record.entryId}; receipt saved at ${paths.receiptPath}. Call verify_registration next.`,
        {
          state: "sealed",
          ...record,
          ...paths,
          receiptBytes: receipt.receipt.length,
        },
      );
    });
}

/* -------------------------- verify_registration ------------------------- */

export function makeVerifyRegistrationTool(deps: ResolvedDeps) {
  return (args: Args<typeof verifyRegistrationInputShape>) =>
    guardHandler("verify_registration", async () => {
      const record = deps.store.load(args.contentHash);
      const receipt = deps.store.readReceipt(record.contentHash);
      if (receipt === undefined || record.entryId === undefined)
        return problemResult("verify_registration", {
          code: "not_sealed",
          message: `registration ${record.contentHash} has no receipt yet: call check_registration until it reports sealed`,
        });
      const statement = deps.store.readStatement(record.contentHash);

      let trust: TrustRoot;
      let rootFrom: string;
      if (args.knownAccumulator !== undefined) {
        trust = {
          root: "known-accumulator",
          accumulator: resolveBytes(
            args.knownAccumulator as BytesInput,
            "knownAccumulator",
          ),
        };
        rootFrom = "supplied by caller";
      } else {
        const signer = await deps.signer();
        trust = { root: "known-log-key", keyXy: await signer.publicKeyXY() };
        rootFrom = `this server's log key (${signer.description})`;
      }

      const result = await verifyFetched({
        kind: "payload",
        receipt,
        payload: statement,
        entryId: record.entryId,
        trust,
        rootProvenance: "supplied",
      });
      const provenance = `statement and receipt from ${deps.store.dir(record.contentHash)}; receipt fetched from ${record.receiptUrl} at ${record.sealedAt}; root ${trust.root} from ${rootFrom}`;
      return ok(summarizeFetched("verify_registration", result, provenance), {
        contentHash: record.contentHash,
        entryId: record.entryId,
        root: trust.root,
        rootFrom,
        result: result as unknown as Record<string, unknown>,
      });
    });
}

/* --------------------------- delegate_sealing --------------------------- */

export function makeDelegateSealingTool(deps: ResolvedDeps) {
  return (args: Args<typeof delegateSealingInputShape>) =>
    guardHandler("delegate_sealing", async () => {
      const baseUrl = args.baseUrl ?? deps.env["FORESTRIE_BASE_URL"];
      if (!baseUrl)
        return missingInput(
          "delegate_sealing",
          "baseUrl",
          "FORESTRIE_BASE_URL",
        );
      const coordinatorUrl =
        args.coordinatorUrl ?? deps.env["FORESTRIE_COORDINATOR_URL"];
      if (!coordinatorUrl)
        return missingInput(
          "delegate_sealing",
          "coordinatorUrl",
          "FORESTRIE_COORDINATOR_URL",
        );
      const sealerKeyB64 =
        args.knownSealerKey ?? deps.env["FORESTRIE_KNOWN_SEALER_KEY"];
      if (!sealerKeyB64)
        return missingInput(
          "delegate_sealing",
          "knownSealerKey",
          "FORESTRIE_KNOWN_SEALER_KEY",
        );
      const knownSealerKeyXY = decodeBase64Text(
        sealerKeyB64,
        "knownSealerKey",
      );
      if (knownSealerKeyXY.length !== 64)
        throw new InputError(
          `knownSealerKey must decode to 64 bytes x‖y (got ${knownSealerKeyXY.length})`,
        );
      const grant = resolveGrant(args.grant, deps);
      if (!grant)
        return missingInput("delegate_sealing", "grant", "FORESTRIE_GRANT");

      const signer = await deps.signer();
      const xy = await signer.publicKeyXY();
      if (
        grant.view.grantData.length !== 64 ||
        toHex(grant.view.grantData) !== toHex(xy)
      )
        return problemResult("delegate_sealing", {
          code: "grant_unusable",
          message: `the grant's grantData does not name this server's log key, so this key does not own log ${grant.view.logId} and cannot delegate its sealing`,
        });

      const outcome = await delegateSealing(
        {
          baseUrl,
          coordinatorUrl,
          knownSealerKeyXY,
          grantB64: grant.b64,
          grant: grant.view,
          ...(args.ttlSeconds !== undefined
            ? { ttlSeconds: args.ttlSeconds }
            : {}),
          ...(deps.sleep !== undefined ? { sleep: deps.sleep } : {}),
        },
        signer,
        { fetchImpl: deps.fetchImpl },
      );
      if (outcome.kind === "problem")
        return problemResult("delegate_sealing", {
          code: `${outcome.stage}_failed`,
          stage: outcome.stage,
          message: outcome.message,
          prepared: outcome.prepared,
          ...(outcome.problem !== undefined ? { http: outcome.problem } : {}),
        });
      return ok(
        `delegated: sealer ${outcome.sealerId} (epoch ${outcome.epoch}) may seal log ${outcome.logId} until ${new Date(outcome.expiresAt * 1000).toISOString()}${outcome.prepared ? "; ran prepare first to publish the log's public root" : ""}.`,
        { state: "delegated", ...outcome },
      );
    });
}
