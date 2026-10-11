/**
 * The requester's tools: issue_grant signs a child grant with the authority
 * key, and register_grant registers it with canopy, paying canopy's 402
 * within the configured caps or relaying the payment requirements, then
 * follows it to its receipt and completes it.
 *
 * register_grant is resumable by the child log id. Each call advances the
 * stored record as far as it can (issued → payment_required → accepted →
 * complete) and stops at the first thing it has to wait for. Every payment
 * it signs for a grant carries a nonce derived from that grant, so one grant
 * can never be paid for twice.
 *
 * Same contract as `tools.ts`: a refusal, an HTTP failure or bad input is a
 * `structuredContent.problem` with a `code`, never a throw.
 */
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { NetError, fetchReceipt } from "@forestrie/mcp-resolve/net";
import { base64ToBytes, bytesToBase64 } from "../core/base64.js";
import { inspectGrant, type GrantView } from "../core/grant.js";
import { toHex } from "../core/hex.js";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
import {
  MAX_PARENT_GRANT_BYTES,
  completeGrant,
  grantContent,
  issueChildGrant,
  parentGrantProblems,
  registerGrantBody,
} from "../core/issue.js";
import {
  originOf,
  readReceiptResponse,
  readRegisterGrantResponse,
  readStatusResponse,
  type RegisterGrantOutcome,
} from "../core/scrapi.js";
import {
  PaymentError,
  grantPaymentNonce,
  readPaymentPayload,
  readPaymentRequired,
  selectWithinCaps,
  type PaymentRequired,
} from "../core/x402.js";
import {
  getRegistrationStatus,
  postGrant,
  registerGrantUrl,
} from "../net/write.js";
import type { GrantRecord } from "./grant-store.js";
import { readPaymentCaps } from "./payer.js";
import { InputError } from "./resolve-input.js";
import {
  BaseUrlSchema,
  GrantSchema,
  decodeBase64Text,
  guardHandler,
  httpProblem,
  httpProblemValue,
  missingInput,
  ok,
  problemResult,
  resolveGrant,
  type Args,
  type ResolvedDeps,
  type ToolResult,
} from "./tools.js";

const ParentGrantSchema = z
  .string()
  .min(1)
  .describe(
    "your authority grant: the completed grant that created your authority log and names this server's authority key, as base64 or a file path; falls back to FORESTRIE_AUTHORITY_GRANT",
  );

const LogIdSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
  .describe("a child log id: a lowercase UUID");

export const issueGrantInputShape = {
  maxHeight: z
    .number()
    .int()
    .positive()
    .describe(
      "the grant's batch ceiling. canopy prices a payment-gated child grant as its unit price × maxHeight, so size it to the work it is for",
    ),
  parentGrant: ParentGrantSchema.optional(),
  grantee: z
    .string()
    .min(1)
    .optional()
    .describe(
      "base64 of the 64-byte x‖y the grant names (the performer's log key); defaults to this server's own log key, for a self-purchase",
    ),
  logId: LogIdSchema.optional().describe(
    "the child data log to create; a fresh random UUID by default",
  ),
};

export const registerGrantInputShape = {
  logId: LogIdSchema.optional().describe(
    "the child log id issue_grant returned: register_grant resumes that grant from wherever the last call reached",
  ),
  grant: GrantSchema.optional().describe(
    "a child grant signed elsewhere (base64 or a file path), instead of logId",
  ),
  parentGrant: ParentGrantSchema.optional(),
  payment: z
    .string()
    .min(1)
    .optional()
    .describe(
      "relay mode: the X-PAYMENT header value your own x402 wallet produced for the payment requirements register_grant returned",
    ),
  baseUrl: BaseUrlSchema.optional(),
  rootLogId: z
    .string()
    .min(1)
    .optional()
    .describe(
      "the forest's root log id (R in /register/{R}/grants); falls back to FORESTRIE_ROOT_LOG_ID",
    ),
};

/* ------------------------------ issue_grant ----------------------------- */

export function makeIssueGrantTool(deps: ResolvedDeps) {
  return (args: Args<typeof issueGrantInputShape>) =>
    guardHandler("issue_grant", async () => {
      const parent = resolveGrant(
        args.parentGrant,
        deps,
        "FORESTRIE_AUTHORITY_GRANT",
      );
      if (!parent)
        return missingInput(
          "issue_grant",
          "parentGrant",
          "FORESTRIE_AUTHORITY_GRANT",
        );
      const authority = await deps.authoritySigner();
      const refusals = parentGrantProblems(
        parent.view,
        await authority.publicKeyXY(),
      );
      if (refusals.length > 0)
        return problemResult("issue_grant", {
          code: "parent_unusable",
          message: refusals.join("; "),
          ownerLogId: parent.view.logId,
        });

      let grantee: Uint8Array;
      let granteeIs: string;
      if (args.grantee !== undefined) {
        grantee = decodeBase64Text(args.grantee, "grantee");
        if (grantee.length !== 64)
          throw new InputError(
            `grantee must decode to 64 bytes x‖y (got ${grantee.length})`,
          );
        granteeIs = "the key supplied";
      } else {
        grantee = await (await deps.signer()).publicKeyXY();
        granteeIs = "this server's log key";
      }

      const logId = args.logId ?? randomUUID();
      if (deps.grants.has(logId))
        return problemResult("issue_grant", {
          code: "already_issued",
          message: `a grant for log ${logId} is already recorded here; call register_grant with that logId, or issue for a new log`,
          logId,
        });

      const issued = await issueChildGrant(
        {
          logId,
          ownerLogId: parent.view.logId,
          grantData: grantee,
          maxHeight: args.maxHeight,
        },
        authority,
      );
      const record: GrantRecord = {
        logId,
        ownerLogId: parent.view.logId,
        state: "issued",
        issuedHere: true,
        granteeHex: toHex(grantee),
        maxHeight: args.maxHeight,
        flagsHex: toHex(issued.flags),
        parentRequiresPayment: parent.view.requiresChildPayment,
        issuedAt: deps.now().toISOString(),
      };
      deps.grants.save(record, {
        "grant.cose": issued.grant,
        "parent.cose": base64ToBytes(parent.b64),
      });
      return ok(
        `issued: a data-log creation grant for log ${logId} under authority log ${record.ownerLogId}, naming ${granteeIs}, maxHeight ${args.maxHeight}. Not yet registered${record.parentRequiresPayment ? "; your authority grant makes its registration payment-gated" : ""}: call register_grant with this logId.`,
        {
          ...record,
          grantee: granteeIs,
          grantBase64: bytesToBase64(issued.grant),
        },
      );
    });
}

/* ----------------------------- register_grant --------------------------- */

interface Located {
  record: GrantRecord;
  grant: Uint8Array;
  view: GrantView;
}

/** The grant this call is about: a stored one by logId, or one supplied. */
function locate(
  args: Args<typeof registerGrantInputShape>,
  deps: ResolvedDeps,
): Located | ToolResult {
  if (args.grant !== undefined) {
    const supplied = resolveGrant(args.grant, deps)!;
    const bytes = base64ToBytes(supplied.b64);
    const logId = supplied.view.logId;
    if (args.logId !== undefined && args.logId !== logId)
      throw new InputError(
        `the grant is for log ${logId}, not the logId given (${args.logId})`,
      );
    if (deps.grants.has(logId)) {
      const stored = deps.grants.read(logId, "grant.cose");
      if (stored === undefined || toHex(stored) !== toHex(bytes))
        return problemResult("register_grant", {
          code: "grant_conflict",
          message: `a different grant for log ${logId} is already recorded here; pass logId alone to resume it`,
          logId,
        });
      return {
        record: deps.grants.load(logId),
        grant: bytes,
        view: supplied.view,
      };
    }
    const record: GrantRecord = {
      logId,
      ownerLogId: supplied.view.ownerLogId,
      state: "issued",
      issuedHere: false,
      granteeHex: toHex(supplied.view.grantData),
      ...(supplied.view.maxHeight !== undefined
        ? { maxHeight: supplied.view.maxHeight }
        : {}),
      flagsHex: supplied.view.flagsHex,
      issuedAt: deps.now().toISOString(),
    };
    deps.grants.save(record, { "grant.cose": bytes });
    return { record, grant: bytes, view: supplied.view };
  }
  if (args.logId === undefined)
    return problemResult("register_grant", {
      code: "missing_input",
      message:
        "pass logId (a grant issue_grant made) or grant (one signed elsewhere)",
    });
  const record = deps.grants.load(args.logId);
  const grant = deps.grants.read(args.logId, "grant.cose");
  if (grant === undefined)
    return problemResult("register_grant", {
      code: "corrupt_record",
      message: `grant ${args.logId} has a record but no grant.cose`,
    });
  return { record, grant, view: inspectGrant(grant) };
}

function decodeHeaderJson(value: string, what: string): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(
      base64ToBytes(value),
    );
  } catch {
    throw new PaymentError(
      what === "X-PAYMENT"
        ? "invalid_payment"
        : "invalid_payment_requirements",
      `${what} is not base64 of UTF-8 text`,
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new PaymentError(
      what === "X-PAYMENT"
        ? "invalid_payment"
        : "invalid_payment_requirements",
      `${what} is not base64 of JSON`,
    );
  }
}

function requirementsView(required: PaymentRequired) {
  return {
    accepts: required.accepts,
    ...(required.resource !== undefined
      ? { resource: required.resource }
      : {}),
  };
}

/**
 * No lock: paying twice for one grant is prevented by the nonce, not by
 * serialising calls. Every authorisation this server signs for a grant
 * carries `grantPaymentNonce(grant content, payer)`, so overlapping calls,
 * a retry after a lost answer and other processes sharing the payer all
 * sign the same nonce, and EIP-3009 settles at most one authorisation per
 * (payer, nonce). The daily cap is approximate under concurrency: calls that
 * pass the check before either records its payment can overshoot it by at
 * most one per-call cap each.
 */
export function makeRegisterGrantTool(deps: ResolvedDeps) {
  return (args: Args<typeof registerGrantInputShape>) =>
    registerGrant(args, deps);
}

function registerGrant(
  args: Args<typeof registerGrantInputShape>,
  deps: ResolvedDeps,
): Promise<ToolResult> {
  return guardHandler("register_grant", async () => {
    const located = locate(args, deps);
    if ("content" in located) return located;
    const { record, grant } = located;
    const store = deps.grants;

    if (record.state === "complete") return completeResult(record, deps);
    if (record.state === "accepted") return advance(record, grant, deps);

    // issued | payment_required: (re)send the registration.
    const baseUrl =
      args.baseUrl ?? record.baseUrl ?? deps.env["FORESTRIE_BASE_URL"];
    if (!baseUrl)
      return missingInput("register_grant", "baseUrl", "FORESTRIE_BASE_URL");
    const rootLogId =
      args.rootLogId ?? record.rootLogId ?? deps.env["FORESTRIE_ROOT_LOG_ID"];
    if (!rootLogId)
      return missingInput(
        "register_grant",
        "rootLogId",
        "FORESTRIE_ROOT_LOG_ID",
      );
    if (
      (record.baseUrl !== undefined && record.baseUrl !== baseUrl) ||
      (record.rootLogId !== undefined && record.rootLogId !== rootLogId)
    )
      return problemResult("register_grant", {
        code: "invalid_input",
        message: `grant ${record.logId} was already sent to ${record.baseUrl} for forest ${record.rootLogId}; it is resumed there, not moved`,
      });

    let parent: Uint8Array | undefined = store.read(
      record.logId,
      "parent.cose",
    );
    if (args.parentGrant !== undefined || parent === undefined) {
      const p = resolveGrant(
        args.parentGrant,
        deps,
        "FORESTRIE_AUTHORITY_GRANT",
      );
      if (p !== undefined) {
        if (p.view.logId !== record.ownerLogId)
          throw new InputError(
            `the parent grant is for log ${p.view.logId}, but this grant's owner is ${record.ownerLogId}`,
          );
        parent = base64ToBytes(p.b64);
        record.parentRequiresPayment = p.view.requiresChildPayment;
      }
    }
    if (parent !== undefined && parent.length > MAX_PARENT_GRANT_BYTES)
      throw new InputError(
        `the parent grant is ${parent.length} bytes; canopy reads at most ${MAX_PARENT_GRANT_BYTES}`,
      );
    // Without the parent as evidence canopy cannot see a payment policy;
    // send an empty body rather than guess one.
    const body =
      parent !== undefined ? registerGrantBody(parent) : new Uint8Array(0);

    record.baseUrl = baseUrl;
    record.rootLogId = rootLogId;
    store.save(record, parent !== undefined ? { "parent.cose": parent } : {});

    const grantB64 = bytesToBase64(grant);
    const resourceUrl = registerGrantUrl(baseUrl, rootLogId);
    const send = (payment?: string) =>
      postGrant(
        {
          baseUrl,
          rootLogId,
          grantB64,
          body,
          ...(payment !== undefined ? { payment } : {}),
        },
        { fetchImpl: deps.fetchImpl },
      );

    // A payment the caller relays from its own wallet.
    let payment: { header: string; via: "payer" | "relay" } | undefined;
    if (args.payment !== undefined) {
      readPaymentPayload(decodeHeaderJson(args.payment, "X-PAYMENT"));
      payment = { header: args.payment, via: "relay" };
    }

    let outcome = await sendOrReport(
      record,
      deps,
      () => send(payment?.header),
      payment,
    );
    if ("content" in outcome) return outcome;

    if (outcome.kind === "payment_required" && payment === undefined) {
      const required = readPaymentRequired(
        decodeHeaderJson(outcome.paymentRequiredHeader, "X-PAYMENT-REQUIRED"),
      );
      record.paymentRequired = required;
      record.state = "payment_required";
      store.save(record);

      const payer = deps.payer();
      if (payer === undefined)
        return ok(
          `payment_required: canopy asks ${describeOptions(required)} to register the grant for log ${record.logId}. No payer is configured here, so pay from your own x402 wallet: give it the paymentRequiredHeader (or the requirements), then call register_grant again with logId ${record.logId} and payment set to the X-PAYMENT value it returns.`,
          {
            state: "payment_required",
            logId: record.logId,
            resourceUrl,
            requirements: requirementsView(required),
            paymentRequiredHeader: outcome.paymentRequiredHeader,
            ...(outcome.problem.detail !== undefined
              ? { detail: outcome.problem.detail }
              : {}),
          },
        );

      // Pay within the caps, only the canopy this server is configured for.
      const configured = deps.env["FORESTRIE_BASE_URL"];
      if (
        configured === undefined ||
        originOf(configured) === undefined ||
        originOf(configured) !== originOf(baseUrl)
      )
        return problemResult("register_grant", {
          code: "cap_origin",
          message: `this server pays only the canopy in FORESTRIE_BASE_URL (${configured ?? "unset"}), not ${baseUrl}`,
          requirements: requirementsView(required),
        });
      const caps = readPaymentCaps(deps.env);
      const now = deps.now();
      let option;
      try {
        option = selectWithinCaps(required, caps, {
          resourceUrl,
          spentTodayAtomic: deps.ledger.spentToday(
            now,
            caps.network,
            caps.asset,
          ),
        });
      } catch (err) {
        if (!(err instanceof PaymentError)) throw err;
        return problemResult("register_grant", {
          code: err.code,
          message: err.message,
          requirements: requirementsView(required),
        });
      }
      const nonce = await grantPaymentNonce(
        grantContent(grant),
        hexToBytes(payer.address),
      );
      let header: string;
      try {
        header = await payer.pay({
          required,
          option,
          nonce,
          nowSeconds: Math.floor(now.getTime() / 1000),
        });
      } catch (err) {
        return problemResult("register_grant", {
          code: "payer_failed",
          message: `the payer (${payer.description}) did not sign the payment: ${err instanceof Error ? err.message : String(err)}. Nothing was sent or counted.`,
        });
      }
      const summary = readPaymentPayload(
        decodeHeaderJson(header, "X-PAYMENT"),
      );
      if (
        summary.value !== option.amount ||
        summary.to.toLowerCase() !== option.payTo.toLowerCase() ||
        summary.network !== option.network ||
        summary.nonce.toLowerCase() !== nonce
      )
        return problemResult("register_grant", {
          code: "invalid_payment",
          message: `the payer signed ${summary.value} to ${summary.to} on ${summary.network} with nonce ${summary.nonce}, not the ${option.amount} to ${option.payTo} on ${option.network} with the grant's nonce ${nonce} it was asked for; not sending it`,
        });
      // Committed from here: count it, then send it. A retry re-signs with
      // the same nonce, which the ledger counts once.
      deps.ledger.record(now, {
        at: now.toISOString(),
        network: option.network,
        asset: option.asset.toLowerCase(),
        amount: option.amount,
        payTo: option.payTo,
        from: summary.from,
        nonce: summary.nonce,
        logId: record.logId,
      });
      payment = { header, via: "payer" };
      outcome = await sendOrReport(record, deps, () => send(header), payment);
      if ("content" in outcome) return outcome;
    }

    if (payment !== undefined) {
      const summary = readPaymentPayload(
        decodeHeaderJson(payment.header, "X-PAYMENT"),
      );
      if (outcome.kind === "payment_required") {
        // canopy refused the payment presented: the next call starts from
        // the challenge again.
        record.state = "payment_required";
        store.save(record);
        return problemResult("register_grant", {
          code: "payment_rejected",
          message: `canopy refused the payment (${outcome.problem.detail ?? outcome.problem.title}). Nothing was registered${payment.via === "payer" ? "; the authorisation still counts toward today's cap until it expires unspent" : ""}.`,
          logId: record.logId,
          payment: summary,
        });
      }
      record.payment = {
        ...summary,
        via: payment.via,
        at: deps.now().toISOString(),
      };
    }

    if (outcome.kind === "problem") {
      store.save(record);
      return problemResult("register_grant", {
        ...httpProblemValue("canopy refused the grant", outcome.problem),
        logId: record.logId,
      });
    }
    if (outcome.kind === "payment_required")
      // Only reachable with a payment present, handled above.
      throw new Error("unreachable: payment_required after payment");

    record.state = "accepted";
    record.statusUrl = outcome.statusUrl;
    record.acceptedAt = deps.now().toISOString();
    store.save(record);
    return ok(
      `accepted: canopy enqueued the grant for log ${record.logId} for sequencing under authority log ${record.ownerLogId}${record.payment ? `, paid ${record.payment.value} (${record.payment.via})` : ""}. Call register_grant again with logId ${record.logId}${outcome.retryAfterSeconds !== undefined ? ` in about ${outcome.retryAfterSeconds}s` : ""} to follow it to its receipt.`,
      {
        ...record,
        ...(outcome.retryAfterSeconds !== undefined
          ? { retryAfterSeconds: outcome.retryAfterSeconds }
          : {}),
      },
    );
  });
}

/** Send, mapping a lost answer to a problem that says how to resume. */
async function sendOrReport(
  record: GrantRecord,
  deps: ResolvedDeps,
  send: () => ReturnType<typeof postGrant>,
  payment: { via: "payer" | "relay" } | undefined,
): Promise<RegisterGrantOutcome | ToolResult> {
  let res;
  try {
    res = await send();
  } catch (err) {
    if (!(err instanceof NetError)) throw err;
    return problemResult("register_grant", {
      code: err.code,
      message: `${err.message}. canopy may or may not have received the grant${payment ? " and the payment" : ""}. Call register_grant again with logId ${record.logId}: ${payment?.via === "payer" ? "it signs again with the grant's own nonce, so at most one payment can settle" : payment ? "pass the same payment again" : "it is sent again unchanged"}.`,
      logId: record.logId,
    });
  }
  return readRegisterGrantResponse(res, originOf(record.baseUrl!));
}

function describeOptions(required: PaymentRequired): string {
  return required.accepts
    .map(
      (o) =>
        `${o.amount} atomic units of ${o.asset} on ${o.network}, to ${o.payTo}`,
    )
    .join(" or ");
}

/** Accepted: follow the status URL to the receipt, then complete the grant. */
async function advance(
  record: GrantRecord,
  grant: Uint8Array,
  deps: ResolvedDeps,
): Promise<ToolResult> {
  const store = deps.grants;
  const origin = originOf(record.baseUrl!);
  if (record.receiptUrl === undefined) {
    const res = await getRegistrationStatus(
      { statusUrl: record.statusUrl! },
      { fetchImpl: deps.fetchImpl },
    );
    const status = readStatusResponse(res, origin);
    if (status.kind === "problem")
      return httpProblem(
        "register_grant",
        "the grant's status URL answered with a problem",
        status.problem,
      );
    if (status.kind === "pending") {
      record.firstPendingAt ??= res.at;
      store.save(record);
      return ok(
        `pending: the grant for log ${record.logId} is not yet sequenced; call register_grant again in ${status.retryAfterSeconds}s`,
        {
          state: "accepted",
          logId: record.logId,
          retryAfterSeconds: status.retryAfterSeconds,
          firstPendingAt: record.firstPendingAt,
        },
      );
    }
    record.receiptUrl = status.receiptUrl;
    record.entryId = status.entryId;
    record.massifHeight = status.massifHeight;
    store.save(record);
  }
  const res = await fetchReceipt(
    { receiptUrl: record.receiptUrl },
    { fetchImpl: deps.fetchImpl },
  );
  const receipt = readReceiptResponse(res);
  if (receipt.kind === "problem")
    return httpProblem(
      "register_grant",
      "the grant's receipt URL answered with a problem",
      receipt.problem,
    );
  if (receipt.kind === "awaiting_seal")
    return ok(
      `awaiting_seal: the grant is sequenced as entry ${record.entryId} in authority log ${record.ownerLogId}; canopy says "${receipt.reason}". It seals once that log's sealing is delegated (delegate_sealing with as: "authority"); call register_grant again in about a minute.`,
      {
        state: "accepted",
        sealed: false,
        logId: record.logId,
        entryId: record.entryId,
        receiptUrl: record.receiptUrl,
        reason: receipt.reason,
      },
    );
  const completed = completeGrant(grant, receipt.receipt, record.entryId!);
  record.state = "complete";
  record.completedAt = deps.now().toISOString();
  store.save(record, {
    "receipt.cose": receipt.receipt,
    "completed.cose": completed,
  });
  return completeResult(record, deps);
}

async function completeResult(
  record: GrantRecord,
  deps: ResolvedDeps,
): Promise<ToolResult> {
  const completed = deps.grants.read(record.logId, "completed.cose");
  if (completed === undefined)
    return problemResult("register_grant", {
      code: "corrupt_record",
      message: `grant ${record.logId} is marked complete but has no completed.cose`,
    });
  const logKey = await (await deps.signer()).publicKeyXY();
  const namesThisServer = record.granteeHex === toHex(logKey);
  return ok(
    `complete: the grant for log ${record.logId} is sealed (entry ${record.entryId}) and completed with its receipt. ${namesThisServer ? "It names this server's log key: pass grantBase64 as grant to delegate_sealing, then to register_statement (or set FORESTRIE_GRANT to it)." : "It names another key: give grantBase64 to the performer holding that key."}`,
    {
      ...record,
      grantBase64: bytesToBase64(completed),
      namesThisServer,
    },
  );
}
